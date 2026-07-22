//! MCP reverse proxy (Phase 1: read-only).
//!
//! Proxies MCP Streamable HTTP traffic to the GitHub-hosted MCP server
//! (default: https://api.githubcopilot.com/mcp/readonly), injecting a pooled
//! GitHub credential upstream so agents never hold a GitHub token.
//!
//! Key behaviors:
//! - Session pinning: the upstream bearer token is selected once per MCP
//!   session (at `initialize`, before an `Mcp-Session-Id` exists) and pinned
//!   for the session lifetime via a `session_id → identity_id` cache.
//! - Streaming passthrough: upstream responses may be `application/json` or
//!   `text/event-stream`; bodies are streamed through untouched.
//! - Header rewrite: client `Authorization` is stripped; pooled token and
//!   optional `X-MCP-Toolsets` are injected.
//! - Audit log: JSON-RPC request frames are parsed best-effort to log
//!   `method` (and tool name for `tools/call`) per request.
//!
//! NOTE: `allowed_owners` is NOT enforced on /mcp in Phase 1 — doing so
//! requires tool-argument inspection. Access is bounded by the pooled token's
//! own permissions and the read-only upstream. Per-agent policy is tracked in
//! https://github.com/openabdev/ghpool/issues/17.

use futures_util::StreamExt as _;

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::Response,
};
use std::sync::Arc;

use crate::{pool, AppState};

/// Max accepted request body (JSON-RPC frames are typically <10 KB).
pub const MAX_BODY_BYTES: usize = 1_048_576;

/// POST covers initialize/tools calls — bounded responses, generous ceiling.
const POST_TIMEOUT_SECS: u64 = 120;
/// DELETE is a small control-plane call.
const DELETE_TIMEOUT_SECS: u64 = 30;

/// Response headers propagated back to the MCP client.
const RESP_HEADERS: &[&str] = &["content-type", "mcp-session-id", "mcp-protocol-version"];

/// Client request headers forwarded upstream (Authorization is deliberately absent).
const FWD_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
];

/// ghpool-owned MCP tools are namespaced so they cannot collide with tools
/// exposed by GitHub's hosted MCP server.
const MINIMIZE_COMMENT_TOOL: &str = "ghpool_review_minimize_comment";
const GITHUB_GRAPHQL_URL: &str = "https://api.github.com/graphql";
const MINIMIZE_CLASSIFIERS: &[&str] = &[
    "ABUSE",
    "DUPLICATE",
    "OFF_TOPIC",
    "OUTDATED",
    "RESOLVED",
    "SPAM",
];

pub async fn mcp_proxy(
    State(state): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Phase 2a: agent authentication. With no [[mcp.agents]] configured this
    // is Phase 1 network-trust mode (agent = None).
    let agent = match authenticate(&state, &headers) {
        Ok(a) => a,
        Err(resp) => return *resp,
    };

    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Session termination without a session identifier is semantically invalid
    if method == Method::DELETE && session_id.is_none() {
        return rpc_error(StatusCode::BAD_REQUEST, "Mcp-Session-Id header required");
    }

    let agent_id = agent.map(|a| a.id.as_str());

    // Parse frame early so we can resolve the target owner for multi-app mode.
    let frame = if method == Method::POST { parse_frame(&body) } else { None };
    let mut resolved_repo: Option<(String, String)> = None;
    if let Some(f) = &frame {
        if f.method == "tools/call" {
            resolved_repo = crate::policy::resolve_repo(f.arguments.as_ref());
        }
    }

    // Policy enforcement for tools/call — before credential resolution, so
    // denied calls never mint or resolve an upstream credential.
    if let Some(frame) = &frame {
        if frame.method == "tools/call" {
            if let (Some(tool_name), Some(agent)) = (frame.tool.as_deref(), agent) {
                // 1. Default-deny tool allowlist (authoritative)
                if !agent.tools.iter().any(|t| t == tool_name) {
                    tracing::warn!(
                        "MCP tools/call {} DENIED (not on allowlist) [agent={}]{}",
                        tool_name, agent.id, session_suffix(session_id.as_deref())
                    );
                    return rpc_error(
                        StatusCode::FORBIDDEN,
                        "tool not permitted by agent policy",
                    );
                }
                // 2. Write classification (unknown names → Write,
                //    conservative). Writes require the enable_writes
                //    gate, which startup validation ties to the App
                //    backend + fail-closed audit (never PATs, never
                //    unaudited).
                if crate::policy::classify_tool(tool_name) == crate::policy::ToolKind::Write
                    && !state.config.mcp.enable_writes
                {
                    tracing::warn!(
                        "MCP tools/call {} DENIED (write tools not enabled) [agent={}]{}",
                        tool_name, agent.id, session_suffix(session_id.as_deref())
                    );
                    return rpc_error(
                        StatusCode::FORBIDDEN,
                        "write tools are not enabled",
                    );
                }
                // 2b. Multi-installation mode: repo-less agents ride pooled
                //     PATs, and writes never run on pooled PATs — even when
                //     writes are enabled. (Also rejected at startup
                //     validation; kept as defense-in-depth.)
                if crate::policy::classify_tool(tool_name) == crate::policy::ToolKind::Write
                    && state.multi_app_tokens.is_some()
                    && agent.repos.is_empty()
                {
                    tracing::warn!(
                        "MCP tools/call {} DENIED (repo-less agent uses pooled PATs) [agent={}]{}",
                        tool_name, agent.id, session_suffix(session_id.as_deref())
                    );
                    return rpc_error(
                        StatusCode::FORBIDDEN,
                        "write tools require a repository-scoped agent",
                    );
                }
                // 3. Repository allowlist (deny-if-unresolvable)
                if !agent.repos.is_empty() {
                    match &resolved_repo {
                        None => {
                            tracing::warn!(
                                "MCP tools/call {} DENIED (no resolvable repo target) [agent={}]{}",
                                tool_name, agent.id, session_suffix(session_id.as_deref())
                            );
                            return rpc_error(
                                StatusCode::FORBIDDEN,
                                "call has no resolvable repository target",
                            );
                        }
                        Some((owner, repo_name)) => {
                            if !crate::policy::repo_allowed(&agent.repos, owner, repo_name) {
                                tracing::warn!(
                                    "MCP tools/call {} DENIED (repo {}/{} not allowlisted) [agent={}]{}",
                                    tool_name, owner, repo_name, agent.id,
                                    session_suffix(session_id.as_deref())
                                );
                                return rpc_error(
                                    StatusCode::FORBIDDEN,
                                    "repository not permitted by agent policy",
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Local ghpool-owned tools are writes even when the upstream policy block
    // is bypassed (for example, in no-agent/network-trust mode). Keep the
    // local mutation path fail-closed and before credential resolution.
    if frame.as_ref().and_then(|f| f.tool.as_deref()) == Some(MINIMIZE_COMMENT_TOOL)
        && (agent.is_none() || !state.config.mcp.enable_writes)
    {
        tracing::warn!(
            "MCP tools/call {} DENIED (local write tools require an authenticated write-enabled agent)",
            MINIMIZE_COMMENT_TOOL
        );
        return rpc_error(
            StatusCode::FORBIDDEN,
            "local write tools require an authenticated write-enabled agent",
        );
    }

    // Multi-installation mode: `initialize` fans out to one upstream session
    // per owner in the agent's envelope; DELETE and notifications fan out to
    // every pinned route. Repo-less agents skip fan-out entirely — they keep
    // the legacy PAT-backed path (reads only; writes are denied above).
    if state.multi_app_tokens.is_some() {
        let frame_method = frame.as_ref().map(|f| f.method.as_str()).unwrap_or("");
        if method == Method::POST && frame_method == "initialize" && session_id.is_none() {
            let Some(agent) = agent else {
                // Startup validation requires agents in multi mode, and
                // authenticate() already rejected keyless requests.
                return rpc_error(StatusCode::UNAUTHORIZED, "agent authentication required");
            };
            if !agent.repos.is_empty() {
                return multi_initialize(&state, &headers, body, agent).await;
            }
        }
        if let Some(sid) = session_id.as_deref() {
            if method == Method::DELETE
                || (method == Method::POST && frame_method.starts_with("notifications/"))
            {
                if let Some(resp) = multi_fanout(&state, &method, &headers, &body, sid, agent).await
                {
                    return resp;
                }
            }
        }
    }

    let route_owner = resolved_repo.as_ref().map(|(o, _)| o.as_str());
    let cred = match pick_credential(&state, session_id.as_deref(), agent, route_owner).await {
        Ok(c) => c,
        Err(StatusCode::NOT_FOUND) => {
            tracing::warn!(
                "MCP request rejected: unknown or expired session{}",
                session_suffix(session_id.as_deref())
            );
            return rpc_error(StatusCode::NOT_FOUND, "session not found or expired");
        }
        Err(StatusCode::FORBIDDEN) => {
            return rpc_error(StatusCode::FORBIDDEN, "session not owned by this agent");
        }
        Err(StatusCode::BAD_GATEWAY) => {
            return rpc_error(StatusCode::BAD_GATEWAY, "upstream credential unavailable");
        }
        Err(code) => return rpc_error(code, "no upstream identity available"),
    };
    let cred_label = cred.label();

    // Request logging
    if let Some(frame) = &frame {
        if frame.method == "tools/call" {
            if let Some(tool_name) = frame.tool.as_deref() {
                let repo_suffix = resolved_repo
                    .as_ref()
                    .map(|(o, r)| format!(" repo={}/{}", o, r))
                    .unwrap_or_default();
                tracing::info!(
                    "MCP tools/call {}{} [{}]{}",
                    tool_name, repo_suffix,
                    audit_via(agent, &cred_label),
                    session_suffix(session_id.as_deref())
                );
            } else {
                tracing::info!(
                    "MCP tools/call [{}]{}",
                    audit_via(agent, &cred_label),
                    session_suffix(session_id.as_deref())
                );
            }
        } else {
            tracing::info!(
                "MCP {} [{}]{}",
                frame.method,
                audit_via(agent, &cred_label),
                session_suffix(session_id.as_deref())
            );
        }
    }

    // Durable audit (2b): write-classified calls that will be forwarded get
    // a fail-closed pre-flight record and (below) a buffered-response result
    // record. Reads keep best-effort tracing only.
    let write_call = frame.as_ref().and_then(|f| {
        f.tool
            .as_deref()
            .filter(|t| {
                f.method == "tools/call"
                    && crate::policy::classify_tool(t) == crate::policy::ToolKind::Write
            })
            .map(str::to_string)
    });
    // Per-agent in-flight cap on write calls (held until the buffered
    // response is fully assembled; the guard decrements on drop).
    let _inflight: Option<InFlightGuard> = match (&write_call, agent_id) {
        (Some(_), Some(aid)) => {
            let cap = state.config.mcp.max_inflight_writes;
            match InFlightGuard::try_acquire(&state.write_inflight, aid, cap) {
                Some(g) => Some(g),
                None => {
                    tracing::warn!(
                        "MCP write call rejected: agent {} at in-flight cap ({})",
                        aid, cap
                    );
                    return rpc_error(
                        StatusCode::TOO_MANY_REQUESTS,
                        "agent write concurrency limit reached",
                    );
                }
            }
        }
        _ => None,
    };

    if let (Some(tool_name), Some(sink)) = (&write_call, &state.audit) {
        let call = crate::audit::CallInfo {
            rpc_id: frame.as_ref().and_then(|f| f.rpc_id.as_ref()),
            session: session_id.as_deref(),
            agent: agent_id,
            credential: &cred_label,
            tool: tool_name,
            repo: resolved_repo.as_ref(),
        };
        let arg_keys =
            crate::audit::redacted_arg_keys(frame.as_ref().and_then(|f| f.arguments.as_ref()));
        if let Err(e) = sink.record_request(&call, &arg_keys) {
            // FAIL-CLOSED: a write whose audit record cannot be persisted
            // must not happen.
            tracing::error!("audit unavailable — rejecting write call (fail-closed): {}", e);
            return rpc_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit backend unavailable — write rejected",
            );
        }
    }

    // ghpool-owned review tools are handled locally. All policy and audit
    // checks above still apply; the upstream GitHub MCP server is not asked
    // to interpret a tool it does not expose.
    if frame.as_ref().and_then(|f| f.tool.as_deref()) == Some(MINIMIZE_COMMENT_TOOL) {
        let local = handle_minimize_comment(&state, &cred, frame.as_ref().unwrap(), GITHUB_GRAPHQL_URL).await;
        if let (Some(tool_name), Some(sink)) = (&write_call, &state.audit) {
            let call = crate::audit::CallInfo {
                rpc_id: frame.as_ref().and_then(|f| f.rpc_id.as_ref()),
                session: session_id.as_deref(),
                agent: agent_id,
                credential: &cred_label,
                tool: tool_name,
                repo: resolved_repo.as_ref(),
            };
            if let Err(e) = sink.record_result(
                &call,
                &crate::audit::CallOutcome {
                    http_status: local.http_status,
                    tool_error: local.tool_error,
                },
            ) {
                tracing::error!("custom MCP tool result audit failed: {}", e);
            }
        }
        return local.response;
    }

    let upstream = state.config.mcp.upstream();
    // Timeouts are method-specific: POST responses (including SSE tool-call
    // results) complete within a bounded window, but GET is the stream
    // resumption channel and may legitimately stay open indefinitely — a
    // total timeout there would sever healthy streams.
    let req = match method {
        Method::POST => state
            .http
            .post(upstream)
            .body(reqwest::Body::from(body))
            .timeout(std::time::Duration::from_secs(POST_TIMEOUT_SECS)),
        Method::GET => state.http.get(&upstream),
        Method::DELETE => state
            .http
            .delete(upstream)
            .timeout(std::time::Duration::from_secs(DELETE_TIMEOUT_SECS)),
        _ => return rpc_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    };

    let Some(mut upstream_headers) =
        build_upstream_headers(&headers, cred.token(), &state.config.mcp.toolsets, agent)
    else {
        tracing::error!(
            "credential '{}' is not a valid header value — check secret source",
            cred_label
        );
        return rpc_error(StatusCode::BAD_GATEWAY, "upstream credential misconfigured");
    };
    // Multi-installation routing: every installation has its own upstream
    // session. Secondary routes replace the downstream session ID with their
    // own; stateless routed calls carry no session at all. Tokens are never
    // mixed within one upstream session.
    if let McpCredential::Routed { upstream_session, .. } = &cred {
        match upstream_session {
            Some(us) if Some(us.as_str()) != session_id.as_deref() => {
                let Ok(v) = us.parse() else {
                    return rpc_error(StatusCode::BAD_GATEWAY, "invalid upstream session id");
                };
                upstream_headers.insert("mcp-session-id", v);
            }
            Some(_) => {}
            None => {
                upstream_headers.remove("mcp-session-id");
            }
        }
    }

    let resp = match req.headers(upstream_headers).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("mcp upstream request failed: {}", e);
            return rpc_error(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    // Best-effort rate budget accounting, if upstream exposes it
    let rate_remaining = resp.headers()
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok());
    let rate_reset = resp.headers()
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if let McpCredential::Pat(identity) = &cred {
        state.pool.update_rate(&identity.id, rate_remaining, rate_reset);

        // Upstream throttled this identity: zero its budget so the pool
        // avoids it for new sessions until the reported (or default) reset.
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            state.pool.update_rate(&identity.id, Some(0), Some(rate_reset.unwrap_or(now + 60)));
            tracing::warn!("MCP upstream 429 for identity {} — budget zeroed", identity.id);
        }
    } else if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        tracing::warn!("MCP upstream 429 on App installation token ({})", cred_label);
    }

    // Pin new sessions: upstream returns Mcp-Session-Id on initialize.
    // The pin binds the session to the exact credential and the agent that
    // initialized it. Routed credentials are never pinned here — their
    // sessions are created by the multi-installation initialize fan-out.
    if let Some(sid) = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        if state.mcp_sessions.get(sid).await.is_none() {
            if let Some(new_pin) = cred.to_pin(agent_id) {
                tracing::info!(
                    "MCP session pinned to credential {}{}{}",
                    cred_label,
                    agent_id.map(|a| format!(" [agent={}]", a)).unwrap_or_default(),
                    session_suffix(Some(sid))
                );
                state.mcp_sessions.insert(sid.to_string(), new_pin).await;
            }
        }
    }

    // Session termination: drop the pin
    if method == Method::DELETE {
        if let Some(sid) = &session_id {
            state.mcp_sessions.invalidate(sid).await;
        }
    }

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    // A secondary route's upstream echoes ITS session ID; the client must
    // only ever see the downstream session ID it initialized with.
    let downstream_sid_override: Option<&str> = match (&cred, session_id.as_deref()) {
        (McpCredential::Routed { upstream_session: Some(us), .. }, Some(dsid)) if us != dsid => {
            Some(dsid)
        }
        _ => None,
    };
    let mut builder = Response::builder().status(status);
    for name in RESP_HEADERS {
        if let Some(v) = resp.headers().get(*name) {
            if *name == "mcp-session-id" {
                if let Some(dsid) = downstream_sid_override {
                    builder = builder.header(*name, dsid);
                    continue;
                }
            }
            builder = builder.header(*name, v.clone());
        }
    }

    // Add ghpool-owned tools only to an authenticated agent's advertised
    // surface when that agent explicitly allowlists the tool. The upstream
    // response remains untouched for all other agents and requests.
    if frame.as_ref().map(|f| f.method.as_str()) == Some("tools/list")
        && state.config.mcp.enable_writes
        && custom_tool_enabled(agent, MINIMIZE_COMMENT_TOOL)
    {
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        match buffer_body(resp, MAX_BODY_BYTES).await {
            Ok(BufferedBody::Complete(bytes)) => {
                let body = inject_custom_tool(
                    &bytes,
                    content_type.as_deref(),
                    agent.map(|a| a.tools.as_slice()),
                )
                .unwrap_or(bytes);
                return builder
                    .body(Body::from(body))
                    .unwrap_or_else(|_| rpc_error(StatusCode::BAD_GATEWAY, "failed to build response"));
            }
            Ok(BufferedBody::Overflow(head, rest)) => {
                let head_stream = futures_util::stream::once(async move {
                    Ok::<_, reqwest::Error>(Bytes::from(head))
                });
                return builder
                    .body(Body::from_stream(head_stream.chain(rest)))
                    .unwrap_or_else(|_| rpc_error(StatusCode::BAD_GATEWAY, "failed to build response"));
            }
            Err(e) => {
                tracing::error!("tools/list response read failed: {}", e);
                return rpc_error(StatusCode::BAD_GATEWAY, "upstream response failed");
            }
        }
    }

    // Audited write call: buffer the response (bounded) to extract the MCP
    // tool outcome — a failed GitHub operation arrives as result.isError
    // inside an HTTP 200/SSE body, so HTTP status alone is not a success
    // signal. Reads keep the zero-copy streaming path.
    if let (Some(tool_name), Some(sink)) = (&write_call, &state.audit) {
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let cap = state
            .config
            .mcp
            .audit
            .as_ref()
            .map(|a| a.max_result_bytes)
            .unwrap_or(4 * 1024 * 1024);

        let call = crate::audit::CallInfo {
            rpc_id: frame.as_ref().and_then(|f| f.rpc_id.as_ref()),
            session: session_id.as_deref(),
            agent: agent_id,
            credential: &cred_label,
            tool: tool_name,
            repo: resolved_repo.as_ref(),
        };

        match buffer_body(resp, cap).await {
            Ok(BufferedBody::Complete(bytes)) => {
                let tool_error =
                    crate::audit::parse_tool_outcome(content_type.as_deref(), &bytes);
                let outcome = crate::audit::CallOutcome {
                    http_status: status.as_u16(),
                    tool_error,
                };
                if let Err(e) = sink.record_result(&call, &outcome) {
                    // The call already happened — cannot unwind. Loud error.
                    tracing::error!("audit result record failed (call already executed): {}", e);
                }
                return builder
                    .body(Body::from(bytes))
                    .unwrap_or_else(|_| rpc_error(StatusCode::BAD_GATEWAY, "failed to build response"));
            }
            Ok(BufferedBody::Overflow(head, rest)) => {
                // Oversize: outcome undeterminable; forward head + remainder
                let outcome = crate::audit::CallOutcome {
                    http_status: status.as_u16(),
                    tool_error: None,
                };
                if let Err(e) = sink.record_result(&call, &outcome) {
                    tracing::error!("audit result record failed (call already executed): {}", e);
                }
                let head_stream = futures_util::stream::once(async move {
                    Ok::<_, reqwest::Error>(Bytes::from(head))
                });
                return builder
                    .body(Body::from_stream(head_stream.chain(rest)))
                    .unwrap_or_else(|_| rpc_error(StatusCode::BAD_GATEWAY, "failed to build response"));
            }
            Err(e) => {
                tracing::error!("upstream body read failed mid-response: {}", e);
                let outcome = crate::audit::CallOutcome {
                    http_status: StatusCode::BAD_GATEWAY.as_u16(),
                    tool_error: None,
                };
                if let Err(e) = sink.record_result(&call, &outcome) {
                    tracing::error!("audit result record failed: {}", e);
                }
                return rpc_error(StatusCode::BAD_GATEWAY, "upstream response failed");
            }
        }
    }

    builder
        .body(Body::from_stream(resp.bytes_stream()))
        .unwrap_or_else(|_| rpc_error(StatusCode::BAD_GATEWAY, "failed to build response"))
}

/// Result of buffering an upstream response up to a byte cap.
enum BufferedBody {
    /// Entire body fit within the cap.
    Complete(Vec<u8>),
    /// Cap exceeded: buffered head + the remaining live stream.
    Overflow(
        Vec<u8>,
        std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    ),
}

async fn buffer_body(resp: reqwest::Response, cap: usize) -> Result<BufferedBody, String> {
    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream().boxed();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let b = chunk.map_err(|e| e.to_string())?;
        buf.extend_from_slice(&b);
        if buf.len() > cap {
            return Ok(BufferedBody::Overflow(buf, stream));
        }
    }
    Ok(BufferedBody::Complete(buf))
}

struct LocalToolResponse {
    response: Response,
    http_status: u16,
    tool_error: Option<bool>,
}

fn custom_tool_enabled(
    agent: Option<&crate::config::McpAgentConfig>,
    tool_name: &str,
) -> bool {
    agent
        .map(|a| a.tools.iter().any(|tool| tool == tool_name))
        .unwrap_or(false)
}

fn custom_tool_definition() -> serde_json::Value {
    serde_json::json!({
        "name": MINIMIZE_COMMENT_TOOL,
        "description": "Minimize a GitHub issue or pull request comment by GraphQL node ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": { "type": "string", "description": "Repository owner." },
                "repo": { "type": "string", "description": "Repository name." },
                "node_id": { "type": "string", "description": "Global GraphQL node ID of the comment." },
                "classifier": {
                    "type": "string",
                    "enum": MINIMIZE_CLASSIFIERS
                }
            },
            "required": ["owner", "repo", "node_id", "classifier"]
        }
    })
}

/// Parse one JSON response from either a JSON body or an SSE event. SSE
/// permits multiple data lines per event; those lines are joined with a
/// newline before JSON decoding, as required by the event-stream format.
fn parse_sse_or_json(body: &[u8], content_type: Option<&str>) -> Option<serde_json::Value> {
    let is_sse = content_type
        .map(|value| value.starts_with("text/event-stream"))
        .unwrap_or(false);
    if !is_sse {
        return serde_json::from_slice(body).ok();
    }

    let text = std::str::from_utf8(body).ok()?;
    let mut current = String::new();
    let mut last_event = None;
    for line in text.lines() {
        if let Some(data) = line.strip_prefix("data:") {
            if !current.is_empty() {
                current.push('\n');
            }
            current.push_str(data.strip_prefix(' ').unwrap_or(data));
        } else if line.is_empty() && !current.is_empty() {
            last_event = Some(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        last_event = Some(current);
    }
    serde_json::from_str(last_event?.as_str()).ok()
}

/// Append a custom tool to a JSON or SSE-framed tools/list response and filter
/// upstream tools against the authenticated agent's complete allowlist. A
/// parse failure returns None so the caller can forward the upstream response
/// unchanged rather than breaking an otherwise compatible MCP session.
fn inject_custom_tool(
    body: &[u8],
    content_type: Option<&str>,
    allowed_tools: Option<&[String]>,
) -> Option<Vec<u8>> {
    let is_sse = content_type
        .map(|value| value.starts_with("text/event-stream"))
        .unwrap_or(false);
    let mut json = parse_sse_or_json(body, content_type)?;
    let tools = json.get_mut("result")?.get_mut("tools")?.as_array_mut()?;
    if let Some(allowed) = allowed_tools {
        tools.retain(|tool| {
            tool.get("name")
                .and_then(|name| name.as_str())
                .map(|name| allowed.iter().any(|candidate| candidate == name))
                .unwrap_or(false)
        });
    }
    if !tools.iter().any(|tool| {
        tool.get("name")
            .and_then(|name| name.as_str())
            == Some(MINIMIZE_COMMENT_TOOL)
    }) {
        tools.push(custom_tool_definition());
    }
    let encoded = serde_json::to_string(&json).ok()?;
    if is_sse {
        Some(format!("event: message\ndata: {}\n\n", encoded).into_bytes())
    } else {
        Some(encoded.into_bytes())
    }
}

fn tool_response(
    rpc_id: Option<&serde_json::Value>,
    is_error: bool,
    http_status: StatusCode,
    text: impl Into<String>,
) -> Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": rpc_id.cloned().unwrap_or(serde_json::Value::Null),
        "result": {
            "isError": is_error,
            "content": [{"type": "text", "text": text.into()}]
        }
    });
    Response::builder()
        .status(http_status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("static MCP tool response")
}

fn local_tool_error(
    rpc_id: Option<&serde_json::Value>,
    http_status: StatusCode,
    message: impl Into<String>,
) -> LocalToolResponse {
    LocalToolResponse {
        response: tool_response(rpc_id, true, http_status, message),
        http_status: http_status.as_u16(),
        tool_error: Some(true),
    }
}

async fn execute_graphql(
    state: &AppState,
    cred: &McpCredential,
    graphql_url: &str,
    payload: &serde_json::Value,
) -> Result<(StatusCode, serde_json::Value), ()> {
    let response = state
        .http
        .post(graphql_url)
        .bearer_auth(cred.token())
        .header("user-agent", concat!("ghpool/", env!("CARGO_PKG_VERSION")))
        .header("content-type", "application/json")
        .json(payload)
        .timeout(std::time::Duration::from_secs(POST_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|error| {
            tracing::error!("custom MCP GraphQL request failed: {}", error);
        })?;
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = response.json().await.map_err(|error| {
        tracing::error!("custom MCP GraphQL response parse failed: {}", error);
    })?;
    Ok((status, body))
}

/// GraphQL identity note: the viewer for an App installation token logs in
/// as "<app-slug>[bot]", while Bot-authored comments carry the bare
/// "<app-slug>" author login (empirically verified against api.github.com).
/// Compare with the "[bot]" suffix normalized on both sides.
fn normalize_actor(login: &str) -> &str {
    login.strip_suffix("[bot]").unwrap_or(login)
}

async fn handle_minimize_comment(
    state: &AppState,
    cred: &McpCredential,
    frame: &Frame,
    graphql_url: &str,
) -> LocalToolResponse {
    let Some(arguments) = frame.arguments.as_ref().and_then(|value| value.as_object()) else {
        return local_tool_error(frame.rpc_id.as_ref(), StatusCode::OK, "arguments must be an object");
    };
    for key in ["owner", "repo", "node_id", "classifier"] {
        if arguments.get(key).and_then(|value| value.as_str()).is_none() {
            return local_tool_error(
                frame.rpc_id.as_ref(),
                StatusCode::OK,
                format!("missing or invalid argument: {}", key),
            );
        }
    }
    let owner = arguments["owner"].as_str().unwrap();
    let repo = arguments["repo"].as_str().unwrap();
    let node_id = arguments["node_id"].as_str().unwrap();
    let classifier = arguments["classifier"].as_str().unwrap();
    if !MINIMIZE_CLASSIFIERS.contains(&classifier) {
        return local_tool_error(
            frame.rpc_id.as_ref(),
            StatusCode::OK,
            "classifier is not supported",
        );
    }

    let verify_payload = serde_json::json!({
        "query": "query VerifyComment($id: ID!) { viewer { login } node(id: $id) { ... on IssueComment { author { login } issue { repository { nameWithOwner } } } ... on PullRequestReviewComment { author { login } pullRequest { repository { nameWithOwner } } } } }",
        "variables": { "id": node_id }
    });
    let (verify_status, verify_body) = match execute_graphql(state, cred, graphql_url, &verify_payload).await {
        Ok(result) => result,
        Err(()) => {
            return local_tool_error(
                frame.rpc_id.as_ref(),
                StatusCode::BAD_GATEWAY,
                "GitHub comment ownership check failed",
            );
        }
    };
    let viewer = verify_body.pointer("/data/viewer/login").and_then(|value| value.as_str());
    let author = verify_body.pointer("/data/node/author/login").and_then(|value| value.as_str());
    let actual_repo = verify_body
        .pointer("/data/node/issue/repository/nameWithOwner")
        .or_else(|| verify_body.pointer("/data/node/pullRequest/repository/nameWithOwner"))
        .and_then(|value| value.as_str());
    let expected_repo = format!("{}/{}", owner, repo);
    if !verify_status.is_success()
        || verify_body.get("errors").is_some()
        || viewer.is_none()
        || author.is_none()
        || viewer.map(normalize_actor) != author.map(normalize_actor)
    {
        tracing::warn!("comment ownership check failed for {}/{}", owner, repo);
        return local_tool_error(
            frame.rpc_id.as_ref(),
            verify_status,
            "comment is not authored by the current GitHub identity",
        );
    }
    if actual_repo
        .map(|value| value.eq_ignore_ascii_case(&expected_repo))
        != Some(true)
    {
        tracing::warn!(
            "comment repository mismatch: expected {}, actual {:?}",
            expected_repo,
            actual_repo
        );
        return local_tool_error(
            frame.rpc_id.as_ref(),
            StatusCode::FORBIDDEN,
            "comment does not belong to the authorized repository",
        );
    }

    let payload = serde_json::json!({
        "query": "mutation MinimizeComment($subjectId: ID!, $classifier: ReportedContentClassifiers!) { minimizeComment(input: { subjectId: $subjectId, classifier: $classifier }) { minimizedComment { isMinimized } } }",
        "variables": { "subjectId": node_id, "classifier": classifier }
    });
    let (status, body) = match execute_graphql(state, cred, graphql_url, &payload).await {
        Ok(result) => result,
        Err(()) => {
            tracing::error!("custom minimize_comment request failed for {}/{}", owner, repo);
            return local_tool_error(
                frame.rpc_id.as_ref(),
                StatusCode::BAD_GATEWAY,
                "GitHub minimize comment request failed",
            );
        }
    };
    let minimized = body
        .pointer("/data/minimizeComment/minimizedComment/isMinimized")
        .and_then(|value| value.as_bool())
        == Some(true);
    if !status.is_success() || body.get("errors").is_some() || !minimized {
        tracing::warn!("GitHub minimize_comment failed for {}/{}", owner, repo);
        return local_tool_error(frame.rpc_id.as_ref(), status, "GitHub rejected comment minimization");
    }

    LocalToolResponse {
        response: tool_response(
            frame.rpc_id.as_ref(),
            false,
            StatusCode::OK,
            format!("Comment minimized as {}", classifier),
        ),
        http_status: status.as_u16(),
        tool_error: Some(false),
    }
}

/// What a pinned MCP session is bound to: the exact credential serving it,
/// and (in agent mode) the agent that initialized it. A session presented by
/// a different agent is rejected; a session whose credential has expired is
/// terminated (404) — sessions cannot outlive their credential (2b gate).
#[derive(Clone, Debug, PartialEq)]
pub struct SessionPin {
    /// None = session created in Phase 1 network-trust mode (no agents).
    pub agent_id: Option<String>,
    pub cred: PinnedCred,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PinnedCred {
    /// Pooled PAT, referenced by identity id (revoked by pool removal).
    Pat { identity_id: String },
    /// GitHub App installation token, pinned by value: the session keeps
    /// using the token it started with (still valid upstream even after the
    /// provider refreshes) and dies at that token's expiry.
    App { token: String, expires_at: u64 },
    /// Multi-installation mode: one pinned credential and one upstream
    /// session per owner, all created eagerly at `initialize` (fan-out).
    /// tools/call frames route by their resolved repository owner; the
    /// session dies (404) when a needed route's token has expired — routes
    /// are minted together, so expiries are effectively aligned.
    MultiApp {
        /// owner (lowercase) → pinned per-installation route.
        routes: std::collections::HashMap<String, AppRoute>,
        /// Owner whose upstream session ID doubles as the downstream
        /// session ID; non-tools/call traffic is served by this route.
        primary: String,
    },
}

/// One installation's pinned credential + upstream session in multi mode.
#[derive(Clone, Debug, PartialEq)]
pub struct AppRoute {
    pub token: String,
    pub expires_at: u64,
    /// Upstream session ID for this installation (None when the upstream
    /// did not assign one — such routes are used statelessly).
    pub upstream_session: Option<String>,
}

/// The upstream credential resolved for one request.
pub enum McpCredential {
    Pat(pool::Identity),
    App(crate::app_token::AppToken),
    /// Multi-installation route: the request is forwarded with this
    /// installation's token, on this installation's own upstream session
    /// (never mixing tokens within one upstream session).
    Routed {
        owner: String,
        token: String,
        upstream_session: Option<String>,
    },
}

impl McpCredential {
    fn token(&self) -> &str {
        match self {
            McpCredential::Pat(i) => &i.token,
            McpCredential::App(t) => &t.token,
            McpCredential::Routed { token, .. } => token,
        }
    }
    /// Audit label for the credential.
    fn label(&self) -> String {
        match self {
            McpCredential::Pat(i) => i.id.clone(),
            McpCredential::App(_) => "github-app".to_string(),
            McpCredential::Routed { owner, .. } => format!("github-app:{}", owner),
        }
    }
    /// Session pin for this credential; None for Routed credentials, whose
    /// sessions are pinned by the multi-installation initialize fan-out.
    fn to_pin(&self, agent_id: Option<&str>) -> Option<SessionPin> {
        let cred = match self {
            McpCredential::Pat(i) => PinnedCred::Pat { identity_id: i.id.clone() },
            McpCredential::App(t) => PinnedCred::App {
                token: t.token.clone(),
                expires_at: t.expires_at,
            },
            McpCredential::Routed { .. } => return None,
        };
        Some(SessionPin { agent_id: agent_id.map(str::to_string), cred })
    }
}

/// Resolve the upstream credential for this request per MCP Streamable HTTP
/// session semantics:
/// - No session ID (i.e. `initialize`): mint/reuse an App installation token
///   when the App backend is configured, else select the highest-budget PAT.
/// - Known session ID: reuse the pinned credential — never rotate
///   mid-session. The session must belong to the same agent (else 403) and
///   its credential must still be valid (expired App token / removed PAT
///   identity → session terminated, 404).
/// - Unknown/expired session ID: 404, so the client re-initializes.
///
/// `route_owner` is the repository owner resolved from tools/call arguments
/// (multi-installation routing key); None routes to the primary installation.
async fn pick_credential(
    state: &AppState,
    session_id: Option<&str>,
    agent: Option<&crate::config::McpAgentConfig>,
    route_owner: Option<&str>,
) -> Result<McpCredential, StatusCode> {
    let agent_id = agent.map(|a| a.id.as_str());
    if let Some(sid) = session_id {
        if let Some(pin) = state.mcp_sessions.get(sid).await {
            if pin.agent_id.as_deref() != agent_id {
                // Session binding violation: a different agent (or mode) is
                // presenting this session ID. Do not disclose whether the
                // session exists beyond the rejection itself.
                tracing::warn!(
                    "MCP session binding violation: session initialized by {:?}, presented by {:?}{}",
                    pin.agent_id, agent_id, session_suffix(Some(sid))
                );
                return Err(StatusCode::FORBIDDEN);
            }
            match pin.cred {
                PinnedCred::Pat { identity_id } => {
                    if let Some(ident) = state.pool.get(&identity_id) {
                        return Ok(McpCredential::Pat(ident));
                    }
                    // Identity left the pool — treat as terminated
                    state.mcp_sessions.invalidate(sid).await;
                }
                PinnedCred::App { token, expires_at } => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    if expires_at > now {
                        return Ok(McpCredential::App(crate::app_token::AppToken {
                            token,
                            expires_at,
                        }));
                    }
                    // Credential expired: the session cannot outlive it
                    tracing::info!(
                        "MCP session terminated: pinned App token expired{}",
                        session_suffix(Some(sid))
                    );
                    state.mcp_sessions.invalidate(sid).await;
                }
                PinnedCred::MultiApp { routes, primary } => {
                    // Routes are minted together — the session dies as a
                    // WHOLE at the earliest expiry (documented behavior),
                    // regardless of which route this call would select.
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    if routes.values().any(|r| r.expires_at <= now) {
                        tracing::info!(
                            "MCP session terminated: a pinned App token expired{}",
                            session_suffix(Some(sid))
                        );
                        state.mcp_sessions.invalidate(sid).await;
                        return Err(StatusCode::NOT_FOUND);
                    }
                    let key = route_owner
                        .map(|o| o.to_lowercase())
                        .unwrap_or_else(|| primary.clone());
                    // Policy (repo allowlist) runs before credential
                    // resolution, and the pin covers every owner the agent's
                    // allowlist spans — a missing route means the call slipped
                    // past policy somehow. Fail closed.
                    let Some(route) = routes.get(&key) else {
                        tracing::warn!(
                            "MCP request rejected: owner {} outside session envelope{}",
                            key, session_suffix(Some(sid))
                        );
                        return Err(StatusCode::FORBIDDEN);
                    };
                    return Ok(McpCredential::Routed {
                        owner: key,
                        token: route.token.clone(),
                        upstream_session: route.upstream_session.clone(),
                    });
                }
            }
        }
        return Err(StatusCode::NOT_FOUND);
    }
    // New session, multi-installation mode: stateless call (initialize is
    // handled by the fan-out path before credential resolution). Route by
    // the resolved owner, or the agent's first owner for repo-less methods.
    // Repo-less agents fall through to the PAT pool (legacy read path).
    if let Some(multi) = &state.multi_app_tokens {
        if let Some(agent) = agent {
            let owners = route_owners(agent);
            if let Some(first_owner) = owners.first() {
                let key = match route_owner {
                    Some(o) => o.to_lowercase(),
                    None => first_owner.clone(),
                };
                let Some(provider) = multi.get(&key) else {
                    return Err(StatusCode::FORBIDDEN);
                };
                let envelope = scope_envelope_for_owner(agent, &key);
                return match provider.token_scoped(&envelope).await {
                    Ok(t) => Ok(McpCredential::Routed {
                        owner: key,
                        token: t.token,
                        upstream_session: None,
                    }),
                    Err(e) => {
                        tracing::error!("App token mint failed for owner {}: {}", key, e);
                        Err(StatusCode::BAD_GATEWAY)
                    }
                };
            }
        }
    }
    // New session: App backend takes precedence when configured. The token
    // is scoped to the agent's repo envelope when possible (exact entries,
    // single owner) so GitHub itself enforces the repository boundary; the
    // proxy-side repo check remains as defense-in-depth.
    if let Some(provider) = &state.app_tokens {
        let envelope = scope_envelope(agent);
        return match provider.token_scoped(&envelope).await {
            Ok(t) => Ok(McpCredential::App(t)),
            Err(e) => {
                tracing::error!("App token mint failed: {}", e);
                Err(StatusCode::BAD_GATEWAY)
            }
        };
    }
    state
        .pool
        .select()
        .map(McpCredential::Pat)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

/// Repository names for a scoped token mint: only when the agent's repo
/// allowlist consists entirely of exact `owner/repo` entries under a single
/// owner (the installation's). Wildcards, mixed owners, or no restriction
/// fall back to an installation-wide token.
fn scope_envelope(agent: Option<&crate::config::McpAgentConfig>) -> Vec<String> {
    let Some(a) = agent else { return Vec::new() };
    if a.repos.is_empty() {
        return Vec::new();
    }
    let mut owner0: Option<&str> = None;
    let mut names = Vec::new();
    for entry in &a.repos {
        match entry.split_once('/') {
            Some((o, r)) if r != "*" && !r.is_empty() => {
                if *owner0.get_or_insert(o) != o {
                    return Vec::new(); // mixed owners → installation-wide
                }
                names.push(r.to_string());
            }
            _ => return Vec::new(), // wildcard/malformed → installation-wide
        }
    }
    names
}

/// Owners (lowercase, sorted, deduped) spanned by an agent's repo allowlist.
/// In multi-installation mode this is the session's credential envelope; the
/// first owner is the deterministic primary.
fn route_owners(agent: &crate::config::McpAgentConfig) -> Vec<String> {
    let mut owners: Vec<String> = agent
        .repos
        .iter()
        .filter_map(|e| e.split_once('/').map(|(o, _)| o.trim().to_lowercase()))
        .filter(|o| !o.is_empty())
        .collect();
    owners.sort();
    owners.dedup();
    owners
}

/// Scoped-mint envelope for ONE owner in multi-installation mode: the exact
/// repo names the agent may touch under that owner. Any wildcard entry for
/// the owner falls back to an installation-wide token (proxy-side checks
/// still apply).
fn scope_envelope_for_owner(agent: &crate::config::McpAgentConfig, owner: &str) -> Vec<String> {
    let mut names = Vec::new();
    for entry in &agent.repos {
        if let Some((o, r)) = entry.split_once('/') {
            if o.eq_ignore_ascii_case(owner) {
                if r == "*" || r.is_empty() {
                    return Vec::new(); // wildcard → installation-wide
                }
                names.push(r.to_string());
            }
        }
    }
    names
}

/// Multi-installation `initialize` fan-out: mint one scoped token per owner
/// in the agent's envelope, open one upstream session per installation, pin
/// every route under the primary upstream session ID (which becomes the
/// downstream session ID), and stream the primary response to the client.
///
/// Fail-closed: any mint or upstream initialize failure fails the whole
/// initialize — the agent learns immediately instead of at its first
/// tools/call for the broken installation.
async fn multi_initialize(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    body: Bytes,
    agent: &crate::config::McpAgentConfig,
) -> Response {
    let Some(multi) = &state.multi_app_tokens else {
        return rpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "multi-installation backend missing",
        );
    };
    let owners = route_owners(agent);
    let Some(primary_owner) = owners.first().cloned() else {
        return rpc_error(StatusCode::BAD_GATEWAY, "agent has no routable repository owners");
    };
    let upstream = state.config.mcp.upstream();

    let mut routes: std::collections::HashMap<String, AppRoute> =
        std::collections::HashMap::new();
    let mut primary_resp: Option<reqwest::Response> = None;

    for owner in &owners {
        let Some(provider) = multi.get(owner) else {
            // Startup validation guarantees coverage; fail closed anyway.
            tracing::error!(
                "no [[mcp.github_apps]] entry for owner {} — rejecting initialize [agent={}]",
                owner, agent.id
            );
            return abort_multi_initialize(
                state,
                &upstream,
                agent,
                &routes,
                rpc_error(
                    StatusCode::BAD_GATEWAY,
                    "no GitHub App installation configured for repository owner",
                ),
            )
            .await;
        };
        let envelope = scope_envelope_for_owner(agent, owner);
        let token = match provider.token_scoped(&envelope).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("App token mint failed for owner {}: {}", owner, e);
                return abort_multi_initialize(
                    state,
                    &upstream,
                    agent,
                    &routes,
                    rpc_error(StatusCode::BAD_GATEWAY, "upstream credential unavailable"),
                )
                .await;
            }
        };
        let Some(upstream_headers) =
            build_upstream_headers(headers, &token.token, &[], Some(agent))
        else {
            tracing::error!(
                "credential for owner {} is not a valid header value — check secret source",
                owner
            );
            return abort_multi_initialize(
                state,
                &upstream,
                agent,
                &routes,
                rpc_error(StatusCode::BAD_GATEWAY, "upstream credential misconfigured"),
            )
            .await;
        };
        let resp = match state
            .http
            .post(&upstream)
            .headers(upstream_headers)
            .body(reqwest::Body::from(body.clone()))
            .timeout(std::time::Duration::from_secs(POST_TIMEOUT_SECS))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("mcp upstream initialize failed for owner {}: {}", owner, e);
                return abort_multi_initialize(
                    state,
                    &upstream,
                    agent,
                    &routes,
                    rpc_error(StatusCode::BAD_GATEWAY, "upstream request failed"),
                )
                .await;
            }
        };
        if !resp.status().is_success() {
            tracing::error!(
                "mcp upstream initialize for owner {} returned {}",
                owner,
                resp.status()
            );
            return abort_multi_initialize(
                state,
                &upstream,
                agent,
                &routes,
                rpc_error(StatusCode::BAD_GATEWAY, "upstream initialize failed"),
            )
            .await;
        }
        let sid = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        routes.insert(
            owner.clone(),
            AppRoute {
                token: token.token.clone(),
                expires_at: token.expires_at,
                upstream_session: sid,
            },
        );
        if *owner == primary_owner {
            primary_resp = Some(resp);
        } else {
            // Secondary responses are consumed internally — and HTTP 2xx is
            // not sufficient: a JSON-RPC error inside a 200 means this
            // installation has no usable session. Fail the whole initialize
            // (fail-closed), because the client only ever sees the primary
            // response and would otherwise believe every route is healthy.
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            match buffer_body(resp, MAX_BODY_BYTES).await {
                Ok(BufferedBody::Complete(bytes)) => {
                    if crate::audit::parse_tool_outcome(content_type.as_deref(), &bytes)
                        == Some(true)
                    {
                        tracing::error!(
                            "mcp upstream initialize for owner {} returned a JSON-RPC error",
                            owner
                        );
                        return abort_multi_initialize(
                            state,
                            &upstream,
                            agent,
                            &routes,
                            rpc_error(StatusCode::BAD_GATEWAY, "upstream initialize failed"),
                        )
                        .await;
                    }
                }
                Ok(BufferedBody::Overflow(_, _)) => {
                    tracing::error!(
                        "mcp upstream initialize for owner {} exceeded the buffer cap",
                        owner
                    );
                    return abort_multi_initialize(
                        state,
                        &upstream,
                        agent,
                        &routes,
                        rpc_error(StatusCode::BAD_GATEWAY, "upstream initialize failed"),
                    )
                    .await;
                }
                Err(e) => {
                    tracing::error!(
                        "mcp upstream initialize read failed for owner {}: {}",
                        owner, e
                    );
                    return abort_multi_initialize(
                        state,
                        &upstream,
                        agent,
                        &routes,
                        rpc_error(StatusCode::BAD_GATEWAY, "upstream request failed"),
                    )
                    .await;
                }
            }
        }
    }

    let Some(primary) = primary_resp else {
        return rpc_error(StatusCode::BAD_GATEWAY, "upstream initialize failed");
    };

    // Pin the whole envelope under the primary upstream session ID — the
    // downstream session ID the client presents from now on.
    if let Some(dsid) = routes
        .get(&primary_owner)
        .and_then(|r| r.upstream_session.clone())
    {
        tracing::info!(
            "MCP session pinned to {} installation route(s): {} [agent={}]{}",
            routes.len(),
            owners.join(","),
            agent.id,
            session_suffix(Some(dsid.as_str()))
        );
        state
            .mcp_sessions
            .insert(
                dsid,
                SessionPin {
                    agent_id: Some(agent.id.clone()),
                    cred: PinnedCred::MultiApp {
                        routes: routes.clone(),
                        primary: primary_owner.clone(),
                    },
                },
            )
            .await;
    } else {
        tracing::warn!(
            "upstream initialize returned no session id — multi-installation session not pinned [agent={}]",
            agent.id
        );
    }

    let status =
        StatusCode::from_u16(primary.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    for name in RESP_HEADERS {
        if let Some(v) = primary.headers().get(*name) {
            builder = builder.header(*name, v.clone());
        }
    }
    builder
        .body(Body::from_stream(primary.bytes_stream()))
        .unwrap_or_else(|_| rpc_error(StatusCode::BAD_GATEWAY, "failed to build response"))
}

/// Abort a partially fanned-out initialize: best-effort DELETE of every
/// upstream session already opened, so a failed initialize does not leave
/// orphaned upstream sessions alive until server-side TTL. The provided
/// error response is returned unchanged — cleanup never masks the failure.
async fn abort_multi_initialize(
    state: &Arc<AppState>,
    upstream: &str,
    agent: &crate::config::McpAgentConfig,
    routes: &std::collections::HashMap<String, AppRoute>,
    error_resp: Response,
) -> Response {
    for (owner, route) in routes {
        let Some(us) = &route.upstream_session else { continue };
        let Some(mut h) = build_upstream_headers(&HeaderMap::new(), &route.token, &[], Some(agent))
        else {
            continue;
        };
        let Ok(v) = us.parse() else { continue };
        h.insert("mcp-session-id", v);
        match state
            .http
            .delete(upstream)
            .headers(h)
            .timeout(std::time::Duration::from_secs(DELETE_TIMEOUT_SECS))
            .send()
            .await
        {
            Ok(_) => tracing::info!(
                "aborted initialize: cleaned up upstream session for owner {} [agent={}]",
                owner, agent.id
            ),
            Err(e) => tracing::warn!(
                "aborted initialize: failed to clean up upstream session for owner {}: {}",
                owner, e
            ),
        }
    }
    error_resp
}

/// Fan a session-wide frame (DELETE, `notifications/*`) out to every route
/// of a multi-installation session, so each upstream session observes the
/// same lifecycle the client drives on the single downstream session.
/// Returns None when the session is not a multi-installation pin — the
/// caller falls through to the normal path.
async fn multi_fanout(
    state: &Arc<AppState>,
    method: &Method,
    headers: &HeaderMap,
    body: &Bytes,
    downstream_sid: &str,
    agent: Option<&crate::config::McpAgentConfig>,
) -> Option<Response> {
    let pin = state.mcp_sessions.get(downstream_sid).await?;
    if pin.agent_id.as_deref() != agent.map(|a| a.id.as_str()) {
        tracing::warn!(
            "MCP session binding violation: session initialized by {:?}, presented by {:?}{}",
            pin.agent_id,
            agent.map(|a| a.id.as_str()),
            session_suffix(Some(downstream_sid))
        );
        return Some(rpc_error(StatusCode::FORBIDDEN, "session not owned by this agent"));
    }
    let PinnedCred::MultiApp { routes, primary } = &pin.cred else {
        return None;
    };

    let upstream = state.config.mcp.upstream();
    // Primary first, then the rest — deterministic, mirrors initialize.
    let mut ordered: Vec<(&String, &AppRoute)> = routes.iter().collect();
    ordered.sort_by_key(|(o, _)| (*o != primary, (*o).clone()));

    let mut primary_result: Option<Response> = None;
    for (owner, route) in ordered {
        let Some(us) = &route.upstream_session else { continue };
        let Some(mut h) = build_upstream_headers(headers, &route.token, &[], agent) else {
            tracing::error!("credential for owner {} is not a valid header value", owner);
            continue;
        };
        let Ok(v) = us.parse() else { continue };
        h.insert("mcp-session-id", v);
        let req = if *method == Method::POST {
            state
                .http
                .post(&upstream)
                .body(reqwest::Body::from(body.clone()))
                .timeout(std::time::Duration::from_secs(POST_TIMEOUT_SECS))
        } else if *method == Method::DELETE {
            state
                .http
                .delete(&upstream)
                .timeout(std::time::Duration::from_secs(DELETE_TIMEOUT_SECS))
        } else {
            return Some(rpc_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"));
        };
        match req.headers(h).send().await {
            Ok(resp) => {
                if owner == primary && primary_result.is_none() {
                    let status = StatusCode::from_u16(resp.status().as_u16())
                        .unwrap_or(StatusCode::BAD_GATEWAY);
                    let mut builder = Response::builder().status(status);
                    for name in RESP_HEADERS {
                        if let Some(v) = resp.headers().get(*name) {
                            if *name == "mcp-session-id" {
                                // Never leak an upstream session ID downstream
                                builder = builder.header(*name, downstream_sid);
                                continue;
                            }
                            builder = builder.header(*name, v.clone());
                        }
                    }
                    let bytes = resp.bytes().await.unwrap_or_default();
                    primary_result = Some(builder.body(Body::from(bytes)).unwrap_or_else(
                        |_| rpc_error(StatusCode::BAD_GATEWAY, "failed to build response"),
                    ));
                } else {
                    let _ = resp.bytes().await;
                }
            }
            Err(e) => {
                tracing::warn!("mcp multi fan-out to owner {} failed: {}", owner, e);
            }
        }
    }

    // Session termination: drop the whole multi-route pin
    if *method == Method::DELETE {
        state.mcp_sessions.invalidate(downstream_sid).await;
    }

    Some(primary_result.unwrap_or_else(|| rpc_error(StatusCode::BAD_GATEWAY, "upstream request failed")))
}

/// RAII in-flight counter for per-agent write concurrency caps.
struct InFlightGuard {
    map: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
    key: String,
}

impl InFlightGuard {
    /// None when the agent is already at the cap.
    fn try_acquire(
        map: &Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
        key: &str,
        cap: usize,
    ) -> Option<Self> {
        let mut m = map.lock().unwrap();
        let count = m.entry(key.to_string()).or_insert(0);
        if cap > 0 && *count >= cap {
            return None;
        }
        *count += 1;
        Some(Self { map: map.clone(), key: key.to_string() })
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap();
        if let Some(c) = m.get_mut(&self.key) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// Phase 2a agent authentication.
/// - No [[mcp.agents]] configured → Phase 1 network-trust mode: Ok(None).
/// - Agents configured → every request must present a valid X-Ghpool-Key;
///   missing or unknown keys get 401 with a JSON-RPC error body.
fn authenticate<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
) -> Result<Option<&'a crate::config::McpAgentConfig>, Box<Response>> {
    let agents = &state.config.mcp.agents;
    if agents.is_empty() {
        return Ok(None);
    }
    let Some(presented) = headers.get("x-ghpool-key").and_then(|v| v.to_str().ok()) else {
        tracing::warn!("MCP request rejected: missing X-Ghpool-Key");
        return Err(Box::new(rpc_error(StatusCode::UNAUTHORIZED, "X-Ghpool-Key header required")));
    };
    for agent in agents {
        if agent.keys.iter().any(|k| keys_match(k, presented)) {
            return Ok(Some(agent));
        }
    }
    tracing::warn!("MCP request rejected: invalid X-Ghpool-Key");
    Err(Box::new(rpc_error(StatusCode::UNAUTHORIZED, "invalid X-Ghpool-Key")))
}

/// Compare keys via SHA-256 digests. Comparing fixed-length digests of both
/// values (rather than the strings themselves) means any timing variance in
/// the equality check leaks nothing useful about the configured key.
fn keys_match(configured: &str, presented: &str) -> bool {
    use sha2::{Digest, Sha256};
    Sha256::digest(configured.as_bytes()) == Sha256::digest(presented.as_bytes())
}

/// Audit attribution: agent id when authenticated, pooled identity always.
fn audit_via(agent: Option<&crate::config::McpAgentConfig>, identity_id: &str) -> String {
    match agent {
        Some(a) => format!("agent={} via {}", a.id, identity_id),
        None => format!("via {}", identity_id),
    }
}

/// Minimal JSON-RPC error body for proxy-level failures, so MCP clients that
/// only speak JSON-RPC degrade gracefully.
fn rpc_error(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": { "code": -32000, "message": message }
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("static error response")
}

/// Build the upstream header set from scratch: the client's Authorization (and
/// anything else unexpected, including any client-supplied X-MCP-*) is never
/// forwarded; the pooled token is injected.
/// Returns None if the configured token is not a valid header value (e.g.
/// contains a stray newline) — callers must not panic on misconfiguration.
///
/// Policy injection:
/// - authenticated agent → exact per-tool allowlist via X-MCP-Tools
///   (defense-in-depth; the authoritative check is in the handler). We do NOT
///   use X-MCP-Toolsets for agents: it silently ignores invalid names
///   (fail-open, #22 finding F).
/// - Phase 1 mode (no agents) → optional global X-MCP-Toolsets, as before.
fn build_upstream_headers(
    client: &HeaderMap,
    token: &str,
    toolsets: &[String],
    agent: Option<&crate::config::McpAgentConfig>,
) -> Option<HeaderMap> {
    let mut h = HeaderMap::new();
    h.insert("authorization", format!("Bearer {}", token).parse().ok()?);
    h.insert(
        "user-agent",
        concat!("ghpool/", env!("CARGO_PKG_VERSION")).parse().expect("static ua header"),
    );
    for name in FWD_HEADERS {
        if let Some(v) = client.get(*name) {
            h.insert(*name, v.clone());
        }
    }
    // MCP Streamable HTTP requires clients to accept both content types
    if !h.contains_key("accept") {
        h.insert("accept", "application/json, text/event-stream".parse().unwrap());
    }
    match agent {
        Some(a) if !a.tools.is_empty() => {
            let upstream_tools: Vec<&str> = a
                .tools
                .iter()
                .map(String::as_str)
                .filter(|tool| *tool != MINIMIZE_COMMENT_TOOL)
                .collect();
            if !upstream_tools.is_empty() {
                if let Ok(v) = upstream_tools.join(",").parse() {
                    h.insert("x-mcp-tools", v);
                }
            }
        }
        _ => {
            if !toolsets.is_empty() {
                if let Ok(v) = toolsets.join(",").parse() {
                    h.insert("x-mcp-toolsets", v);
                }
            }
        }
    }
    Some(h)
}

/// A best-effort parse of a JSON-RPC request frame.
struct Frame {
    method: String,
    /// JSON-RPC request id (for audit correlation).
    rpc_id: Option<serde_json::Value>,
    /// Tool name, for `tools/call` frames.
    tool: Option<String>,
    /// Tool arguments, for `tools/call` frames.
    arguments: Option<serde_json::Value>,
}

fn parse_frame(body: &[u8]) -> Option<Frame> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let method = v.get("method")?.as_str()?.to_string();
    let rpc_id = v.get("id").cloned();
    let (tool, arguments) = if method == "tools/call" {
        let params = v.get("params");
        (
            params
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .map(str::to_string),
            params.and_then(|p| p.get("arguments")).cloned(),
        )
    } else {
        (None, None)
    };
    Some(Frame { method, rpc_id, tool, arguments })
}

fn session_suffix(session_id: Option<&str>) -> String {
    match session_id {
        Some(sid) => format!(" [session={}]", &sid[..sid.len().min(8)]),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cache, config};
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state(identity_ids: &[&str]) -> Arc<AppState> {
        test_state_with(identity_ids, "http://unused.invalid", &[])
    }

    fn test_state_with(identity_ids: &[&str], upstream: &str, toolsets: &[&str]) -> Arc<AppState> {
        test_state_full(identity_ids, upstream, toolsets, vec![])
    }

    fn agent(id: &str, key: &str, tools: &[&str]) -> config::McpAgentConfig {
        config::McpAgentConfig {
            id: id.to_string(),
            key: None,
            keys: vec![key.to_string()],
            tools: tools.iter().map(|s| s.to_string()).collect(),
            repos: Vec::new(),
        }
    }

    fn pin(identity: &str, agent: Option<&str>) -> SessionPin {
        SessionPin {
            agent_id: agent.map(str::to_string),
            cred: PinnedCred::Pat { identity_id: identity.to_string() },
        }
    }

    fn cred_pat_id(c: &McpCredential) -> &str {
        match c {
            McpCredential::Pat(i) => &i.id,
            _ => panic!("expected PAT credential"),
        }
    }


    fn test_state_full(
        identity_ids: &[&str],
        upstream: &str,
        toolsets: &[&str],
        agents: Vec<config::McpAgentConfig>,
    ) -> Arc<AppState> {
        let identities: Vec<config::IdentityConfig> = identity_ids
            .iter()
            .map(|id| config::IdentityConfig {
                id: id.to_string(),
                token: format!("token-{}", id),
            })
            .collect();
        let pool = pool::PatPool::new(&identities);
        let cache_config = config::CacheConfig::default();
        let cache = cache::Cache::new(&cache_config);
        Arc::new(AppState {
            pool,
            cache,
            config: config::Config {
                port: 8080,
                identities,
                allowed_owners: vec!["openabdev".to_string()],
                cache: cache_config,
                mcp: config::McpConfig {
                    enabled: true,
                    enable_writes: false,
                    upstream: Some(upstream.to_string()),
                    toolsets: toolsets.iter().map(|s| s.to_string()).collect(),
                    session_ttl_secs: 3600,
                    max_inflight_writes: 4,
                    agents,
                    github_app: None,
                    github_apps: Vec::new(),
                    audit: None,
                },
            },
            token_users: moka::future::Cache::builder().max_capacity(10).build(),
            http: reqwest::Client::new(),
            mcp_sessions: moka::future::Cache::builder().max_capacity(100).build(),
            app_tokens: None,
            multi_app_tokens: None,
            audit: None,
            write_inflight: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    #[test]
    fn test_custom_tool_definition_is_namespaced_and_write_shaped() {
        let definition = custom_tool_definition();
        assert_eq!(definition["name"], MINIMIZE_COMMENT_TOOL);
        assert!(MINIMIZE_CLASSIFIERS.contains(&"OUTDATED"));
        assert_eq!(crate::policy::classify_tool(MINIMIZE_COMMENT_TOOL), crate::policy::ToolKind::Write);
    }

    #[test]
    fn test_inject_custom_tool_json_response() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let injected = inject_custom_tool(body, Some("application/json"), None).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&injected).unwrap();
        assert_eq!(json["result"]["tools"][0]["name"], MINIMIZE_COMMENT_TOOL);
    }

    #[test]
    fn test_inject_custom_tool_sse_response() {
        let body = br#"event: message
data: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}

"#;
        let injected = inject_custom_tool(body, Some("text/event-stream"), None).unwrap();
        assert!(String::from_utf8(injected).unwrap().contains(MINIMIZE_COMMENT_TOOL));
    }

    #[test]
    fn test_custom_tool_not_added_twice() {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":[{{"name":"{}"}}]}}}}"#,
            MINIMIZE_COMMENT_TOOL
        );
        let injected = inject_custom_tool(body.as_bytes(), Some("application/json"), None).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&injected).unwrap();
        assert_eq!(json["result"]["tools"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_inject_custom_tool_filters_to_allowlist() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"issue_read"},{"name":"create_issue"}]}}"#;
        let allowed = vec![MINIMIZE_COMMENT_TOOL.to_string(), "issue_read".to_string()];
        let injected = inject_custom_tool(body, Some("application/json"), Some(&allowed)).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&injected).unwrap();
        let names: Vec<&str> = json["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert_eq!(names, vec!["issue_read", MINIMIZE_COMMENT_TOOL]);
    }

    #[test]
    fn test_custom_tool_enabled_requires_allowlist_match() {
        let allowed = agent("review", "key", &[MINIMIZE_COMMENT_TOOL]);
        let other = agent("other", "key", &["issue_read"]);
        assert!(custom_tool_enabled(Some(&allowed), MINIMIZE_COMMENT_TOOL));
        assert!(!custom_tool_enabled(Some(&other), MINIMIZE_COMMENT_TOOL));
        assert!(!custom_tool_enabled(None, MINIMIZE_COMMENT_TOOL));
    }

    #[test]
    fn test_header_filter_preserves_upstream_tools() {
        let client = HeaderMap::new();
        let allowed = agent("review", "key", &[MINIMIZE_COMMENT_TOOL, "issue_read"]);
        let headers = build_upstream_headers(&client, "token", &[], Some(&allowed)).unwrap();
        assert_eq!(headers.get("x-mcp-tools").unwrap(), "issue_read");
    }

    #[test]
    fn test_parse_sse_or_json_joins_multiline_data() {
        let body = br#"event: message
data: {"jsonrpc":"2.0",
data: "id":1,"result":{"tools":[]}}

"#;
        let parsed = parse_sse_or_json(body, Some("text/event-stream")).unwrap();
        assert_eq!(parsed["result"]["tools"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_parse_frame_tools_call() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_issue","arguments":{"owner":"openabdev","repo":"ghpool"}}}"#;
        let f = parse_frame(body).unwrap();
        assert_eq!(f.method, "tools/call");
        assert_eq!(f.tool.as_deref(), Some("get_issue"));
        assert_eq!(f.arguments.unwrap()["owner"], "openabdev");
    }

    #[test]
    fn test_parse_frame_initialize() {
        let body = br#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
        let f = parse_frame(body).unwrap();
        assert_eq!(f.method, "initialize");
        assert!(f.tool.is_none());
        assert!(f.arguments.is_none());
    }

    #[test]
    fn test_parse_frame_invalid() {
        assert!(parse_frame(b"not json").is_none());
        assert!(parse_frame(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#).is_none());
    }

    #[test]
    fn test_header_rewrite_strips_client_auth() {
        let mut client = HeaderMap::new();
        client.insert("authorization", "Bearer client-secret".parse().unwrap());
        client.insert("mcp-session-id", "sess-abc".parse().unwrap());
        client.insert("mcp-protocol-version", "2025-06-18".parse().unwrap());
        client.insert("x-random-header", "should-not-forward".parse().unwrap());

        let h = build_upstream_headers(&client, "pool-token", &[], None).unwrap();

        assert_eq!(h.get("authorization").unwrap(), "Bearer pool-token");
        assert_eq!(h.get("mcp-session-id").unwrap(), "sess-abc");
        assert_eq!(h.get("mcp-protocol-version").unwrap(), "2025-06-18");
        assert!(h.get("x-random-header").is_none());
        // default accept injected when client omits it
        assert_eq!(h.get("accept").unwrap(), "application/json, text/event-stream");
        assert!(h.get("x-mcp-toolsets").is_none());
    }

    #[test]
    fn test_header_rewrite_injects_toolsets() {
        let client = HeaderMap::new();
        let toolsets = vec!["issues".to_string(), "pull_requests".to_string()];
        let h = build_upstream_headers(&client, "t", &toolsets, None).unwrap();
        assert_eq!(h.get("x-mcp-toolsets").unwrap(), "issues,pull_requests");
    }

    #[test]
    fn test_header_rewrite_invalid_token_is_error_not_panic() {
        // e.g. an untrimmed env secret with a trailing newline must not panic
        let client = HeaderMap::new();
        assert!(build_upstream_headers(&client, "tok\nen", &[], None).is_none());
        assert!(build_upstream_headers(&client, "token\n", &[], None).is_none());
    }

    #[tokio::test]
    async fn test_session_pinning_returns_pinned_identity() {
        let state = test_state(&["alice", "bob"]);
        state.mcp_sessions.insert("sess-1".to_string(), pin("bob", None)).await;

        let cred = pick_credential(&state, Some("sess-1"), None, None).await.unwrap();
        assert_eq!(cred_pat_id(&cred), "bob");
        assert_eq!(cred.token(), "token-bob");
    }

    #[tokio::test]
    async fn test_unknown_session_returns_404() {
        let state = test_state(&["alice"]);
        match pick_credential(&state, Some("never-seen"), None, None).await {
            Err(code) => assert_eq!(code, StatusCode::NOT_FOUND),
            Ok(_) => panic!("unknown session must not resolve an identity"),
        }
    }

    #[tokio::test]
    async fn test_no_session_selects_from_pool() {
        let state = test_state(&["alice"]);
        let cred = pick_credential(&state, None, None, None).await.unwrap();
        assert_eq!(cred_pat_id(&cred), "alice");
    }

    #[tokio::test]
    async fn test_no_identities_returns_503() {
        let state = test_state(&[]);
        match pick_credential(&state, None, None, None).await {
            Err(code) => assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE),
            Ok(_) => panic!("expected SERVICE_UNAVAILABLE with empty pool"),
        }
    }

    #[tokio::test]
    async fn test_stale_pin_returns_404_and_unpins() {
        // Session pinned to an identity that no longer exists in the pool:
        // treated as terminated (404), pin removed — never identity rotation.
        let state = test_state(&["alice"]);
        state.mcp_sessions.insert("sess-x".to_string(), pin("gone", None)).await;
        match pick_credential(&state, Some("sess-x"), None, None).await {
            Err(code) => assert_eq!(code, StatusCode::NOT_FOUND),
            Ok(_) => panic!("stale pin must not resolve an identity"),
        }
        assert!(state.mcp_sessions.get("sess-x").await.is_none());
    }

    // ---- Integration tests: real handler against an in-process mock upstream ----

    #[derive(Clone)]
    struct Captured {
        method: String,
        auth: Option<String>,
        toolsets: Option<String>,
        tools_hdr: Option<String>,
        ghpool_key: Option<String>,
        session: Option<String>,
        body: String,
    }

    type CapturedLog = Arc<std::sync::Mutex<Vec<Captured>>>;

    const MOCK_SSE_BODY: &str =
        "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{}}\n\n";

    /// Plays the GitHub-hosted MCP server: records every request it receives,
    /// returns an SSE response with an Mcp-Session-Id for `initialize` frames,
    /// plain JSON otherwise, and 500 for frames containing "fail_500".
    async fn mock_upstream_handler(
        State(captured): State<CapturedLog>,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
        let body_str = String::from_utf8_lossy(&body).to_string();
        captured.lock().unwrap().push(Captured {
            method: method.to_string(),
            auth: get("authorization"),
            toolsets: get("x-mcp-toolsets"),
            tools_hdr: get("x-mcp-tools"),
            ghpool_key: get("x-ghpool-key"),
            session: get("mcp-session-id"),
            body: body_str.clone(),
        });
        if body_str.contains("fail_500") {
            return Response::builder()
                .status(500)
                .body(Body::from("upstream error"))
                .unwrap();
        }
        if body_str.contains("make_it_fail") {
            // Tool-level failure inside HTTP 200 (the isError case)
            return Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"boom"}]}}"#,
                ))
                .unwrap();
        }
        if body_str.contains("\"initialize\"") {
            return Response::builder()
                .status(200)
                .header("content-type", "text/event-stream")
                .header("mcp-session-id", "mock-sess-1")
                .body(Body::from(MOCK_SSE_BODY))
                .unwrap();
        }
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#))
            .unwrap()
    }

    async fn spawn_mock_upstream() -> (String, CapturedLog) {
        let captured: CapturedLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .route("/", axum::routing::any(mock_upstream_handler))
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{}", addr), captured)
    }

    fn mcp_app(state: Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route(
                "/mcp",
                axum::routing::post(mcp_proxy).get(mcp_proxy).delete(mcp_proxy),
            )
            .with_state(state)
    }

    fn post_frame(frame: &str, extra_headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json");
        for (k, v) in extra_headers {
            builder = builder.header(*k, *v);
        }
        builder.body(Body::from(frame.to_string())).unwrap()
    }

    #[tokio::test]
    async fn test_proxy_strips_client_auth_and_injects_pool_token() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_with(&["alice"], &url, &[]);
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                &[("authorization", "Bearer client-secret")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].auth.as_deref(), Some("Bearer token-alice"));
        assert!(reqs[0].toolsets.is_none());
        assert!(reqs[0].body.contains("tools/list"));
    }

    #[tokio::test]
    async fn test_proxy_forwards_configured_toolsets() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_with(&["alice"], &url, &["issues", "pull_requests"]);
        let resp = mcp_app(state)
            .oneshot(post_frame(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, &[]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs[0].toolsets.as_deref(), Some("issues,pull_requests"));
    }

    #[tokio::test]
    async fn test_proxy_sse_passthrough_and_session_capture() {
        let (url, _captured) = spawn_mock_upstream().await;
        let state = test_state_with(&["alice"], &url, &[]);
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#, &[]))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "text/event-stream"
        );
        assert_eq!(resp.headers().get("mcp-session-id").unwrap(), "mock-sess-1");

        // SSE body streamed byte-identical
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], MOCK_SSE_BODY.as_bytes());

        // Session pinned to the identity that served initialize (Phase 1
        // mode: no agent binding)
        assert_eq!(
            state.mcp_sessions.get("mock-sess-1").await,
            Some(pin("alice", None))
        );
    }

    #[tokio::test]
    async fn test_proxy_session_pinned_across_requests() {
        let (url, captured) = spawn_mock_upstream().await;
        // Two identities: without pinning, the pool's least-used tie-break
        // would flip to the other identity on the second request.
        let state = test_state_with(&["alice", "bob"], &url, &[]);
        let app = mcp_app(state);

        let resp = app
            .clone()
            .oneshot(post_frame(r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#, &[]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                &[("mcp-session-id", "mock-sess-1")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        // Same token on both requests proves the pin overrode pool selection
        assert_eq!(reqs[0].auth, reqs[1].auth);
        assert_eq!(reqs[1].session.as_deref(), Some("mock-sess-1"));
    }

    #[tokio::test]
    async fn test_proxy_delete_unpins_session() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_with(&["alice"], &url, &[]);
        state
            .mcp_sessions
            .insert("dead-sess".to_string(), pin("alice", None))
            .await;

        let req = Request::builder()
            .method("DELETE")
            .uri("/mcp")
            .header("mcp-session-id", "dead-sess")
            .body(Body::empty())
            .unwrap();
        let resp = mcp_app(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // DELETE was forwarded upstream and the local pin was dropped
        assert_eq!(captured.lock().unwrap()[0].method, "DELETE");
        assert!(state.mcp_sessions.get("dead-sess").await.is_none());
    }

    #[tokio::test]
    async fn test_proxy_unknown_session_returns_404_jsonrpc_error() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_with(&["alice"], &url, &[]);
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                &[("mcp-session-id", "ghost-session")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Error body is a JSON-RPC error object, not a bare status
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert!(v["error"]["message"].is_string());

        // Upstream must never see a request for an unknown session
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_proxy_delete_without_session_returns_400() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_with(&["alice"], &url, &[]);
        let req = Request::builder()
            .method("DELETE")
            .uri("/mcp")
            .body(Body::empty())
            .unwrap();
        let resp = mcp_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_proxy_upstream_error_propagates() {
        let (url, _captured) = spawn_mock_upstream().await;
        let state = test_state_with(&["alice"], &url, &[]);
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fail_500"}}"#,
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ---- Phase 2a: agent authn + default-deny tool allowlist ----

    #[test]
    fn test_keys_match() {
        assert!(keys_match("secret-key-1", "secret-key-1"));
        assert!(!keys_match("secret-key-1", "secret-key-2"));
        assert!(!keys_match("secret-key-1", ""));
    }

    #[tokio::test]
    async fn test_no_agents_configured_is_open_phase1_mode() {
        // Phase 1 network-trust mode: request without any key succeeds
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(&["alice"], &url, &[], vec![]);
        let resp = mcp_app(state)
            .oneshot(post_frame(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, &[]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_agents_configured_missing_key_is_401() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![agent("bot-a", "key-a", &["issue_read"])],
        );
        let resp = mcp_app(state)
            .oneshot(post_frame(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, &[]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // JSON-RPC error body
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"]["message"].is_string());
        // Upstream never sees unauthenticated requests
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_agents_configured_wrong_key_is_401() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![agent("bot-a", "key-a", &["issue_read"])],
        );
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                &[("x-ghpool-key", "wrong-key")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_agent_allowed_tool_passes_with_tools_header() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &["issues"], // global toolsets must be ignored for agents
            vec![agent("bot-a", "key-a", &["issue_read", "get_file_contents"])],
        );
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{}}}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        // exact per-tool allowlist injected upstream
        assert_eq!(reqs[0].tools_hdr.as_deref(), Some("issue_read,get_file_contents"));
        // agent mode: global toolsets NOT injected
        assert!(reqs[0].toolsets.is_none());
        // the ghpool key itself never goes upstream
        assert!(reqs[0].ghpool_key.is_none());
        // pooled token injected as usual
        assert_eq!(reqs[0].auth.as_deref(), Some("Bearer token-alice"));
    }

    #[tokio::test]
    async fn test_agent_denied_tool_is_403_and_never_reaches_upstream() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![agent("bot-a", "key-a", &["issue_read"])],
        );
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_file_contents","arguments":{}}}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"]["message"].as_str().unwrap().contains("not permitted"));

        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_agent_empty_allowlist_denies_all_tool_calls() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(&["alice"], &url, &[], vec![agent("bot-a", "key-a", &[])]);
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{}}}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_agent_non_tool_call_methods_pass() {
        // initialize / tools/list are not tools/call — allowlist doesn't apply
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![agent("bot-a", "key-a", &["issue_read"])],
        );
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                &[("x-ghpool-key", "key-a"), ("mcp-session-id", "mock-sess-1")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(captured.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_multiple_agents_resolve_to_correct_policy() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![
                agent("bot-a", "key-a", &["issue_read"]),
                agent("bot-b", "key-b", &["issue_read", "list_issues"]),
            ],
        );
        // bot-b may call list_issues…
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","arguments":{}}}"#,
                &[("x-ghpool-key", "key-b")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            captured.lock().unwrap()[0].tools_hdr.as_deref(),
            Some("issue_read,list_issues")
        );
        // …but bot-a may not
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_issues","arguments":{}}}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    // ---- 2b-1: session-to-agent binding + dual-key rotation ----

    #[tokio::test]
    async fn test_session_binding_rejects_different_agent() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![
                agent("bot-a", "key-a", &["issue_read"]),
                agent("bot-b", "key-b", &["issue_read"]),
            ],
        );
        // bot-a initializes and owns the session
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            state.mcp_sessions.get("mock-sess-1").await,
            Some(pin("alice", Some("bot-a")))
        );

        // bot-b presents bot-a's session ID with a VALID key of its own → 403
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{}}}"#,
                &[("x-ghpool-key", "key-b"), ("mcp-session-id", "mock-sess-1")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // Upstream saw only the initialize
        assert_eq!(captured.lock().unwrap().len(), 1);

        // The rightful owner still works
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"issue_read","arguments":{}}}"#,
                &[("x-ghpool-key", "key-a"), ("mcp-session-id", "mock-sess-1")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_session_binding_rejects_phase1_session_in_agent_mode() {
        // A pin without an agent binding must not be usable by an
        // authenticated agent (and vice versa) — mode changes invalidate.
        let (url, _captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![agent("bot-a", "key-a", &["issue_read"])],
        );
        state.mcp_sessions.insert("old-sess".to_string(), pin("alice", None)).await;

        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                &[("x-ghpool-key", "key-a"), ("mcp-session-id", "old-sess")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_dual_keys_both_valid_for_rotation() {
        let (url, captured) = spawn_mock_upstream().await;
        let mut a = agent("bot-a", "old-key", &["issue_read"]);
        a.keys.push("new-key".to_string());
        let state = test_state_full(&["alice"], &url, &[], vec![a]);

        for key in ["old-key", "new-key"] {
            let resp = mcp_app(state.clone())
                .oneshot(post_frame(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                    &[("x-ghpool-key", key)],
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "key {} must be valid", key);
        }
        assert_eq!(captured.lock().unwrap().len(), 2);

        // Both keys resolve to the SAME agent (same policy)
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"not_allowed","arguments":{}}}"#,
                &[("x-ghpool-key", "new-key")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // ---- 2b-2: write classification + repo allowlists ----

    fn agent_with_repos(
        id: &str,
        key: &str,
        tools: &[&str],
        repos: &[&str],
    ) -> config::McpAgentConfig {
        let mut a = agent(id, key, tools);
        a.repos = repos.iter().map(|s| s.to_string()).collect();
        a
    }

    #[tokio::test]
    async fn test_write_tool_blocked_even_when_allowlisted() {
        // Operator mistake: create_issue on the allowlist while writes are
        // not enabled → still 403, never reaches upstream.
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![agent("bot-a", "key-a", &["issue_read", "create_issue"])],
        );
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"openabdev","repo":"ghpool","title":"x"}}}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"]["message"].as_str().unwrap().contains("write tools"));
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_repo_allowlist_allows_matching_repo() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![agent_with_repos("bot-a", "key-a", &["issue_read"], &["openabdev/ghpool"])],
        );
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"openabdev","repo":"ghpool","issue_number":15}}}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_repo_allowlist_denies_other_repo() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![agent_with_repos("bot-a", "key-a", &["issue_read"], &["openabdev/ghpool"])],
        );
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"openabdev","repo":"openab","issue_number":1}}}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_repo_allowlist_denies_unresolvable_target() {
        // search_code has no owner/repo arguments → deny-if-unresolvable
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![agent_with_repos("bot-a", "key-a", &["search_code"], &["openabdev/*"])],
        );
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_code","arguments":{"query":"foo"}}}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"]["message"].as_str().unwrap().contains("no resolvable repository"));
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_repo_allowlist_wildcard_owner() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![agent_with_repos("bot-a", "key-a", &["issue_read"], &["openabdev/*"])],
        );
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"openabdev","repo":"anything","issue_number":1}}}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_empty_repos_is_unrestricted_and_search_passes() {
        // Backward compat: 2a-style agent (no repos) can use repo-less tools
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(
            &["alice"], &url, &[],
            vec![agent("bot-a", "key-a", &["search_code"])],
        );
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_code","arguments":{"query":"foo"}}}"#,
                &[("x-ghpool-key", "key-a")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_phase1_mode_unaffected_by_write_classification() {
        // No agents → Phase 1 network-trust mode: the readonly upstream is
        // the write barrier; ghpool does not block (backward compatible).
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(&["alice"], &url, &[], vec![]);
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"o","repo":"r","title":"t"}}}"#,
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    // ---- ghpool-owned tool: handler-level tests (mock GraphQL) ----

    /// Mock api.github.com/graphql: VerifyComment queries answer with the
    /// given author/repo (viewer is always the App bot identity, with the
    /// "[bot]" suffix exactly as the live API returns it); MinimizeComment
    /// mutations are recorded and succeed.
    async fn spawn_mock_graphql(
        author_login: &'static str,
        node_repo: &'static str,
        verify_errors: bool,
    ) -> (String, Arc<std::sync::Mutex<Vec<serde_json::Value>>>) {
        use axum::{routing::post, Json, Router};
        type Log = Arc<std::sync::Mutex<Vec<serde_json::Value>>>;
        let log: Log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log2 = log.clone();
        let handler = move |Json(body): Json<serde_json::Value>| {
            let log = log2.clone();
            async move {
                let query = body["query"].as_str().unwrap_or_default().to_string();
                if query.contains("MinimizeComment") {
                    log.lock().unwrap().push(body);
                    return Json(serde_json::json!({
                        "data": {"minimizeComment": {"minimizedComment": {"isMinimized": true}}}
                    }));
                }
                if verify_errors {
                    return Json(serde_json::json!({
                        "data": null,
                        "errors": [{"message": "Could not resolve node"}]
                    }));
                }
                Json(serde_json::json!({
                    "data": {
                        "viewer": {"login": "oab-ghpool[bot]"},
                        "node": {
                            "author": {"login": author_login},
                            "issue": {"repository": {"nameWithOwner": node_repo}}
                        }
                    }
                }))
            }
        };
        let app = Router::new().route("/", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{}/", addr), log)
    }

    fn minimize_frame(owner: &str, repo: &str, classifier: &str) -> Frame {
        Frame {
            method: "tools/call".to_string(),
            rpc_id: Some(serde_json::json!(1)),
            tool: Some(MINIMIZE_COMMENT_TOOL.to_string()),
            arguments: Some(serde_json::json!({
                "owner": owner,
                "repo": repo,
                "node_id": "IC_kwDOtest",
                "classifier": classifier,
            })),
        }
    }

    fn app_cred() -> McpCredential {
        McpCredential::App(crate::app_token::AppToken {
            token: "ghs_test".to_string(),
            expires_at: now() + 3600,
        })
    }

    #[tokio::test]
    async fn test_minimize_accepts_app_bot_authored_comment() {
        // The live API returns viewer "oab-ghpool[bot]" but Bot comment
        // authors carry the bare "oab-ghpool" login — the ownership check
        // must accept the App's own comments (empirically verified shape).
        let (gql, mutations) = spawn_mock_graphql("oab-ghpool", "openabdev/ghpool", false).await;
        let state = test_state_full(&["alice"], "http://unused", &[], vec![]);
        let frame = minimize_frame("openabdev", "ghpool", "OUTDATED");
        let out = handle_minimize_comment(&state, &app_cred(), &frame, &gql).await;
        assert_eq!(out.http_status, 200);
        assert_eq!(out.tool_error, Some(false));
        let recorded = mutations.lock().unwrap();
        assert_eq!(recorded.len(), 1, "exactly one mutation");
        assert_eq!(recorded[0]["variables"]["subjectId"], "IC_kwDOtest");
        assert_eq!(recorded[0]["variables"]["classifier"], "OUTDATED");
    }

    #[tokio::test]
    async fn test_minimize_rejects_human_authored_comment() {
        let (gql, mutations) = spawn_mock_graphql("chaodu-agent", "openabdev/ghpool", false).await;
        let state = test_state_full(&["alice"], "http://unused", &[], vec![]);
        let frame = minimize_frame("openabdev", "ghpool", "OUTDATED");
        let out = handle_minimize_comment(&state, &app_cred(), &frame, &gql).await;
        assert_eq!(out.tool_error, Some(true));
        assert!(mutations.lock().unwrap().is_empty(), "no mutation for foreign authors");
    }

    #[tokio::test]
    async fn test_minimize_rejects_repo_mismatch() {
        // node_id belongs to another repository than the policy-checked
        // owner/repo arguments — must be refused before the mutation.
        let (gql, mutations) = spawn_mock_graphql("oab-ghpool", "openabdev/other-repo", false).await;
        let state = test_state_full(&["alice"], "http://unused", &[], vec![]);
        let frame = minimize_frame("openabdev", "ghpool", "OUTDATED");
        let out = handle_minimize_comment(&state, &app_cred(), &frame, &gql).await;
        assert_eq!(out.http_status, StatusCode::FORBIDDEN.as_u16());
        assert_eq!(out.tool_error, Some(true));
        assert!(mutations.lock().unwrap().is_empty(), "no cross-repo mutation");
    }

    #[tokio::test]
    async fn test_minimize_rejects_graphql_errors_and_bad_classifier() {
        // GraphQL soft errors (HTTP 200 + errors[]) fail closed.
        let (gql, mutations) = spawn_mock_graphql("oab-ghpool", "openabdev/ghpool", true).await;
        let state = test_state_full(&["alice"], "http://unused", &[], vec![]);
        let frame = minimize_frame("openabdev", "ghpool", "OUTDATED");
        let out = handle_minimize_comment(&state, &app_cred(), &frame, &gql).await;
        assert_eq!(out.tool_error, Some(true));
        assert!(mutations.lock().unwrap().is_empty());

        // Unknown classifier is rejected before any network call.
        let frame = minimize_frame("openabdev", "ghpool", "WRONG");
        let out = handle_minimize_comment(&state, &app_cred(), &frame, "http://127.0.0.1:1/").await;
        assert_eq!(out.tool_error, Some(true));
    }

    #[tokio::test]
    async fn test_phase1_mode_denies_local_minimize_tool() {
        // No agents → local write tools must not bypass the write gate and
        // reach GitHub through the legacy PAT-backed path.
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_full(&["alice"], &url, &[], vec![]);
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ghpool_review_minimize_comment","arguments":{"owner":"openabdev","repo":"ghpool","node_id":"MDU6SXNzdWUx","classifier":"OUTDATED"}}}"#,
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(captured.lock().unwrap().len(), 0);
    }

    // ---- 2b-3: GitHub App credential backend ----

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Mock GitHub API that mints installation tokens.
    async fn spawn_mock_github() -> String {
        let app = axum::Router::new().route(
            "/app/installations/42/access_tokens",
            axum::routing::post(|| async {
                let exp = time::OffsetDateTime::from_unix_timestamp((now() + 3600) as i64)
                    .unwrap()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap();
                axum::Json(serde_json::json!({"token": "ghs_mock_token", "expires_at": exp}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{}", addr)
    }

    async fn test_state_app_mode(upstream: &str) -> Arc<AppState> {
        let gh = spawn_mock_github().await;
        let provider = crate::app_token::AppTokenProvider::new(
            "12345".into(),
            crate::app_token::tests::TEST_RSA_PEM,
            Some(42),
            None,
            gh,
        )
        .unwrap();
        // No PAT identities: App backend is the only credential source
        let cache_config = config::CacheConfig::default();
        Arc::new(AppState {
            pool: pool::PatPool::new(&[]),
            cache: cache::Cache::new(&cache_config),
            config: config::Config {
                port: 8080,
                identities: vec![],
                allowed_owners: vec!["openabdev".to_string()],
                cache: cache_config,
                mcp: config::McpConfig {
                    enabled: true,
                    enable_writes: false,
                    upstream: Some(upstream.to_string()),
                    toolsets: vec![],
                    session_ttl_secs: 3600,
                    max_inflight_writes: 4,
                    agents: vec![],
                    github_app: None, // provider injected directly below
                    github_apps: Vec::new(),
                    audit: None,
                },
            },
            token_users: moka::future::Cache::builder().max_capacity(10).build(),
            http: reqwest::Client::new(),
            mcp_sessions: moka::future::Cache::builder().max_capacity(100).build(),
            app_tokens: Some(provider),
            multi_app_tokens: None,
            audit: None,
            write_inflight: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    #[tokio::test]
    async fn test_app_mode_mints_and_pins_app_credential() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_app_mode(&url).await;

        let resp = mcp_app(state.clone())
            .oneshot(post_frame(r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#, &[]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Upstream saw the App installation token
        assert_eq!(
            captured.lock().unwrap()[0].auth.as_deref(),
            Some("Bearer ghs_mock_token")
        );

        // Session pinned to the App credential by value
        let pin = state.mcp_sessions.get("mock-sess-1").await.unwrap();
        match pin.cred {
            PinnedCred::App { token, expires_at } => {
                assert_eq!(token, "ghs_mock_token");
                assert!(expires_at > now() + 3000);
            }
            other => panic!("expected App pin, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_app_mode_session_reuses_pinned_token() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_app_mode(&url).await;

        // initialize → pin
        mcp_app(state.clone())
            .oneshot(post_frame(r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#, &[]))
            .await
            .unwrap();
        // follow-up on the same session
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                &[("mcp-session-id", "mock-sess-1")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[1].auth.as_deref(), Some("Bearer ghs_mock_token"));
    }

    #[tokio::test]
    async fn test_session_cannot_outlive_app_credential() {
        let (url, captured) = spawn_mock_upstream().await;
        let state = test_state_app_mode(&url).await;

        // Simulate a session whose pinned App token has expired
        state
            .mcp_sessions
            .insert(
                "old-sess".to_string(),
                SessionPin {
                    agent_id: None,
                    cred: PinnedCred::App {
                        token: "ghs_expired".into(),
                        expires_at: now() - 10,
                    },
                },
            )
            .await;

        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                &[("mcp-session-id", "old-sess")],
            ))
            .await
            .unwrap();
        // Terminated per MCP spec: 404 → client re-initializes
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Pin removed; upstream never called
        assert!(state.mcp_sessions.get("old-sess").await.is_none());
        assert!(captured.lock().unwrap().is_empty());
    }

    // ---- 2b-4: durable fail-closed audit for write calls ----

    fn audit_tmp(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("ghpool-mcp-audit-{}-{}.jsonl", name, std::process::id()))
            .to_str().unwrap().to_string()
    }

    /// Phase-1-mode state (writes pass through) with a real audit sink.
    fn test_state_audited(upstream: &str, sink: crate::audit::AuditSink, cap: usize) -> Arc<AppState> {
        let cache_config = config::CacheConfig::default();
        let identities = vec![config::IdentityConfig { id: "alice".into(), token: "token-alice".into() }];
        Arc::new(AppState {
            pool: pool::PatPool::new(&identities),
            cache: cache::Cache::new(&cache_config),
            config: config::Config {
                port: 8080,
                identities,
                allowed_owners: vec!["openabdev".to_string()],
                cache: cache_config,
                mcp: config::McpConfig {
                    enabled: true,
                    enable_writes: false,
                    upstream: Some(upstream.to_string()),
                    toolsets: vec![],
                    session_ttl_secs: 3600,
                    max_inflight_writes: 4,
                    agents: vec![],
                    github_app: None,
                    github_apps: Vec::new(),
                    audit: Some(config::AuditConfig { path: "unused".into(), max_result_bytes: cap }),
                },
            },
            token_users: moka::future::Cache::builder().max_capacity(10).build(),
            http: reqwest::Client::new(),
            mcp_sessions: moka::future::Cache::builder().max_capacity(100).build(),
            app_tokens: None,
            multi_app_tokens: None,
            audit: Some(sink),
            write_inflight: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    fn read_audit(path: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn test_write_call_records_request_and_result() {
        let (url, _captured) = spawn_mock_upstream().await;
        let path = audit_tmp("ok");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let state = test_state_audited(&url, sink, 1024 * 1024);

        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"openabdev","repo":"ghpool","title":"secret title"}}}"#,
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // body still delivered intact
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(!body.is_empty());

        let records = read_audit(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["phase"], "request");
        assert_eq!(records[0]["tool"], "create_issue");
        assert_eq!(records[0]["repo"], "openabdev/ghpool");
        assert_eq!(records[0]["rpc_id"], 7);
        // argument VALUES never recorded
        assert!(!records[0].to_string().contains("secret title"));
        assert_eq!(records[1]["phase"], "result");
        assert_eq!(records[1]["http_status"], 200);
        assert_eq!(records[1]["tool_error"], false);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_write_call_records_tool_error_inside_http_200() {
        let (url, _captured) = spawn_mock_upstream().await;
        let path = audit_tmp("iserror");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let state = test_state_audited(&url, sink, 1024 * 1024);

        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"make_it_fail","arguments":{"owner":"o","repo":"r"}}}"#,
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK); // transport says OK…

        let records = read_audit(&path);
        assert_eq!(records[1]["http_status"], 200);
        assert_eq!(records[1]["tool_error"], true); // …audit says the operation failed
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_audit_fail_closed_rejects_write_before_upstream() {
        let (url, captured) = spawn_mock_upstream().await;
        let sink = crate::audit::AuditSink::failing_for_tests();
        let state = test_state_audited(&url, sink, 1024 * 1024);

        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"o","repo":"r"}}}"#,
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"]["message"].as_str().unwrap().contains("audit"));
        // FAIL-CLOSED: upstream never saw the call
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_read_calls_bypass_audit_sink() {
        let (url, captured) = spawn_mock_upstream().await;
        let path = audit_tmp("reads");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let state = test_state_audited(&url, sink, 1024 * 1024);

        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"o","repo":"r"}}}"#,
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(captured.lock().unwrap().len(), 1);
        // reads: streaming path, no durable records
        assert!(read_audit(&path).is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_oversize_write_response_delivered_with_null_outcome() {
        let (url, _captured) = spawn_mock_upstream().await;
        let path = audit_tmp("overflow");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        // cap of 4 bytes: every response overflows
        let state = test_state_audited(&url, sink, 4);

        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"o","repo":"r"}}}"#,
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // full body still delivered despite the tiny buffer cap
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v.get("result").is_some());

        let records = read_audit(&path);
        assert_eq!(records[1]["phase"], "result");
        assert_eq!(records[1]["tool_error"], serde_json::Value::Null);
        std::fs::remove_file(&path).ok();
    }

    // ---- 2b-5: enable writes ----

    #[test]
    fn test_scope_envelope() {
        // exact entries, single owner → repo names
        let a = agent_with_repos("a", "k", &[], &["openabdev/ghpool", "openabdev/openab"]);
        assert_eq!(scope_envelope(Some(&a)), vec!["ghpool", "openab"]);
        // wildcard → installation-wide
        let a = agent_with_repos("a", "k", &[], &["openabdev/*"]);
        assert!(scope_envelope(Some(&a)).is_empty());
        // mixed owners → installation-wide
        let a = agent_with_repos("a", "k", &[], &["openabdev/ghpool", "oablab/chi"]);
        assert!(scope_envelope(Some(&a)).is_empty());
        // no restriction → installation-wide
        let a = agent("a", "k", &[]);
        assert!(scope_envelope(Some(&a)).is_empty());
        assert!(scope_envelope(None).is_empty());
    }

    fn test_state_writes_enabled(
        upstream: &str,
        sink: crate::audit::AuditSink,
        agents: Vec<config::McpAgentConfig>,
        max_inflight: usize,
    ) -> Arc<AppState> {
        let cache_config = config::CacheConfig::default();
        let identities = vec![config::IdentityConfig { id: "alice".into(), token: "token-alice".into() }];
        Arc::new(AppState {
            pool: pool::PatPool::new(&identities),
            cache: cache::Cache::new(&cache_config),
            config: config::Config {
                port: 8080,
                identities,
                allowed_owners: vec!["openabdev".to_string()],
                cache: cache_config,
                mcp: config::McpConfig {
                    enabled: true,
                    enable_writes: true,
                    upstream: Some(upstream.to_string()),
                    toolsets: vec![],
                    session_ttl_secs: 3600,
                    max_inflight_writes: max_inflight,
                    agents,
                    github_app: None, // PAT creds acceptable for unit tests
                    github_apps: Vec::new(),
                    audit: Some(config::AuditConfig { path: "unused".into(), max_result_bytes: 1024 * 1024 }),
                },
            },
            token_users: moka::future::Cache::builder().max_capacity(10).build(),
            http: reqwest::Client::new(),
            mcp_sessions: moka::future::Cache::builder().max_capacity(100).build(),
            app_tokens: None,
            multi_app_tokens: None,
            audit: Some(sink),
            write_inflight: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    #[tokio::test]
    async fn test_write_allowed_when_enabled_with_audit_trail() {
        let (url, captured) = spawn_mock_upstream().await;
        let path = audit_tmp("write-enabled");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let state = test_state_writes_enabled(
            &url, sink,
            vec![agent_with_repos("bot-w", "key-w", &["create_issue"], &["openabdev/ghpool"])],
            4,
        );

        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"openabdev","repo":"ghpool","title":"t"}}}"#,
                &[("x-ghpool-key", "key-w")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // upstream reached, with the exact allowlist injected
        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tools_hdr.as_deref(), Some("create_issue"));
        drop(reqs);
        // audit: request + result records with agent attribution
        let records = read_audit(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["agent"], "bot-w");
        assert_eq!(records[1]["tool_error"], false);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_write_still_denied_off_allowlist_or_repo() {
        let (url, captured) = spawn_mock_upstream().await;
        let path = audit_tmp("write-denied");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let state = test_state_writes_enabled(
            &url, sink,
            vec![agent_with_repos("bot-w", "key-w", &["create_issue"], &["openabdev/ghpool"])],
            4,
        );
        // wrong repo → 403 even with writes enabled
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"evil","repo":"other","title":"t"}}}"#,
                &[("x-ghpool-key", "key-w")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // tool off allowlist → 403
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file","arguments":{"owner":"openabdev","repo":"ghpool"}}}"#,
                &[("x-ghpool-key", "key-w")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(captured.lock().unwrap().is_empty());
        // denials never reach the durable audit (pre-flight is post-policy)
        let denied_path = audit_tmp("write-denied");
        assert!(read_audit(&denied_path).is_empty());
        std::fs::remove_file(&denied_path).ok();
    }

    #[test]
    fn test_inflight_guard_cap_and_release() {
        let map = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let g1 = InFlightGuard::try_acquire(&map, "bot-a", 2);
        let g2 = InFlightGuard::try_acquire(&map, "bot-a", 2);
        assert!(g1.is_some() && g2.is_some());
        // at cap
        assert!(InFlightGuard::try_acquire(&map, "bot-a", 2).is_none());
        // other agents unaffected
        assert!(InFlightGuard::try_acquire(&map, "bot-b", 2).is_some());
        // release frees a slot
        drop(g1);
        assert!(InFlightGuard::try_acquire(&map, "bot-a", 2).is_some());
        // cap 0 = unlimited
        for _ in 0..10 {
            assert!(InFlightGuard::try_acquire(&map, "bot-c", 0).is_some());
        }
    }

    #[tokio::test]
    async fn test_write_rejected_at_inflight_cap() {
        let (url, captured) = spawn_mock_upstream().await;
        let path = audit_tmp("cap");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let state = test_state_writes_enabled(
            &url, sink,
            vec![agent_with_repos("bot-w", "key-w", &["create_issue"], &["openabdev/ghpool"])],
            1,
        );
        // Saturate the cap by holding a guard, then issue a write
        let _held = InFlightGuard::try_acquire(&state.write_inflight, "bot-w", 1).unwrap();
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"openabdev","repo":"ghpool","title":"t"}}}"#,
                &[("x-ghpool-key", "key-w")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(captured.lock().unwrap().is_empty());
        std::fs::remove_file(&path).ok();
    }

    // ---- Multi-installation GitHub App routing (one key, many orgs) ----

    /// Mock GitHub API minting distinguishable tokens per installation.
    async fn spawn_mock_github_multi() -> String {
        async fn mint(token: &'static str) -> axum::Json<serde_json::Value> {
            let exp = time::OffsetDateTime::from_unix_timestamp((now() + 3600) as i64)
                .unwrap()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
            axum::Json(serde_json::json!({"token": token, "expires_at": exp}))
        }
        let app = axum::Router::new()
            .route(
                "/app/installations/41/access_tokens",
                axum::routing::post(|| mint("ghs_openabdev")),
            )
            .route(
                "/app/installations/42/access_tokens",
                axum::routing::post(|| mint("ghs_oablab")),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{}", addr)
    }

    /// Upstream mock whose initialize responses derive the session ID from
    /// the presented bearer token — distinct installations get distinct
    /// upstream sessions. Non-initialize responses echo the session they
    /// were called with (to exercise the downstream session ID override).
    async fn mock_upstream_handler_multi(
        State(captured): State<CapturedLog>,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
        let body_str = String::from_utf8_lossy(&body).to_string();
        let auth = get("authorization");
        let session = get("mcp-session-id");
        captured.lock().unwrap().push(Captured {
            method: method.to_string(),
            auth: auth.clone(),
            toolsets: get("x-mcp-toolsets"),
            tools_hdr: get("x-mcp-tools"),
            ghpool_key: get("x-ghpool-key"),
            session: session.clone(),
            body: body_str.clone(),
        });
        if body_str.contains("fail_secondary")
            && auth.as_deref() == Some("Bearer ghs_openabdev")
        {
            // JSON-RPC error INSIDE an HTTP 200 — a session id is present
            // but the initialization failed at the protocol level.
            return Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .header("mcp-session-id", "sess-ghs_openabdev")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":0,"error":{"code":-32603,"message":"boom"}}"#,
                ))
                .unwrap();
        }
        if body_str.contains("\"initialize\"") {
            let token = auth
                .as_deref()
                .unwrap_or("")
                .trim_start_matches("Bearer ")
                .to_string();
            return Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .header("mcp-session-id", format!("sess-{}", token))
                .body(Body::from(r#"{"jsonrpc":"2.0","id":0,"result":{}}"#))
                .unwrap();
        }
        let mut builder = Response::builder()
            .status(200)
            .header("content-type", "application/json");
        if let Some(sid) = session {
            builder = builder.header("mcp-session-id", sid);
        }
        builder
            .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#))
            .unwrap()
    }

    async fn spawn_mock_upstream_multi() -> (String, CapturedLog) {
        let captured: CapturedLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .route("/", axum::routing::any(mock_upstream_handler_multi))
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{}", addr), captured)
    }

    /// Multi-installation state: agent b0 spans openabdev (installation 41)
    /// and oablab (installation 42). Sorted owners make oablab the primary.
    async fn test_state_multi(
        upstream: &str,
        enable_writes: bool,
        sink: Option<crate::audit::AuditSink>,
    ) -> Arc<AppState> {
        let gh = spawn_mock_github_multi().await;
        let entries = vec![
            config::GithubAppsEntry {
                app_id: "111".into(),
                private_key: crate::app_token::tests::TEST_RSA_PEM.into(),
                installation_id: Some(41),
                owner: "openabdev".into(),
            },
            config::GithubAppsEntry {
                app_id: "222".into(),
                private_key: crate::app_token::tests::TEST_RSA_PEM.into(),
                installation_id: Some(42),
                owner: "oablab".into(),
            },
        ];
        let multi = crate::app_token::MultiAppTokenProvider::new(&entries, gh).unwrap();
        let agents = vec![
            agent_with_repos(
                "b0",
                "key-b0",
                &["issue_read", "list_issues", "create_issue", "add_issue_comment"],
                &["openabdev/openab", "oablab/chi"],
            ),
            // Second agent with a valid key of its own — for session
            // binding tests (must never be able to ride b0's session).
            agent_with_repos(
                "intruder",
                "key-intruder",
                &["issue_read"],
                &["openabdev/openab"],
            ),
            // Repo-less agent (like the legacy b2): keeps the PAT-backed
            // read path in multi mode, writes always denied.
            agent_with_repos(
                "b2pat",
                "key-b2pat",
                &["search_code", "issue_read", "create_issue"],
                &[],
            ),
        ];
        let cache_config = config::CacheConfig::default();
        let has_sink = sink.is_some();
        let identities = vec![config::IdentityConfig {
            id: "alice".into(),
            token: "token-alice".into(),
        }];
        Arc::new(AppState {
            pool: pool::PatPool::new(&identities),
            cache: cache::Cache::new(&cache_config),
            config: config::Config {
                port: 8080,
                identities: identities.clone(),
                allowed_owners: vec!["openabdev".to_string(), "oablab".to_string()],
                cache: cache_config,
                mcp: config::McpConfig {
                    enabled: true,
                    enable_writes,
                    upstream: Some(upstream.to_string()),
                    toolsets: vec![],
                    session_ttl_secs: 3600,
                    max_inflight_writes: 4,
                    agents,
                    github_app: None,
                    github_apps: entries,
                    audit: has_sink.then(|| config::AuditConfig {
                        path: "unused".into(),
                        max_result_bytes: 1024 * 1024,
                    }),
                },
            },
            token_users: moka::future::Cache::builder().max_capacity(10).build(),
            http: reqwest::Client::new(),
            mcp_sessions: moka::future::Cache::builder().max_capacity(100).build(),
            app_tokens: None,
            multi_app_tokens: Some(multi),
            audit: sink,
            write_inflight: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    const MULTI_INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#;

    #[test]
    fn test_route_owners_and_owner_envelope() {
        let a = agent_with_repos(
            "a", "k", &[],
            &["openabdev/openab", "OABLAB/chi", "openabdev/ghpool"],
        );
        assert_eq!(route_owners(&a), vec!["oablab", "openabdev"]);
        assert_eq!(scope_envelope_for_owner(&a, "openabdev"), vec!["openab", "ghpool"]);
        assert_eq!(scope_envelope_for_owner(&a, "oablab"), vec!["chi"]);
        assert!(scope_envelope_for_owner(&a, "other").is_empty());
        // wildcard for the owner → installation-wide
        let w = agent_with_repos("a", "k", &[], &["openabdev/*", "openabdev/openab"]);
        assert!(scope_envelope_for_owner(&w, "openabdev").is_empty());
        // other owners unaffected by that wildcard
        let m = agent_with_repos("a", "k", &[], &["openabdev/*", "oablab/chi"]);
        assert_eq!(scope_envelope_for_owner(&m, "oablab"), vec!["chi"]);
    }

    #[tokio::test]
    async fn test_multi_initialize_fans_out_and_pins_routes() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let state = test_state_multi(&url, false, None).await;
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(MULTI_INIT, &[("x-ghpool-key", "key-b0")]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Primary is the first sorted owner (oablab) — its upstream session
        // ID is the downstream session ID.
        assert_eq!(resp.headers().get("mcp-session-id").unwrap(), "sess-ghs_oablab");

        // One upstream initialize per installation, each with its own token
        {
            let reqs = captured.lock().unwrap();
            assert_eq!(reqs.len(), 2);
            let auths: Vec<String> =
                reqs.iter().map(|r| r.auth.clone().unwrap_or_default()).collect();
            assert!(auths.contains(&"Bearer ghs_oablab".to_string()));
            assert!(auths.contains(&"Bearer ghs_openabdev".to_string()));
        }

        // The pin covers both routes with distinct upstream sessions
        let pin = state.mcp_sessions.get("sess-ghs_oablab").await.unwrap();
        assert_eq!(pin.agent_id.as_deref(), Some("b0"));
        match pin.cred {
            PinnedCred::MultiApp { routes, primary } => {
                assert_eq!(primary, "oablab");
                assert_eq!(routes.len(), 2);
                assert_eq!(routes["oablab"].token, "ghs_oablab");
                assert_eq!(
                    routes["oablab"].upstream_session.as_deref(),
                    Some("sess-ghs_oablab")
                );
                assert_eq!(routes["openabdev"].token, "ghs_openabdev");
                assert_eq!(
                    routes["openabdev"].upstream_session.as_deref(),
                    Some("sess-ghs_openabdev")
                );
            }
            other => panic!("expected MultiApp pin, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_multi_tools_call_routes_by_owner() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let state = test_state_multi(&url, false, None).await;
        mcp_app(state.clone())
            .oneshot(post_frame(MULTI_INIT, &[("x-ghpool-key", "key-b0")]))
            .await
            .unwrap();
        captured.lock().unwrap().clear();

        // openabdev call → openabdev token, on openabdev's OWN upstream
        // session; the client still sees the downstream session ID.
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"openabdev","repo":"openab","issue_number":1}}}"#,
                &[("x-ghpool-key", "key-b0"), ("mcp-session-id", "sess-ghs_oablab")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("mcp-session-id").unwrap(), "sess-ghs_oablab");

        // oablab call → oablab token on the primary upstream session
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"oablab","repo":"chi","issue_number":2}}}"#,
                &[("x-ghpool-key", "key-b0"), ("mcp-session-id", "sess-ghs_oablab")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("mcp-session-id").unwrap(), "sess-ghs_oablab");

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].auth.as_deref(), Some("Bearer ghs_openabdev"));
        assert_eq!(reqs[0].session.as_deref(), Some("sess-ghs_openabdev"));
        assert_eq!(reqs[1].auth.as_deref(), Some("Bearer ghs_oablab"));
        assert_eq!(reqs[1].session.as_deref(), Some("sess-ghs_oablab"));
    }

    #[tokio::test]
    async fn test_multi_uncovered_owner_denied_by_policy() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let state = test_state_multi(&url, false, None).await;
        mcp_app(state.clone())
            .oneshot(post_frame(MULTI_INIT, &[("x-ghpool-key", "key-b0")]))
            .await
            .unwrap();
        captured.lock().unwrap().clear();

        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"evil","repo":"repo","issue_number":1}}}"#,
                &[("x-ghpool-key", "key-b0"), ("mcp-session-id", "sess-ghs_oablab")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_multi_stateless_call_routes_without_session() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let state = test_state_multi(&url, false, None).await;
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"openabdev","repo":"openab","issue_number":1}}}"#,
                &[("x-ghpool-key", "key-b0")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].auth.as_deref(), Some("Bearer ghs_openabdev"));
        // stateless: no session forwarded upstream
        assert!(reqs[0].session.is_none());
    }

    #[tokio::test]
    async fn test_multi_expired_route_terminates_session() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let state = test_state_multi(&url, false, None).await;
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "openabdev".to_string(),
            AppRoute {
                token: "ghs_expired".into(),
                expires_at: now() - 10,
                upstream_session: Some("u1".into()),
            },
        );
        routes.insert(
            "oablab".to_string(),
            AppRoute {
                token: "ghs_live".into(),
                expires_at: now() + 3600,
                upstream_session: Some("u2".into()),
            },
        );
        state
            .mcp_sessions
            .insert(
                "dsid".to_string(),
                SessionPin {
                    agent_id: Some("b0".into()),
                    cred: PinnedCred::MultiApp { routes, primary: "oablab".into() },
                },
            )
            .await;

        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                // Call the LIVE route (oablab): routes are minted together,
                // so ANY expired route terminates the session as a whole.
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"oablab","repo":"chi","issue_number":1}}}"#,
                &[("x-ghpool-key", "key-b0"), ("mcp-session-id", "dsid")],
            ))
            .await
            .unwrap();
        // Terminated per MCP spec: 404 → client re-initializes (fresh mints)
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(state.mcp_sessions.get("dsid").await.is_none());
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_multi_initialize_fails_closed_on_secondary_jsonrpc_error() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let state = test_state_multi(&url, false, None).await;
        // The mock returns a JSON-RPC error (inside HTTP 200) for the
        // openabdev (secondary) installation when the frame is tagged.
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"tag":"fail_secondary"}}"#,
                &[("x-ghpool-key", "key-b0")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        // No session pinned
        assert!(state.mcp_sessions.get("sess-ghs_oablab").await.is_none());
        // Partial-initialize cleanup: every upstream session opened before
        // the failure was DELETEd with its own credential — no orphans.
        let reqs = captured.lock().unwrap();
        let posts: Vec<&Captured> = reqs.iter().filter(|r| r.method == "POST").collect();
        assert_eq!(posts.len(), 2);
        let deletes: Vec<(String, String)> = reqs
            .iter()
            .filter(|r| r.method == "DELETE")
            .map(|r| {
                (r.auth.clone().unwrap_or_default(), r.session.clone().unwrap_or_default())
            })
            .collect();
        assert!(
            deletes.contains(&("Bearer ghs_oablab".into(), "sess-ghs_oablab".into())),
            "primary upstream session must be cleaned up, got {:?}",
            deletes
        );
        assert!(
            deletes.contains(&("Bearer ghs_openabdev".into(), "sess-ghs_openabdev".into())),
            "failed secondary's session must be cleaned up too, got {:?}",
            deletes
        );
    }

    #[tokio::test]
    async fn test_multi_notifications_fan_out_to_all_routes() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let state = test_state_multi(&url, false, None).await;
        mcp_app(state.clone())
            .oneshot(post_frame(MULTI_INIT, &[("x-ghpool-key", "key-b0")]))
            .await
            .unwrap();
        captured.lock().unwrap().clear();

        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                &[("x-ghpool-key", "key-b0"), ("mcp-session-id", "sess-ghs_oablab")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Never leak an upstream session ID downstream
        assert_eq!(resp.headers().get("mcp-session-id").unwrap(), "sess-ghs_oablab");

        // Every installation's upstream session received the notification
        // with its own credential and its own session ID
        {
            let reqs = captured.lock().unwrap();
            assert_eq!(reqs.len(), 2);
            assert!(reqs.iter().all(|r| r.body.contains("notifications/initialized")));
            let pairs: Vec<(String, String)> = reqs
                .iter()
                .map(|r| {
                    (r.auth.clone().unwrap_or_default(), r.session.clone().unwrap_or_default())
                })
                .collect();
            assert!(pairs.contains(&("Bearer ghs_oablab".into(), "sess-ghs_oablab".into())));
            assert!(pairs.contains(&("Bearer ghs_openabdev".into(), "sess-ghs_openabdev".into())));
        }

        // Notification fan-out does not terminate the session
        assert!(state.mcp_sessions.get("sess-ghs_oablab").await.is_some());
    }

    #[tokio::test]
    async fn test_multi_session_binding_rejects_other_agent() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let state = test_state_multi(&url, false, None).await;
        mcp_app(state.clone())
            .oneshot(post_frame(MULTI_INIT, &[("x-ghpool-key", "key-b0")]))
            .await
            .unwrap();
        captured.lock().unwrap().clear();

        // A different agent with a VALID key of its own, presenting b0's
        // session on tools/call (routed path) → 403, upstream untouched
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"openabdev","repo":"openab","issue_number":1}}}"#,
                &[("x-ghpool-key", "key-intruder"), ("mcp-session-id", "sess-ghs_oablab")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(captured.lock().unwrap().is_empty());

        // Same for DELETE (fan-out path) → 403, pin survives
        let req = Request::builder()
            .method("DELETE")
            .uri("/mcp")
            .header("x-ghpool-key", "key-intruder")
            .header("mcp-session-id", "sess-ghs_oablab")
            .body(Body::empty())
            .unwrap();
        let resp = mcp_app(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(captured.lock().unwrap().is_empty());
        assert!(state.mcp_sessions.get("sess-ghs_oablab").await.is_some());

        // The rightful owner still works
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"oablab","repo":"chi","issue_number":2}}}"#,
                &[("x-ghpool-key", "key-b0"), ("mcp-session-id", "sess-ghs_oablab")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_multi_delete_fans_out_to_all_routes() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let state = test_state_multi(&url, false, None).await;
        mcp_app(state.clone())
            .oneshot(post_frame(MULTI_INIT, &[("x-ghpool-key", "key-b0")]))
            .await
            .unwrap();
        captured.lock().unwrap().clear();

        let req = Request::builder()
            .method("DELETE")
            .uri("/mcp")
            .header("x-ghpool-key", "key-b0")
            .header("mcp-session-id", "sess-ghs_oablab")
            .body(Body::empty())
            .unwrap();
        let resp = mcp_app(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Every installation's upstream session was terminated, each with
        // its own credential
        {
            let reqs = captured.lock().unwrap();
            assert_eq!(reqs.len(), 2);
            assert!(reqs.iter().all(|r| r.method == "DELETE"));
            let pairs: Vec<(String, String)> = reqs
                .iter()
                .map(|r| {
                    (r.auth.clone().unwrap_or_default(), r.session.clone().unwrap_or_default())
                })
                .collect();
            assert!(pairs.contains(&("Bearer ghs_oablab".into(), "sess-ghs_oablab".into())));
            assert!(pairs.contains(&("Bearer ghs_openabdev".into(), "sess-ghs_openabdev".into())));
        }

        assert!(state.mcp_sessions.get("sess-ghs_oablab").await.is_none());
    }

    #[tokio::test]
    async fn test_multi_repoless_agent_keeps_pat_read_path() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let state = test_state_multi(&url, false, None).await;

        // initialize as the repo-less agent: NO fan-out — single upstream
        // request, served by the pooled PAT, pinned normally
        let resp = mcp_app(state.clone())
            .oneshot(post_frame(MULTI_INIT, &[("x-ghpool-key", "key-b2pat")]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("mcp-session-id").unwrap(), "sess-token-alice");
        {
            let reqs = captured.lock().unwrap();
            assert_eq!(reqs.len(), 1, "repo-less agent must not fan out");
            assert_eq!(reqs[0].auth.as_deref(), Some("Bearer token-alice"));
        }
        assert_eq!(
            state.mcp_sessions.get("sess-token-alice").await,
            Some(pin("alice", Some("b2pat")))
        );

        // repo-less read tools (search_code) still work on the session
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_code","arguments":{"query":"foo"}}}"#,
                &[("x-ghpool-key", "key-b2pat"), ("mcp-session-id", "sess-token-alice")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(captured.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_multi_repoless_agent_writes_denied_even_when_enabled() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let path = audit_tmp("repoless-write");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        // writes globally enabled — the repo-less agent must still be denied
        let state = test_state_multi(&url, true, Some(sink)).await;
        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"openabdev","repo":"openab","title":"t"}}}"#,
                &[("x-ghpool-key", "key-b2pat")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"]["message"].as_str().unwrap().contains("repository-scoped"));
        assert!(captured.lock().unwrap().is_empty());
        assert!(read_audit(&path).is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_multi_write_audited_with_installation_label() {
        let (url, captured) = spawn_mock_upstream_multi().await;
        let path = audit_tmp("multi-write");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let state = test_state_multi(&url, true, Some(sink)).await;
        mcp_app(state.clone())
            .oneshot(post_frame(MULTI_INIT, &[("x-ghpool-key", "key-b0")]))
            .await
            .unwrap();
        captured.lock().unwrap().clear();

        let resp = mcp_app(state)
            .oneshot(post_frame(
                r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"openabdev","repo":"openab","title":"t"}}}"#,
                &[("x-ghpool-key", "key-b0"), ("mcp-session-id", "sess-ghs_oablab")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Forwarded with the openabdev installation credential
        {
            let reqs = captured.lock().unwrap();
            assert_eq!(reqs.len(), 1);
            assert_eq!(reqs[0].auth.as_deref(), Some("Bearer ghs_openabdev"));
        }

        // Audit attributes the write to the exact installation
        let records = read_audit(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["phase"], "request");
        assert_eq!(records[0]["agent"], "b0");
        assert_eq!(records[0]["cred"], "github-app:openabdev");
        assert_eq!(records[0]["repo"], "openabdev/openab");
        assert_eq!(records[1]["phase"], "result");
        assert_eq!(records[1]["tool_error"], false);
        std::fs::remove_file(&path).ok();
    }
}
