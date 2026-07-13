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
    let cred = match pick_credential(&state, session_id.as_deref(), agent_id).await {
        Ok(c) => c,
        Err(StatusCode::NOT_FOUND) => {
            // Per MCP Streamable HTTP spec: unknown/expired sessions get 404,
            // prompting the client to re-initialize. Never rotate identities
            // mid-session.
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

    // Audit log + policy enforcement (single frame parse, kept for the
    // write-audit path below)
    let frame = if method == Method::POST { parse_frame(&body) } else { None };
    let mut resolved_repo: Option<(String, String)> = None;
    if let Some(frame) = &frame {
        if frame.method == "tools/call" {
            if let Some(tool_name) = frame.tool.as_deref() {
                resolved_repo = crate::policy::resolve_repo(frame.arguments.as_ref());
                if let Some(agent) = agent {
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
                    // 2. Write classification: ALL write-classified tools
                    //    are blocked until the write path ships (2b-5).
                    //    Unknown tools classify as writes (conservative).
                    if crate::policy::classify_tool(tool_name) == crate::policy::ToolKind::Write {
                        tracing::warn!(
                            "MCP tools/call {} DENIED (write tools not enabled) [agent={}]{}",
                            tool_name, agent.id, session_suffix(session_id.as_deref())
                        );
                        return rpc_error(
                            StatusCode::FORBIDDEN,
                            "write tools are not enabled",
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
                let repo_suffix = resolved_repo
                    .as_ref()
                    .map(|(o, r)| format!(" repo={}/{}", o, r))
                    .unwrap_or_default();
                tracing::info!(
                    "MCP tools/call {}{} [{}]{}",
                    tool_name, repo_suffix,
                    audit_via(agent, cred.label()),
                    session_suffix(session_id.as_deref())
                );
            } else {
                tracing::info!(
                    "MCP tools/call [{}]{}",
                    audit_via(agent, cred.label()),
                    session_suffix(session_id.as_deref())
                );
            }
        } else {
            tracing::info!(
                "MCP {} [{}]{}",
                frame.method,
                audit_via(agent, cred.label()),
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
    if let (Some(tool_name), Some(sink)) = (&write_call, &state.audit) {
        let call = crate::audit::CallInfo {
            rpc_id: frame.as_ref().and_then(|f| f.rpc_id.as_ref()),
            session: session_id.as_deref(),
            agent: agent_id,
            credential: cred.label(),
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

    let upstream = &state.config.mcp.upstream;
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
        Method::GET => state.http.get(upstream),
        Method::DELETE => state
            .http
            .delete(upstream)
            .timeout(std::time::Duration::from_secs(DELETE_TIMEOUT_SECS)),
        _ => return rpc_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    };

    let Some(upstream_headers) =
        build_upstream_headers(&headers, cred.token(), &state.config.mcp.toolsets, agent)
    else {
        tracing::error!(
            "credential '{}' is not a valid header value — check secret source",
            cred.label()
        );
        return rpc_error(StatusCode::BAD_GATEWAY, "upstream credential misconfigured");
    };

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
        tracing::warn!("MCP upstream 429 on App installation token");
    }

    // Pin new sessions: upstream returns Mcp-Session-Id on initialize.
    // The pin binds the session to the exact credential and the agent that
    // initialized it.
    if let Some(sid) = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        if state.mcp_sessions.get(sid).await.is_none() {
            tracing::info!(
                "MCP session pinned to credential {}{}{}",
                cred.label(),
                agent_id.map(|a| format!(" [agent={}]", a)).unwrap_or_default(),
                session_suffix(Some(sid))
            );
            state
                .mcp_sessions
                .insert(sid.to_string(), cred.to_pin(agent_id))
                .await;
        }
    }

    // Session termination: drop the pin
    if method == Method::DELETE {
        if let Some(sid) = &session_id {
            state.mcp_sessions.invalidate(sid).await;
        }
    }

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    for name in RESP_HEADERS {
        if let Some(v) = resp.headers().get(*name) {
            builder = builder.header(*name, v.clone());
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
            credential: cred.label(),
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
}

/// The upstream credential resolved for one request.
pub enum McpCredential {
    Pat(pool::Identity),
    App(crate::app_token::AppToken),
}

impl McpCredential {
    fn token(&self) -> &str {
        match self {
            McpCredential::Pat(i) => &i.token,
            McpCredential::App(t) => &t.token,
        }
    }
    /// Audit label for the credential.
    fn label(&self) -> &str {
        match self {
            McpCredential::Pat(i) => &i.id,
            McpCredential::App(_) => "github-app",
        }
    }
    fn to_pin(&self, agent_id: Option<&str>) -> SessionPin {
        SessionPin {
            agent_id: agent_id.map(str::to_string),
            cred: match self {
                McpCredential::Pat(i) => PinnedCred::Pat { identity_id: i.id.clone() },
                McpCredential::App(t) => PinnedCred::App {
                    token: t.token.clone(),
                    expires_at: t.expires_at,
                },
            },
        }
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
async fn pick_credential(
    state: &AppState,
    session_id: Option<&str>,
    agent_id: Option<&str>,
) -> Result<McpCredential, StatusCode> {
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
            }
        }
        return Err(StatusCode::NOT_FOUND);
    }
    // New session: App backend takes precedence when configured
    if let Some(provider) = &state.app_tokens {
        return match provider.token().await {
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
            if let Ok(v) = a.tools.join(",").parse() {
                h.insert("x-mcp-tools", v);
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
            McpCredential::App(_) => panic!("expected PAT credential"),
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
                    upstream: upstream.to_string(),
                    toolsets: toolsets.iter().map(|s| s.to_string()).collect(),
                    session_ttl_secs: 3600,
                    agents,
                    github_app: None,
                    audit: None,
                },
            },
            token_users: moka::future::Cache::builder().max_capacity(10).build(),
            http: reqwest::Client::new(),
            mcp_sessions: moka::future::Cache::builder().max_capacity(100).build(),
            app_tokens: None,
            audit: None,
        })
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

        let cred = pick_credential(&state, Some("sess-1"), None).await.unwrap();
        assert_eq!(cred_pat_id(&cred), "bob");
        assert_eq!(cred.token(), "token-bob");
    }

    #[tokio::test]
    async fn test_unknown_session_returns_404() {
        let state = test_state(&["alice"]);
        match pick_credential(&state, Some("never-seen"), None).await {
            Err(code) => assert_eq!(code, StatusCode::NOT_FOUND),
            Ok(_) => panic!("unknown session must not resolve an identity"),
        }
    }

    #[tokio::test]
    async fn test_no_session_selects_from_pool() {
        let state = test_state(&["alice"]);
        let cred = pick_credential(&state, None, None).await.unwrap();
        assert_eq!(cred_pat_id(&cred), "alice");
    }

    #[tokio::test]
    async fn test_no_identities_returns_503() {
        let state = test_state(&[]);
        match pick_credential(&state, None, None).await {
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
        match pick_credential(&state, Some("sess-x"), None).await {
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
                    upstream: upstream.to_string(),
                    toolsets: vec![],
                    session_ttl_secs: 3600,
                    agents: vec![],
                    github_app: None, // provider injected directly below
                    audit: None,
                },
            },
            token_users: moka::future::Cache::builder().max_capacity(10).build(),
            http: reqwest::Client::new(),
            mcp_sessions: moka::future::Cache::builder().max_capacity(100).build(),
            app_tokens: Some(provider),
            audit: None,
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
                    upstream: upstream.to_string(),
                    toolsets: vec![],
                    session_ttl_secs: 3600,
                    agents: vec![],
                    github_app: None,
                    audit: Some(config::AuditConfig { path: "unused".into(), max_result_bytes: cap }),
                },
            },
            token_users: moka::future::Cache::builder().max_capacity(10).build(),
            http: reqwest::Client::new(),
            mcp_sessions: moka::future::Cache::builder().max_capacity(100).build(),
            app_tokens: None,
            audit: Some(sink),
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
}
