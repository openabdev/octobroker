mod app_token;
mod audit;
mod cache;
mod config;
mod mcp;
mod policy;
mod pool;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::get,
    routing::post,
    Router,
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};
use tracing_subscriber::EnvFilter;

struct AppState {
    pool: pool::PatPool,
    cache: cache::Cache,
    config: config::Config,
    token_users: moka::future::Cache<String, String>,
    http: reqwest::Client,
    /// MCP session pinning: Mcp-Session-Id → (pooled identity, agent binding)
    mcp_sessions: moka::future::Cache<String, mcp::SessionPin>,
    /// GitHub App installation token provider for the MCP path (2b).
    /// None = PAT pool backend.
    app_tokens: Option<app_token::AppTokenProvider>,
    /// Durable audit sink for write-classified MCP calls (2b). None = audit
    /// not configured (writes cannot be enabled without it).
    audit: Option<audit::AuditSink>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("ghpool=info".parse().unwrap()))
        .with_timer(tracing_subscriber::fmt::time::LocalTime::new(
            time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]").unwrap(),
        ))
        .init();

    let config = config::Config::load().await;
    let pool = pool::PatPool::new(&config.identities);
    let cache = cache::Cache::new(&config.cache);

    let app_tokens = config.mcp.github_app.as_ref().map(|app| {
        app_token::AppTokenProvider::new(
            app.app_id.clone(),
            &app.private_key,
            app.installation_id,
            app.owner.clone(),
            "https://api.github.com".to_string(),
        )
        .expect("invalid [mcp.github_app] config")
    });
    if app_tokens.is_some() {
        tracing::info!("MCP credential backend: GitHub App installation tokens");
    }

    let audit = config.mcp.audit.as_ref().map(|a| {
        let sink = audit::AuditSink::open(&a.path).expect("invalid [mcp.audit] config");
        tracing::info!("MCP durable audit enabled → {}", a.path);
        sink
    });

    let state = Arc::new(AppState {
        pool,
        cache,
        config: config.clone(),
        token_users: moka::future::Cache::builder().max_capacity(100).build(),
        http: reqwest::Client::new(),
        mcp_sessions: moka::future::Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(std::time::Duration::from_secs(config.mcp.session_ttl_secs))
            .build(),
        app_tokens,
        audit,
    });

    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/stats", get(stats))
        .route("/graphql", post(graphql_proxy))
        .route("/raw/{*path}", get(proxy_raw))
        .route("/{*path}", get(proxy));

    if config.mcp.enabled {
        tracing::info!("MCP reverse proxy enabled → {}", config.mcp.upstream);
        app = app.route(
            "/mcp",
            post(mcp::mcp_proxy)
                .get(mcp::mcp_proxy)
                .delete(mcp::mcp_proxy)
                .layer(axum::extract::DefaultBodyLimit::max(mcp::MAX_BODY_BYTES)),
        );
    }

    let app = app.with_state(state);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("ghpool listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn healthz() -> &'static str {
    "ok"
}

async fn stats(State(state): State<Arc<AppState>>) -> Json<Value> {
    let identities = state.pool.snapshot();
    let cache_stats = state.cache.stats();
    Json(serde_json::json!({
        "identities": identities,
        "cache": cache_stats,
    }))
}

async fn proxy(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    let api_path = format!("/{}", path);

    // Check allowed owners
    if !is_allowed_path(&api_path, &state.config.allowed_owners) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Build cache key
    let cache_key = cache::build_key(&api_path, &query);

    // Check cache
    if let Some(cached) = state.cache.get(&cache_key).await {
        tracing::info!("200 OK {} [cache HIT]", api_path);
        return Ok(Json(cached));
    }

    // Select identity from pool
    let identity = state.pool.select().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    // Build GitHub API URL
    let mut url = format!("https://api.github.com{}", api_path);
    if !query.is_empty() {
        let qs: Vec<String> = query.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        url = format!("{}?{}", url, qs.join("&"));
    }

    // Forward request
    let mut req = state.http.get(&url)
        .header("Authorization", format!("Bearer {}", identity.token))
        .header("User-Agent", concat!("ghpool/", env!("CARGO_PKG_VERSION")))
        .header("Accept", "application/vnd.github+json");

    if let Some(version) = headers.get("x-github-api-version") {
        req = req.header("X-GitHub-Api-Version", version);
    }

    let resp = req.send().await.map_err(|e| {
        tracing::error!("github request failed: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    // Update rate limit from response headers
    let rate_remaining = resp.headers()
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok());
    let rate_reset = resp.headers()
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    state.pool.update_rate(&identity.id, rate_remaining, rate_reset);

    let status = resp.status();
    let body: Value = resp.json().await.map_err(|e| {
        tracing::error!("failed to parse github response: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    if !status.is_success() {
        tracing::warn!("github returned {}: {}", status, api_path);
        return Err(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY));
    }

    // Write to cache
    let route_kind = cache::classify_route(&api_path);
    state.cache.insert(&cache_key, &body, route_kind).await;

    tracing::info!("200 OK {} [via {}]", api_path, identity.id);
    Ok(Json(body))
}

async fn proxy_raw(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<(StatusCode, HeaderMap, String), StatusCode> {
    let api_path = format!("/{}", path);

    if !is_allowed_path(&api_path, &state.config.allowed_owners) {
        return Err(StatusCode::FORBIDDEN);
    }

    let accept = headers.get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.github.v3.diff")
        .to_string();

    // Select the identity BEFORE checking the cache. The cache key is scoped
    // to this identity so a response fetched under one PAT's access scope is
    // never served to a caller that would resolve to a different identity
    // (prevents cross-identity leakage when the pool holds PATs with
    // different repo access).
    let identity = state.pool.select().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let cache_key = cache::build_raw_key(&api_path, &query, &accept, &identity.id);

    let mut url = format!("https://api.github.com{}", api_path);
    if !query.is_empty() {
        let qs: Vec<String> = query.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        url = format!("{}?{}", url, qs.join("&"));
    }

    let state_for_fetch = state.clone();
    let token = identity.token.clone();
    let identity_id = identity.id.clone();
    let api_path_for_log = api_path.clone();

    let result = state.cache.get_or_insert_raw(&cache_key, async move {
        let resp = state_for_fetch.http.get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("User-Agent", concat!("ghpool/", env!("CARGO_PKG_VERSION")))
            .header("Accept", &accept)
            .send()
            .await
            .map_err(|e| format!("github request failed: {e}"))?;

        let rate_remaining = resp.headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        let rate_reset = resp.headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        state_for_fetch.pool.update_rate(&identity_id, rate_remaining, rate_reset);

        let status = resp.status();
        let body = resp.text().await.map_err(|_| "failed to read response body".to_string())?;

        if !status.is_success() {
            tracing::warn!("github returned {}: {}", status, api_path_for_log);
            // Encode the status so the caller can map it back to an HTTP error.
            return Err(format!("upstream_status:{}", status.as_u16()));
        }

        Ok(body)
    }).await;

    match result {
        Ok(body) => {
            tracing::info!("200 OK {} [raw, via {}]", api_path, identity.id);
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert("content-type", "text/plain".parse().unwrap());
            Ok((StatusCode::OK, resp_headers, body))
        }
        Err(e) => {
            if let Some(code_str) = e.strip_prefix("upstream_status:") {
                if let Ok(code) = code_str.parse::<u16>() {
                    return Err(StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY));
                }
            }
            tracing::error!("raw proxy failed: {}", e);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

fn is_allowed_path(path: &str, allowed_owners: &[String]) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 3 && parts[1] == "repos" {
        let owner = parts[2].to_lowercase();
        return allowed_owners.iter().any(|a| a.to_lowercase() == owner);
    }
    // Non-repo paths (e.g. /rate_limit) are allowed
    true
}

async fn graphql_proxy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, StatusCode> {
    let body_value: Value = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let query_str = body_value.get("query").and_then(|q| q.as_str()).unwrap_or("");
    let is_mutation = query_str.trim_start().starts_with("mutation");

    // For queries: check cache
    let cache_key = format!("graphql:{}", cache::build_graphql_key(&body));
    if !is_mutation {
        if let Some(cached) = state.cache.get(&cache_key).await {
            tracing::info!("200 OK /graphql [cache HIT]");
            return Ok(Json(cached));
        }
    }

    // Mutations: passthrough client's own auth. Queries: use pooled PAT.
    let (auth_header, identity_id) = if is_mutation {
        let client_auth = headers.get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                tracing::warn!("mutation rejected: no Authorization header from client");
                StatusCode::UNAUTHORIZED
            })?
            .to_string();
        let id = resolve_token_user(&state, &client_auth).await;
        (client_auth, id)
    } else {
        let identity = state.pool.select().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        (format!("Bearer {}", identity.token), identity.id.clone())
    };

    let resp = state.http.post("https://api.github.com/graphql")
        .header("Authorization", &auth_header)
        .header("User-Agent", concat!("ghpool/", env!("CARGO_PKG_VERSION")))
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| {
            tracing::error!("graphql request failed: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    if !is_mutation {
        let rate_remaining = resp.headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        let rate_reset = resp.headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        state.pool.update_rate(&identity_id, rate_remaining, rate_reset);
    }

    let status = resp.status();
    let resp_body: Value = resp.json().await.map_err(|e| {
        tracing::error!("failed to parse graphql response: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    if !status.is_success() {
        tracing::warn!("graphql returned {}", status);
        return Err(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY));
    }

    if !is_mutation {
        state.cache.insert(&cache_key, &resp_body, cache::RouteKind::Other).await;
    }

    tracing::info!("200 OK /graphql [via {}]{}", identity_id, if is_mutation { " (mutation)" } else { "" });
    Ok(Json(resp_body))
}

async fn resolve_token_user(state: &AppState, auth_header: &str) -> String {
    let key = auth_header.chars().rev().take(8).collect::<String>();
    if let Some(user) = state.token_users.get(&key).await {
        return user;
    }
    let user = match state.http.get("https://api.github.com/user")
        .header("Authorization", auth_header)
        .header("User-Agent", concat!("ghpool/", env!("CARGO_PKG_VERSION")))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            resp.json::<Value>().await.ok()
                .and_then(|v| v["login"].as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "unknown".to_string())
        }
        _ => "unknown".to_string(),
    };
    state.token_users.insert(key, user.clone()).await;
    user
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state(allowed_owners: Vec<&str>) -> Arc<AppState> {
        let identities = vec![config::IdentityConfig {
            id: "test".to_string(),
            token: "fake-token".to_string(),
        }];
        let pool = pool::PatPool::new(&identities);
        let cache_config = config::CacheConfig::default();
        let cache = cache::Cache::new(&cache_config);
        Arc::new(AppState {
            pool,
            cache,
            config: config::Config {
                port: 8080,
                identities,
                allowed_owners: allowed_owners.iter().map(|s| s.to_string()).collect(),
                cache: cache_config,
                mcp: config::McpConfig::default(),
            },
            token_users: moka::future::Cache::builder().max_capacity(10).build(),
            http: reqwest::Client::new(),
            mcp_sessions: moka::future::Cache::builder().max_capacity(10).build(),
            app_tokens: None,
            audit: None,
        })
    }

    fn app(state: Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route("/healthz", axum::routing::get(healthz))
            .route("/stats", axum::routing::get(stats))
            .route("/raw/{*path}", axum::routing::get(proxy_raw))
            .route("/{*path}", axum::routing::get(proxy))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_healthz() {
        let state = test_state(vec!["openabdev"]);
        let resp = app(state)
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_forbidden_owner() {
        let state = test_state(vec!["openabdev"]);
        let resp = app(state)
            .oneshot(Request::builder().uri("/repos/evil-org/repo/pulls/1").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_raw_forbidden_owner() {
        let state = test_state(vec!["openabdev"]);
        let resp = app(state)
            .oneshot(Request::builder().uri("/raw/repos/evil-org/repo/pulls/1").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_allowed_non_repo_path() {
        // Non-repo paths like /rate_limit are allowed (will fail at GitHub but not 403)
        let state = test_state(vec!["openabdev"]);
        let resp = app(state)
            .oneshot(Request::builder().uri("/rate_limit").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // Will be BAD_GATEWAY since fake token can't reach GitHub, but NOT FORBIDDEN
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_is_allowed_path() {
        let owners = vec!["openabdev".to_string(), "oablab".to_string()];
        assert!(is_allowed_path("/repos/openabdev/ghpool/pulls/1", &owners));
        assert!(is_allowed_path("/repos/oablab/chi/issues", &owners));
        assert!(!is_allowed_path("/repos/evil/repo/pulls/1", &owners));
        // Non-repo paths are allowed
        assert!(is_allowed_path("/rate_limit", &owners));
        assert!(is_allowed_path("/user", &owners));
    }
}
