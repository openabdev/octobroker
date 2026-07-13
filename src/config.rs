use serde::Deserialize;
use std::fs;

#[derive(Clone)]
pub struct Config {
    pub port: u16,
    pub identities: Vec<IdentityConfig>,
    pub allowed_owners: Vec<String>,
    pub cache: CacheConfig,
    pub mcp: McpConfig,
}

#[derive(Clone)]
pub struct IdentityConfig {
    pub id: String,
    pub token: String,
}

#[derive(Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_max_entries")]
    pub max_entries: u64,
    #[serde(default = "default_pr_ttl")]
    pub pr_view_ttl_secs: u64,
    #[serde(default = "default_pr_ttl")]
    pub issue_list_ttl_secs: u64,
    #[serde(default = "default_run_ttl")]
    pub run_list_ttl_secs: u64,
    #[serde(default = "default_commit_ttl")]
    pub commit_list_ttl_secs: u64,
    #[serde(default = "default_repo_ttl")]
    pub repo_view_ttl_secs: u64,
    #[serde(default = "default_ttl")]
    pub default_ttl_secs: u64,
    /// TTL for raw (non-JSON, e.g. diff/patch) responses.
    #[serde(default = "default_raw_ttl")]
    pub raw_ttl_secs: u64,
    /// Max total bytes held by the raw response cache (weigher-enforced).
    #[serde(default = "default_raw_max_bytes")]
    pub raw_max_bytes: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: default_max_entries(),
            pr_view_ttl_secs: default_pr_ttl(),
            issue_list_ttl_secs: default_pr_ttl(),
            run_list_ttl_secs: default_run_ttl(),
            commit_list_ttl_secs: default_commit_ttl(),
            repo_view_ttl_secs: default_repo_ttl(),
            default_ttl_secs: default_ttl(),
            raw_ttl_secs: default_raw_ttl(),
            raw_max_bytes: default_raw_max_bytes(),
        }
    }
}

/// MCP reverse proxy configuration (Phase 1: read-only).
/// When enabled, ghpool proxies MCP Streamable HTTP traffic on /mcp to the
/// GitHub-hosted MCP server, injecting a pooled credential upstream so agents
/// never hold a GitHub token.
#[derive(Clone, Deserialize)]
pub struct McpConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Upstream MCP endpoint. Defaults to GitHub's hosted read-only variant.
    #[serde(default = "default_mcp_upstream")]
    pub upstream: String,
    /// Optional toolset restriction, injected as X-MCP-Toolsets header.
    /// Only used when no [[mcp.agents]] are configured (Phase 1 mode).
    #[serde(default)]
    pub toolsets: Vec<String>,
    /// Idle TTL for session → identity pinning.
    #[serde(default = "default_mcp_session_ttl")]
    pub session_ttl_secs: u64,
    /// Per-agent authentication + default-deny tool allowlists (Phase 2a).
    /// Empty = Phase 1 network-trust mode (no agent authn on /mcp).
    /// Non-empty = every /mcp request must present a valid X-Ghpool-Key.
    #[serde(default)]
    pub agents: Vec<McpAgentConfig>,
    /// GitHub App credential backend (Phase 2b). When configured, the MCP
    /// path injects short-lived installation tokens instead of pooled PATs.
    #[serde(default)]
    pub github_app: Option<GithubAppConfig>,
}

/// GitHub App credentials for the MCP path.
#[derive(Clone, Deserialize)]
pub struct GithubAppConfig {
    pub app_id: String,
    /// App private key PEM. Supports the same secret references as tokens
    /// (env:/aws:secretsmanager:/k8s:), resolved at config load. For env/
    /// file sources the PEM may use literal "\n" escapes.
    pub private_key: String,
    /// Explicit installation id. Either this or `owner` is required.
    #[serde(default)]
    pub installation_id: Option<u64>,
    /// Org or user whose installation to discover (used when
    /// installation_id is not set).
    #[serde(default)]
    pub owner: Option<String>,
}

/// One authenticated MCP agent: key(s) → identity → tool allowlist.
#[derive(Clone, Deserialize)]
pub struct McpAgentConfig {
    pub id: String,
    /// Shared key presented via X-Ghpool-Key (single-key form). Supports the
    /// same secret reference formats as identity tokens; resolved at load.
    #[serde(default)]
    pub key: Option<String>,
    /// Multiple simultaneously valid keys, for zero-downtime rotation:
    /// add the new key, roll agents over, remove the old key. Merged with
    /// `key` at config load (both forms may be combined).
    #[serde(default)]
    pub keys: Vec<String>,
    /// Default-deny tool allowlist (exact upstream tool names, e.g.
    /// "issue_read"). tools/call for anything not listed is rejected at the
    /// proxy; the same list is injected upstream as X-MCP-Tools.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Repository allowlist: `owner/repo` (exact) or `owner/*` entries.
    /// When non-empty, every tools/call must resolve to an allowlisted repo
    /// from its arguments; calls with no resolvable repo target are DENIED
    /// (deny-if-unresolvable). Empty = no repository restriction.
    #[serde(default)]
    pub repos: Vec<String>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstream: default_mcp_upstream(),
            toolsets: Vec::new(),
            session_ttl_secs: default_mcp_session_ttl(),
            agents: Vec::new(),
            github_app: None,
        }
    }
}

fn default_mcp_upstream() -> String {
    "https://api.githubcopilot.com/mcp/readonly".to_string()
}
fn default_mcp_session_ttl() -> u64 { 3600 }

fn default_port() -> u16 { 8080 }
fn default_max_entries() -> u64 { 10000 }
fn default_pr_ttl() -> u64 { 30 }
fn default_run_ttl() -> u64 { 15 }
fn default_raw_ttl() -> u64 { 30 }
fn default_raw_max_bytes() -> u64 { 256 * 1024 * 1024 } // 256 MiB
fn default_commit_ttl() -> u64 { 120 }
fn default_repo_ttl() -> u64 { 300 }
fn default_ttl() -> u64 { 60 }

// Raw TOML structures (before secret resolution)
#[derive(Deserialize)]
struct RawConfig {
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    identities: Vec<RawIdentity>,
    #[serde(default)]
    allowed_owners: Vec<String>,
    #[serde(default)]
    cache: CacheConfig,
    #[serde(default)]
    mcp: McpConfig,
}

#[derive(Deserialize)]
struct RawIdentity {
    id: String,
    token: String, // may be a secret reference
}

impl Config {
    pub async fn load() -> Self {
        if let Some(path) = Self::resolve_config_path() {
            match fs::read_to_string(&path) {
                Ok(content) => {
                    tracing::info!("loading config from {}", path);
                    let raw: RawConfig = toml::from_str(&content)
                        .expect("failed to parse config file");
                    let mut config = Self::from_raw(raw).await;
                    config.apply_env_overrides();
                    return config;
                }
                Err(e) => {
                    // Most likely a typo'd GHPOOL_CONFIG — don't fail silently
                    tracing::warn!("cannot read config at {}: {} — falling back to env-only mode", path, e);
                }
            }
        }
        tracing::info!("no config file found — using environment variables only");

        // Fallback: env vars only
        let identities = Self::identities_from_env();
        let allowed_owners = std::env::var("GHPOOL_ALLOWED_OWNERS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let port = std::env::var("GHPOOL_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_port());

        let mut config = Config { port, identities, allowed_owners, cache: CacheConfig::default(), mcp: McpConfig::default() };
        config.apply_env_overrides();
        config
    }

    /// Config file search order:
    /// 1. GHPOOL_CONFIG env var (explicit always wins; if set but unreadable,
    ///    a warning is logged and no other file is tried)
    /// 2. ./config.toml (repo-local dev)
    /// 3. $XDG_CONFIG_HOME/ghpool/config.toml (default ~/.config/ghpool/)
    ///
    /// Returns None when nothing is found → env-only mode.
    fn resolve_config_path() -> Option<String> {
        if let Ok(p) = std::env::var("GHPOOL_CONFIG") {
            return Some(p);
        }
        if std::path::Path::new("config.toml").exists() {
            return Some("config.toml".to_string());
        }
        let xdg_base = std::env::var("XDG_CONFIG_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOME").ok().map(|h| format!("{}/.config", h)))?;
        let xdg_path = format!("{}/ghpool/config.toml", xdg_base);
        if std::path::Path::new(&xdg_path).exists() {
            return Some(xdg_path);
        }
        None
    }

    async fn from_raw(raw: RawConfig) -> Self {
        let mut identities = Vec::with_capacity(raw.identities.len());
        for ri in raw.identities {
            let token = resolve_secret(&ri.token).await;
            identities.push(IdentityConfig { id: ri.id, token });
        }
        let mut mcp = raw.mcp;
        for agent in &mut mcp.agents {
            // Normalize: resolve secret refs and collapse `key` into `keys`.
            let mut resolved = Vec::new();
            if let Some(k) = agent.key.take() {
                resolved.push(resolve_secret(&k).await);
            }
            for k in &agent.keys {
                resolved.push(resolve_secret(k).await);
            }
            if resolved.is_empty() {
                panic!("mcp agent '{}' has no key/keys configured", agent.id);
            }
            agent.keys = resolved;
        }
        if let Some(app) = &mut mcp.github_app {
            let pem = resolve_secret(&app.private_key).await;
            // Env vars / JSON secrets often carry the PEM with literal \n
            app.private_key = pem.replace("\\n", "\n");
        }
        Config {
            port: raw.port,
            identities,
            allowed_owners: raw.allowed_owners,
            cache: raw.cache,
            mcp,
        }
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("GHPOOL_PORT") {
            if let Ok(p) = v.parse() { self.port = p; }
        }
        if let Ok(v) = std::env::var("GHPOOL_ALLOWED_OWNERS") {
            self.allowed_owners = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }
        if let Ok(v) = std::env::var("GHPOOL_MCP_ENABLED") {
            self.mcp.enabled = matches!(v.to_lowercase().as_str(), "1" | "true" | "yes");
        }
    }

    fn identities_from_env() -> Vec<IdentityConfig> {
        std::env::vars()
            .filter(|(k, _)| k.starts_with("GHPOOL_PAT_"))
            .map(|(k, v)| IdentityConfig {
                id: k.strip_prefix("GHPOOL_PAT_").unwrap().to_lowercase(),
                token: v,
            })
            .collect()
    }
}

/// Resolve a secret reference string.
/// Formats:
///   aws:secretsmanager:<secret-name>:<json-key>
///   k8s:<namespace>/<secret-name>:<key>
///   env:<VAR_NAME>
///   (anything else) — used as literal value
async fn resolve_secret(value: &str) -> String {
    if let Some(rest) = value.strip_prefix("env:") {
        return std::env::var(rest)
            .unwrap_or_else(|_| panic!("env var {} not set", rest));
    }
    if let Some(rest) = value.strip_prefix("aws:secretsmanager:") {
        return resolve_aws_secret(rest).await;
    }
    if let Some(rest) = value.strip_prefix("k8s:") {
        return resolve_k8s_secret(rest);
    }
    value.to_string()
}

async fn resolve_aws_secret(spec: &str) -> String {
    // spec = "secret-name:json-key"
    let (secret_name, json_key) = spec.split_once(':')
        .expect("aws secret ref must be aws:secretsmanager:<name>:<key>");
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);
    let resp = client.get_secret_value()
        .secret_id(secret_name)
        .send()
        .await
        .expect("failed to fetch secret from AWS Secrets Manager");
    let secret_string = resp.secret_string()
        .expect("secret has no string value");
    let parsed: serde_json::Value = serde_json::from_str(secret_string)
        .expect("secret value is not valid JSON");
    parsed[json_key].as_str()
        .unwrap_or_else(|| panic!("key '{}' not found in secret '{}'", json_key, secret_name))
        .to_string()
}

fn resolve_k8s_secret(spec: &str) -> String {
    // spec = "namespace/secret-name:key"
    // Reads from /var/run/secrets/kubernetes.io/serviceaccount/.. mounted path
    // or the standard projected volume path: /etc/secrets/<secret-name>/<key>
    let (path_part, key) = spec.split_once(':')
        .expect("k8s secret ref must be k8s:<namespace>/<secret-name>:<key>");
    let (_, secret_name) = path_part.split_once('/')
        .expect("k8s secret ref must include namespace/secret-name");
    let file_path = format!("/etc/secrets/{}/{}", secret_name, key);
    fs::read_to_string(&file_path)
        .unwrap_or_else(|_| panic!("cannot read k8s secret at {}", file_path))
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_config_path_chain() {
        // Single test covering the whole chain to avoid parallel-test races
        // on process-global state (env vars + cwd; no other test touches
        // either).
        let tmp = std::env::temp_dir().join(format!("ghpool-cfg-test-{}", std::process::id()));
        let ghpool_dir = tmp.join("ghpool");
        let cwd_dir = tmp.join("cwd");
        fs::create_dir_all(&ghpool_dir).unwrap();
        fs::create_dir_all(&cwd_dir).unwrap();

        // Run from an empty cwd so a developer's local ./config.toml doesn't
        // affect the outcome.
        let orig_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&cwd_dir).unwrap();
        std::env::remove_var("GHPOOL_CONFIG");
        std::env::set_var("XDG_CONFIG_HOME", &tmp);

        assert_eq!(Config::resolve_config_path(), None, "no file anywhere → env-only");

        // ./config.toml in cwd is found
        fs::write(cwd_dir.join("config.toml"), "port = 1\n").unwrap();
        assert_eq!(
            Config::resolve_config_path().as_deref(),
            Some("config.toml"),
            "cwd file found"
        );
        fs::remove_file(cwd_dir.join("config.toml")).unwrap();

        // XDG file exists → picked up
        let xdg_file = ghpool_dir.join("config.toml");
        fs::write(&xdg_file, "port = 1234\n").unwrap();
        assert_eq!(
            Config::resolve_config_path().as_deref(),
            Some(xdg_file.to_str().unwrap()),
            "XDG path found"
        );

        // Explicit GHPOOL_CONFIG wins over XDG, even if the path doesn't exist
        std::env::set_var("GHPOOL_CONFIG", "/nonexistent/override.toml");
        assert_eq!(
            Config::resolve_config_path().as_deref(),
            Some("/nonexistent/override.toml"),
            "explicit env var always wins"
        );

        std::env::remove_var("GHPOOL_CONFIG");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::set_current_dir(orig_cwd).unwrap();
        fs::remove_dir_all(&tmp).ok();
    }
}
