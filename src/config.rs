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
/// When enabled, octobroker proxies MCP Streamable HTTP traffic on /mcp to the
/// GitHub-hosted MCP server, injecting a pooled credential upstream so agents
/// never hold a GitHub token.
#[derive(Clone, Deserialize)]
pub struct McpConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Enable write tools for authenticated agents (Phase 2b-5).
    /// Hard requirements, validated at startup: [[mcp.agents]] non-empty,
    /// [mcp.github_app] configured (writes never run on pooled PATs), and
    /// [mcp.audit] configured (writes are fail-closed audited).
    #[serde(default)]
    pub enable_writes: bool,
    /// Enable the /git-credential endpoint: repository-scoped agents can
    /// exchange their X-Octobroker-Key for a short-lived, single-repo GitHub App
    /// installation token usable as a git-over-HTTPS credential
    /// (username `x-access-token`). Hard requirements mirror enable_writes:
    /// [[mcp.agents]], an App backend, and [mcp.audit] (every issuance is
    /// fail-closed audited). The App needs Contents: read/write for pushes.
    #[serde(default)]
    pub enable_git_credentials: bool,
    /// Mint read-only (`contents: read`) git credentials instead of the
    /// default `contents: write`. When true, the token issued by
    /// /git-credential can `git clone`/fetch a private repo but CANNOT push —
    /// letting a read-only agent be granted clone access without also granting
    /// commit/push. With this set the App only needs Contents: read on the
    /// target repositories. Default false (push-capable, unchanged behavior).
    #[serde(default)]
    pub git_credentials_read_only: bool,
    /// Upstream MCP endpoint. Defaults to GitHub's hosted read-only variant,
    /// or the full write-capable surface when enable_writes is set.
    #[serde(default)]
    pub upstream: Option<String>,
    /// Optional toolset restriction, injected as X-MCP-Toolsets header.
    /// Only used when no [[mcp.agents]] are configured (Phase 1 mode).
    #[serde(default)]
    pub toolsets: Vec<String>,
    /// Idle TTL for session → identity pinning.
    #[serde(default = "default_mcp_session_ttl")]
    pub session_ttl_secs: u64,
    /// Max concurrent write calls per agent (in-flight cap). 0 = unlimited.
    #[serde(default = "default_mcp_max_inflight_writes")]
    pub max_inflight_writes: usize,
    /// Per-agent authentication + default-deny tool allowlists (Phase 2a).
    /// Empty = Phase 1 network-trust mode (no agent authn on /mcp).
    /// Non-empty = every /mcp request must present a valid X-Octobroker-Key.
    #[serde(default)]
    pub agents: Vec<McpAgentConfig>,
    /// GitHub App credential backend (Phase 2b). When configured, the MCP
    /// path injects short-lived installation tokens instead of pooled PATs.
    #[serde(default)]
    pub github_app: Option<GithubAppConfig>,
    /// Multi-app mode: one App installation per repository owner. When
    /// configured, tool calls are routed to the matching installation based
    /// on the resolved owner from tool arguments. Mutually exclusive with
    /// `github_app` (validated at startup).
    #[serde(default)]
    pub github_apps: Vec<GithubAppsEntry>,
    /// Durable audit trail for write-classified tools/call (Phase 2b).
    /// Required before writes can be enabled (2b-5): a write call whose
    /// pre-flight audit record cannot be persisted is rejected (fail-closed).
    #[serde(default)]
    pub audit: Option<AuditConfig>,
}

/// Durable audit configuration.
#[derive(Clone, Deserialize)]
pub struct AuditConfig {
    /// JSONL file path (append + fsync per record).
    pub path: String,
    /// Max upstream response bytes buffered to extract the tool outcome for
    /// write calls; larger responses are forwarded but recorded with
    /// tool_error = null (undeterminable).
    #[serde(default = "default_audit_max_result_bytes")]
    pub max_result_bytes: usize,
}

fn default_audit_max_result_bytes() -> usize {
    4 * 1024 * 1024
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

/// Multi-app mode: one GitHub App installation per repository owner.
/// Each entry maps a normalized owner to its own App credential, enabling
/// a single authenticated MCP agent to operate across organizations via
/// owner-based routing. The owner is resolved from tool call arguments
/// (never agent-controlled installation selection).
#[derive(Clone, Deserialize)]
pub struct GithubAppsEntry {
    pub app_id: String,
    pub private_key: String,
    #[serde(default)]
    pub installation_id: Option<u64>,
    /// Required in multi-app mode: the owner this entry handles.
    pub owner: String,
}

/// One authenticated MCP agent: key(s) → identity → tool allowlist.
#[derive(Clone, Deserialize)]
pub struct McpAgentConfig {
    pub id: String,
    /// Shared key presented via X-Octobroker-Key (single-key form). Supports the
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
    /// Per-agent override of `[mcp] git_credentials_read_only`.
    /// `true` = this agent's /git-credential tokens are minted `contents:
    /// read` (clone/fetch, no push) regardless of the global default;
    /// `false` = explicitly push-capable (`contents: write`), even when the
    /// global default is read-only — the mixed-fleet case: a read-only fleet
    /// default with one push-capable agent. Omitted (`None`) inherits the
    /// global flag. Both values are operator-set config, never
    /// agent-controlled.
    #[serde(default)]
    pub git_credentials_read_only: Option<bool>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enable_writes: false,
            enable_git_credentials: false,
            git_credentials_read_only: false,
            upstream: None,
            toolsets: Vec::new(),
            session_ttl_secs: default_mcp_session_ttl(),
            max_inflight_writes: default_mcp_max_inflight_writes(),
            agents: Vec::new(),
            github_app: None,
            github_apps: Vec::new(),
            audit: None,
        }
    }
}

impl McpConfig {
    /// Effective upstream: explicit config wins; otherwise the read-only
    /// variant, or the full write-capable surface when writes are enabled.
    pub fn upstream(&self) -> String {
        if let Some(u) = &self.upstream {
            return u.clone();
        }
        if self.enable_writes {
            "https://api.githubcopilot.com/mcp/".to_string()
        } else {
            default_mcp_upstream()
        }
    }

    /// Startup validation of the write gate's hard requirements.
    pub fn validate(&self) -> Result<(), String> {
        if self.enable_writes {
            if self.agents.is_empty() {
                return Err("enable_writes requires [[mcp.agents]] — writes are never available in network-trust mode".into());
            }
            if self.github_app.is_none() && self.github_apps.is_empty() {
                return Err("enable_writes requires [mcp.github_app] or [[mcp.github_apps]] — writes never run on pooled PATs".into());
            }
            if self.audit.is_none() {
                return Err("enable_writes requires [mcp.audit] — writes are fail-closed audited".into());
            }
            // Multi-installation mode: repo-less agents ride pooled PATs, and
            // writes never run on pooled PATs — an agent allowlisting a
            // write-classified tool must be repository-scoped.
            if !self.github_apps.is_empty() {
                for agent in &self.agents {
                    if agent.repos.is_empty()
                        && agent
                            .tools
                            .iter()
                            .any(|t| crate::policy::classify_tool(t) == crate::policy::ToolKind::Write)
                    {
                        return Err(format!(
                            "mcp agent '{}' allowlists write tools but has no `repos` — repo-less agents use pooled PATs and writes never run on pooled PATs",
                            agent.id
                        ));
                    }
                }
            }
        }
        // Git credential issuance shares the write gate's hard requirements:
        // authenticated agents, App-backed tokens (never PATs), and a
        // fail-closed audit trail for every issuance.
        if self.enable_git_credentials {
            if self.agents.is_empty() {
                return Err("enable_git_credentials requires [[mcp.agents]] — credentials are only issued to authenticated agents".into());
            }
            if self.github_app.is_none() && self.github_apps.is_empty() {
                return Err("enable_git_credentials requires [mcp.github_app] or [[mcp.github_apps]] — git credentials are App installation tokens, never PATs".into());
            }
            if self.audit.is_none() {
                return Err("enable_git_credentials requires [mcp.audit] — issuance is fail-closed audited".into());
            }
            if self
                .github_app
                .as_ref()
                .is_some_and(|app| app.owner.as_deref().is_none_or(|o| o.trim().is_empty()))
            {
                return Err("enable_git_credentials with [mcp.github_app] requires `owner` — explicit installation IDs are verified against this owner before issuance".into());
            }
        }
        // Mutual exclusion: singular and plural forms cannot coexist
        if self.github_app.is_some() && !self.github_apps.is_empty() {
            return Err("[mcp.github_app] and [[mcp.github_apps]] are mutually exclusive — use one or the other".into());
        }
        // Multi-app validation
        if !self.github_apps.is_empty() {
            let mut seen_owners: std::collections::HashSet<String> = std::collections::HashSet::new();
            for entry in &self.github_apps {
                let normalized = entry.owner.trim().to_lowercase();
                if normalized.is_empty() {
                    return Err("[[mcp.github_apps]] entry has empty owner".into());
                }
                if !seen_owners.insert(normalized.clone()) {
                    return Err(format!(
                        "[[mcp.github_apps]] duplicate owner '{}' — each owner must map to exactly one App",
                        entry.owner
                    ));
                }
            }
            // Multi-installation routing derives each session's credential
            // envelope from the agent's repo allowlist. Agents WITH repos
            // must be fully covered by installations; agents WITHOUT repos
            // keep the legacy PAT-backed read path (writes are denied for
            // them at the proxy — writes never run on pooled PATs).
            if self.agents.is_empty() {
                return Err("[[mcp.github_apps]] requires [[mcp.agents]] — multi-installation routing is not available in network-trust mode".into());
            }
            for agent in &self.agents {
                for repo_entry in &agent.repos {
                    // Strict form: `owner/name` or `owner/*` — no empty or
                    // whitespace-padded parts, no extra path segments.
                    // Sloppy entries would silently widen token scope
                    // (installation-wide mint) or fail only at runtime.
                    let owner = match repo_entry.split_once('/') {
                        Some((owner, name))
                            if !owner.is_empty()
                                && owner == owner.trim()
                                && (name == "*"
                                    || (!name.is_empty()
                                        && name == name.trim()
                                        && !name.contains('/'))) =>
                        {
                            owner
                        }
                        _ => {
                            return Err(format!(
                                "mcp agent '{}' repo entry '{}' is malformed — expected owner/repo or owner/*",
                                agent.id, repo_entry
                            ));
                        }
                    };
                    let normalized = owner.to_lowercase();
                    if !seen_owners.contains(&normalized) {
                        return Err(format!(
                            "mcp agent '{}' authorizes repo owner '{}' but no [[mcp.github_apps]] entry covers it — agents cannot authorize a repo owner without a matching installation",
                            agent.id, owner
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

fn default_mcp_upstream() -> String {
    "https://api.githubcopilot.com/mcp/readonly".to_string()
}
fn default_mcp_session_ttl() -> u64 { 3600 }
fn default_mcp_max_inflight_writes() -> usize { 4 }

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
                    // Most likely a typo'd OCTOBROKER_CONFIG — don't fail silently
                    tracing::warn!("cannot read config at {}: {} — falling back to env-only mode", path, e);
                }
            }
        }
        tracing::info!("no config file found — using environment variables only");

        // Fallback: env vars only
        let identities = Self::identities_from_env();
        let allowed_owners = std::env::var("OCTOBROKER_ALLOWED_OWNERS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let port = std::env::var("OCTOBROKER_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_port());

        let mut config = Config { port, identities, allowed_owners, cache: CacheConfig::default(), mcp: McpConfig::default() };
        config.apply_env_overrides();
        config
    }

    /// Config file search order:
    /// 1. OCTOBROKER_CONFIG env var (explicit always wins; if set but unreadable,
    ///    a warning is logged and no other file is tried)
    /// 2. ./config.toml (repo-local dev)
    /// 3. $XDG_CONFIG_HOME/octobroker/config.toml (default ~/.config/octobroker/)
    ///
    /// Returns None when nothing is found → env-only mode.
    fn resolve_config_path() -> Option<String> {
        if let Ok(p) = std::env::var("OCTOBROKER_CONFIG") {
            return Some(p);
        }
        if std::path::Path::new("config.toml").exists() {
            return Some("config.toml".to_string());
        }
        let xdg_base = std::env::var("XDG_CONFIG_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOME").ok().map(|h| format!("{}/.config", h)))?;
        let xdg_path = format!("{}/octobroker/config.toml", xdg_base);
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
        for entry in &mut mcp.github_apps {
            let pem = resolve_secret(&entry.private_key).await;
            entry.private_key = pem.replace("\\n", "\n");
            entry.owner = entry.owner.trim().to_lowercase();
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
        if let Ok(v) = std::env::var("OCTOBROKER_PORT") {
            if let Ok(p) = v.parse() { self.port = p; }
        }
        if let Ok(v) = std::env::var("OCTOBROKER_ALLOWED_OWNERS") {
            self.allowed_owners = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }
        if let Ok(v) = std::env::var("OCTOBROKER_MCP_ENABLED") {
            self.mcp.enabled = matches!(v.to_lowercase().as_str(), "1" | "true" | "yes");
        }
    }

    fn identities_from_env() -> Vec<IdentityConfig> {
        std::env::vars()
            .filter(|(k, _)| k.starts_with("OCTOBROKER_PAT_"))
            .map(|(k, v)| IdentityConfig {
                id: k.strip_prefix("OCTOBROKER_PAT_").unwrap().to_lowercase(),
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
        let tmp = std::env::temp_dir().join(format!("octobroker-cfg-test-{}", std::process::id()));
        let octobroker_dir = tmp.join("octobroker");
        let cwd_dir = tmp.join("cwd");
        fs::create_dir_all(&octobroker_dir).unwrap();
        fs::create_dir_all(&cwd_dir).unwrap();

        // Run from an empty cwd so a developer's local ./config.toml doesn't
        // affect the outcome.
        let orig_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&cwd_dir).unwrap();
        std::env::remove_var("OCTOBROKER_CONFIG");
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
        let xdg_file = octobroker_dir.join("config.toml");
        fs::write(&xdg_file, "port = 1234\n").unwrap();
        assert_eq!(
            Config::resolve_config_path().as_deref(),
            Some(xdg_file.to_str().unwrap()),
            "XDG path found"
        );

        // Explicit OCTOBROKER_CONFIG wins over XDG, even if the path doesn't exist
        std::env::set_var("OCTOBROKER_CONFIG", "/nonexistent/override.toml");
        assert_eq!(
            Config::resolve_config_path().as_deref(),
            Some("/nonexistent/override.toml"),
            "explicit env var always wins"
        );

        std::env::remove_var("OCTOBROKER_CONFIG");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::set_current_dir(orig_cwd).unwrap();
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_agent_git_credentials_read_only_toml_roundtrip() {
        // Tri-state per-agent override: omitted → None (inherit global),
        // explicit true/false → pinned. Guards the #[serde(default)] and
        // the Option<bool> type against accidental refactors.
        let m: McpConfig = toml::from_str(
            r#"
            enabled = true

            [[agents]]
            id = "inherits"
            keys = ["k1"]

            [[agents]]
            id = "pinned-ro"
            keys = ["k2"]
            git_credentials_read_only = true

            [[agents]]
            id = "pinned-rw"
            keys = ["k3"]
            git_credentials_read_only = false
            "#,
        )
        .unwrap();
        assert_eq!(m.agents[0].git_credentials_read_only, None);
        assert_eq!(m.agents[1].git_credentials_read_only, Some(true));
        assert_eq!(m.agents[2].git_credentials_read_only, Some(false));
    }

    #[test]
    fn test_mcp_validate_write_gate() {
        let mut m = McpConfig { enabled: true, enable_writes: true, ..Default::default() };
        assert!(m.validate().unwrap_err().contains("[[mcp.agents]]"));
        m.agents.push(McpAgentConfig {
            id: "a".into(), key: None, keys: vec!["k".into()], tools: vec![], repos: vec![],
            git_credentials_read_only: None,
        });
        assert!(m.validate().unwrap_err().contains("github_app"));
        m.github_app = Some(GithubAppConfig {
            app_id: "1".into(), private_key: "pem".into(), installation_id: Some(1), owner: None,
        });
        assert!(m.validate().unwrap_err().contains("audit"));
        m.audit = Some(AuditConfig { path: "/tmp/a.jsonl".into(), max_result_bytes: 1024 });
        assert!(m.validate().is_ok());
        // reads-only config never requires anything
        let m = McpConfig { enabled: true, ..Default::default() };
        assert!(m.validate().is_ok());
    }

    #[test]
    fn test_mcp_upstream_default_flips_with_writes() {
        let m = McpConfig::default();
        assert!(m.upstream().ends_with("/readonly"));
        let m = McpConfig { enable_writes: true, ..Default::default() };
        assert_eq!(m.upstream(), "https://api.githubcopilot.com/mcp/");
        let m = McpConfig { upstream: Some("http://x/".into()), enable_writes: true, ..Default::default() };
        assert_eq!(m.upstream(), "http://x/");
    }

    #[test]
    fn test_mcp_validate_multi_app() {
        fn entry(owner: &str) -> GithubAppsEntry {
            GithubAppsEntry {
                app_id: "1".into(),
                private_key: "pem".into(),
                installation_id: Some(1),
                owner: owner.into(),
            }
        }
        fn multi_agent(repos: &[&str]) -> McpAgentConfig {
            McpAgentConfig {
                id: "b0".into(),
                key: None,
                keys: vec!["k".into()],
                tools: vec![],
                repos: repos.iter().map(|s| s.to_string()).collect(),
                git_credentials_read_only: None,
            }
        }

        // mutually exclusive with the singular form
        let m = McpConfig {
            github_app: Some(GithubAppConfig {
                app_id: "1".into(), private_key: "pem".into(),
                installation_id: Some(1), owner: None,
            }),
            github_apps: vec![entry("openabdev")],
            agents: vec![multi_agent(&["openabdev/x"])],
            ..Default::default()
        };
        assert!(m.validate().unwrap_err().contains("mutually exclusive"));

        // duplicate owners (case-insensitive) rejected
        let m = McpConfig {
            github_apps: vec![entry("openabdev"), entry("OpenABdev")],
            agents: vec![multi_agent(&["openabdev/x"])],
            ..Default::default()
        };
        assert!(m.validate().unwrap_err().contains("duplicate owner"));

        // empty owner rejected
        let m = McpConfig {
            github_apps: vec![entry("  ")],
            agents: vec![multi_agent(&["openabdev/x"])],
            ..Default::default()
        };
        assert!(m.validate().unwrap_err().contains("empty owner"));

        // agents required in multi mode (routing needs an envelope)
        let m = McpConfig { github_apps: vec![entry("openabdev")], ..Default::default() };
        assert!(m.validate().unwrap_err().contains("[[mcp.agents]]"));

        // repo-less agents are allowed (legacy PAT read path)…
        let m = McpConfig {
            github_apps: vec![entry("openabdev")],
            agents: vec![multi_agent(&[])],
            ..Default::default()
        };
        assert!(m.validate().is_ok());

        // …but a repo-less agent allowlisting a WRITE tool with writes
        // enabled is a startup error (writes never run on pooled PATs)
        let mut wa = multi_agent(&[]);
        wa.tools = vec!["issue_read".into(), "create_issue".into()];
        let m = McpConfig {
            enable_writes: true,
            enable_git_credentials: false,
            github_apps: vec![entry("openabdev")],
            agents: vec![wa],
            audit: Some(AuditConfig { path: "/tmp/a.jsonl".into(), max_result_bytes: 1024 }),
            ..Default::default()
        };
        assert!(m.validate().unwrap_err().contains("pooled PATs"));

        // every repo owner must have a matching installation
        let m = McpConfig {
            github_apps: vec![entry("openabdev")],
            agents: vec![multi_agent(&["openabdev/x", "oablab/chi"])],
            ..Default::default()
        };
        assert!(m.validate().unwrap_err().contains("no [[mcp.github_apps]] entry"));

        // malformed repo entry rejected
        let m = McpConfig {
            github_apps: vec![entry("openabdev")],
            agents: vec![multi_agent(&["justanowner"])],
            ..Default::default()
        };
        assert!(m.validate().unwrap_err().contains("malformed"));

        // sloppy entries that would widen scope or fail at runtime: rejected
        for bad in ["openabdev/", "openabdev/repo/extra", "openabdev / repo", "openabdev/ repo", "/repo"] {
            let m = McpConfig {
                github_apps: vec![entry("openabdev")],
                agents: vec![multi_agent(&[bad])],
                ..Default::default()
            };
            assert!(
                m.validate().unwrap_err().contains("malformed"),
                "entry '{}' must be rejected",
                bad
            );
        }

        // wildcard form accepted
        let m = McpConfig {
            github_apps: vec![entry("openabdev")],
            agents: vec![multi_agent(&["openabdev/*"])],
            ..Default::default()
        };
        assert!(m.validate().is_ok());

        // valid multi config satisfies the write gate too
        let m = McpConfig {
            enabled: true,
            enable_writes: true,
            enable_git_credentials: false,
            github_apps: vec![entry("openabdev"), entry("oablab")],
            agents: vec![multi_agent(&["openabdev/openab", "oablab/chi"])],
            audit: Some(AuditConfig { path: "/tmp/a.jsonl".into(), max_result_bytes: 1024 }),
            ..Default::default()
        };
        assert!(m.validate().is_ok());
    }

    #[test]
    fn test_mcp_validate_git_credentials_gate() {
        fn agent() -> McpAgentConfig {
            McpAgentConfig {
                id: "b0".into(),
                key: None,
                keys: vec!["k".into()],
                tools: vec![],
                repos: vec!["openabdev/openab".into()],
                git_credentials_read_only: None,
            }
        }
        fn audit() -> Option<AuditConfig> {
            Some(AuditConfig { path: "/tmp/a.jsonl".into(), max_result_bytes: 1024 })
        }
        fn single(owner: Option<&str>) -> Option<GithubAppConfig> {
            Some(GithubAppConfig {
                app_id: "1".into(),
                private_key: "pem".into(),
                installation_id: Some(1),
                owner: owner.map(|s| s.to_string()),
            })
        }

        // agents required
        let m = McpConfig { enable_git_credentials: true, ..Default::default() };
        assert!(m.validate().unwrap_err().contains("[[mcp.agents]]"));

        // App backend required — never PATs
        let m = McpConfig {
            enable_git_credentials: true,
            agents: vec![agent()],
            ..Default::default()
        };
        assert!(m.validate().unwrap_err().contains("never PATs"));

        // audit required
        let m = McpConfig {
            enable_git_credentials: true,
            agents: vec![agent()],
            github_app: single(Some("openabdev")),
            ..Default::default()
        };
        assert!(m.validate().unwrap_err().contains("[mcp.audit]"));

        // singular App without owner: the explicit installation ID cannot be
        // verified against an account, so startup must fail
        for owner in [None, Some(""), Some("  ")] {
            let m = McpConfig {
                enable_git_credentials: true,
                agents: vec![agent()],
                github_app: single(owner),
                audit: audit(),
                ..Default::default()
            };
            assert!(
                m.validate().unwrap_err().contains("requires `owner`"),
                "owner {:?} must be rejected",
                owner
            );
        }

        // singular App with owner set: valid
        let m = McpConfig {
            enable_git_credentials: true,
            agents: vec![agent()],
            github_app: single(Some("openabdev")),
            audit: audit(),
            ..Default::default()
        };
        assert!(m.validate().is_ok());

        // multi-App form (owners inherent to entries): valid
        let m = McpConfig {
            enable_git_credentials: true,
            agents: vec![agent()],
            github_apps: vec![GithubAppsEntry {
                app_id: "1".into(),
                private_key: "pem".into(),
                installation_id: Some(1),
                owner: "openabdev".into(),
            }],
            audit: audit(),
            ..Default::default()
        };
        assert!(m.validate().is_ok());
    }
}
