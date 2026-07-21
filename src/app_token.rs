//! GitHub App installation token provider (Phase 2b, #17).
//!
//! Replaces the PAT pool as the MCP path's upstream credential:
//! - Short-lived: installation tokens expire after ~1h; we mint lazily and
//!   cache until shortly before expiry.
//! - Compliant: rate limits scale with the installation instead of
//!   aggregating personal accounts.
//! - Verified: the hosted MCP endpoint accepts installation tokens
//!   (#22 spike, finding A).
//!
//! Flow: RS256 JWT signed with the App private key (10-minute validity,
//! 60s clock-skew backdate) → POST /app/installations/{id}/access_tokens
//! → { token, expires_at }. The installation id is configured explicitly
//! or discovered once from the owner (org/user) at first use.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

/// Refresh this long before the reported expiry: long enough that a token
/// handed to an in-flight request stays valid for the request's lifetime.
const REFRESH_MARGIN: Duration = Duration::from_secs(300);

/// Owner verification is re-checked this often. GitHub accounts can rename
/// (and freed names can be re-claimed), so a verified owner→installation
/// binding must not live for the whole process lifetime.
const VERIFY_TTL: Duration = Duration::from_secs(3600);

/// Hard ceiling on any single GitHub App API call (JWT-authenticated mint,
/// installation resolution/verification). Without it a stalled connection
/// would hold a singleflight waiter queue indefinitely.
const MINT_TIMEOUT: Duration = Duration::from_secs(30);

/// A minted installation token plus its expiry (unix seconds).
#[derive(Clone, Debug)]
pub struct AppToken {
    pub token: String,
    pub expires_at: u64,
}

pub struct AppTokenProvider {
    app_id: String,
    encoding_key: jsonwebtoken::EncodingKey,
    /// Explicit installation id, or discovered from `owner` on first mint.
    installation_id: Mutex<Option<u64>>,
    owner: Option<String>,
    api_base: String,
    http: reqwest::Client,
    /// Cache keyed by purpose + scope envelope. MCP and git credentials are
    /// intentionally isolated: a repo-scoped MCP token may carry broader App
    /// permissions and must never satisfy a git credential request.
    cached: Mutex<HashMap<String, AppToken>>,
    /// Per-key singleflight locks: concurrent misses for the SAME cache key
    /// wait for one mint; distinct keys (different repos or purposes) mint
    /// in parallel so one slow mint cannot stall unrelated issuance.
    /// Entries are evicted when the mint completes, so the map is bounded
    /// by in-flight mints — request-supplied repo names (e.g. failed mints
    /// under a wildcard allowlist) cannot accumulate.
    mint_locks: Mutex<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    /// Owner verified from GitHub's installation API for an explicit ID,
    /// with the verification time — re-checked after VERIFY_TTL. The
    /// configured owner label is not trusted by itself.
    verified_owner: Mutex<Option<(String, u64)>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    expires_at: String, // RFC 3339
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
    account: Option<InstallationAccount>,
}

#[derive(Deserialize)]
struct InstallationAccount {
    login: String,
}

impl AppTokenProvider {
    /// `private_key_pem` is the App's PEM (RSA). `api_base` is normally
    /// https://api.github.com (overridable for tests).
    pub fn new(
        app_id: String,
        private_key_pem: &str,
        installation_id: Option<u64>,
        owner: Option<String>,
        api_base: String,
    ) -> Result<Self, String> {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| format!("invalid GitHub App private key: {}", e))?;
        if installation_id.is_none() && owner.is_none() {
            return Err("github_app requires installation_id or owner".to_string());
        }
        Ok(Self {
            app_id,
            encoding_key,
            installation_id: Mutex::new(installation_id),
            owner,
            api_base,
            http: reqwest::Client::builder()
                .timeout(MINT_TIMEOUT)
                .build()
                .map_err(|e| format!("http client build failed: {}", e))?,
            cached: Mutex::new(HashMap::new()),
            mint_locks: Mutex::new(HashMap::new()),
            verified_owner: Mutex::new(None),
        })
    }

    /// Installation-wide token, minting/refreshing if absent or near expiry.
    /// (Equivalent to `token_scoped(&[])`; kept for tests and future callers.)
    #[cfg(test)]
    pub async fn token(&self) -> Result<AppToken, String> {
        self.token_scoped(&[]).await
    }

    /// Token scoped to a repository envelope (2b-5, per community review):
    /// minted with the API's `repositories` parameter so GitHub itself
    /// enforces the boundary. Empty slice = installation-wide. Tokens are
    /// cached per envelope and refreshed near expiry.
    pub async fn token_scoped(&self, repositories: &[String]) -> Result<AppToken, String> {
        self.token_for("mcp", repositories, None).await
    }

    /// Git-over-HTTPS credential: a distinct cache namespace and a
    /// least-privilege permission envelope. `contents:write` is sufficient
    /// for fetch/push and prevents the returned token from bypassing MCP tool
    /// policy for issues, PRs, Actions, administration, etc.
    pub async fn token_git(&self, repository: &str) -> Result<AppToken, String> {
        self.token_for(
            "git:contents=write",
            &[repository.to_string()],
            Some(serde_json::json!({ "contents": "write" })),
        )
        .await
    }

    async fn token_for(
        &self,
        purpose: &str,
        repositories: &[String],
        permissions: Option<serde_json::Value>,
    ) -> Result<AppToken, String> {
        let mut envelope: Vec<String> = repositories.to_vec();
        envelope.sort();
        let key = format!("{}:{}", purpose, envelope.join(","));

        let now = unix_now();
        if let Some(t) = self.cached.lock().unwrap().get(&key) {
            if t.expires_at > now + REFRESH_MARGIN.as_secs() {
                return Ok(t.clone());
            }
        }
        // Key-scoped singleflight: concurrent misses for the SAME key wait
        // for one mint and then re-check the cache; distinct keys proceed in
        // parallel so a slow mint never stalls unrelated issuance.
        let key_lock = self
            .mint_locks
            .lock()
            .unwrap()
            .entry(key.clone())
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _mint_guard = key_lock.lock().await;
        if let Some(t) = self.cached.lock().unwrap().get(&key) {
            if t.expires_at > unix_now() + REFRESH_MARGIN.as_secs() {
                // fulfilled by the leader while we waited — evict our entry
                // too in case the leader's eviction raced our map insert
                self.mint_locks.lock().unwrap().remove(&key);
                return Ok(t.clone());
            }
        }
        let result = self.mint(&envelope, permissions.as_ref()).await;
        if let Ok(fresh) = &result {
            self.cached.lock().unwrap().insert(key.clone(), fresh.clone());
        }
        // Evict the singleflight entry whether the mint succeeded or failed:
        // waiters already holding this Arc still serialize behind it and
        // re-check the cache; the next fresh miss creates a new lock. This
        // bounds the map to in-flight mints instead of every key ever seen.
        self.mint_locks.lock().unwrap().remove(&key);
        result
    }

    async fn mint(
        &self,
        repositories: &[String],
        permissions: Option<&serde_json::Value>,
    ) -> Result<AppToken, String> {
        let jwt = self.sign_jwt()?;
        let installation_id = self.resolve_installation(&jwt).await?;

        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.api_base, installation_id
        );
        let mut body = serde_json::Map::new();
        if !repositories.is_empty() {
            // Scope the token to explicit repositories (names within the
            // VERIFIED installation owner). GitHub rejects unknown repos.
            body.insert("repositories".into(), serde_json::json!(repositories));
        }
        if let Some(p) = permissions {
            body.insert("permissions".into(), p.clone());
        }
        let mut req = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", jwt))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", concat!("ghpool/", env!("CARGO_PKG_VERSION")));
        if !body.is_empty() {
            req = req.json(&body);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("token mint request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "token mint failed: {} {}",
                status,
                body.chars().take(200).collect::<String>()
            ));
        }
        let tr: TokenResponse = resp
            .json()
            .await
            .map_err(|e| format!("token mint response parse failed: {}", e))?;
        let expires_at = parse_rfc3339_unix(&tr.expires_at)
            .ok_or_else(|| format!("unparsable expires_at: {}", tr.expires_at))?;

        tracing::info!(
            "minted GitHub App installation token (installation={}, scope={}, expires in {}s)",
            installation_id,
            if repositories.is_empty() { "installation-wide".to_string() } else { repositories.join(",") },
            expires_at.saturating_sub(unix_now())
        );
        Ok(AppToken { token: tr.token, expires_at })
    }

    /// Verify that this provider's installation belongs to `expected_owner`.
    /// This is mandatory before credential issuance: an explicit
    /// installation ID plus an operator-supplied owner label is not an
    /// identity binding. Without this API check, same-named repositories in
    /// different accounts could receive a token under a misbound route.
    pub async fn verify_owner(&self, expected_owner: &str) -> Result<(), String> {
        let expected = expected_owner.to_lowercase();
        if self
            .verified_owner
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|(o, at)| *o == expected && at + VERIFY_TTL.as_secs() > unix_now())
        {
            return Ok(());
        }
        let jwt = self.sign_jwt()?;
        let installation_id = self.resolve_installation(&jwt).await?;
        let url = format!("{}/app/installations/{}", self.api_base, installation_id);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", jwt))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", concat!("ghpool/", env!("CARGO_PKG_VERSION")))
            .send()
            .await
            .map_err(|e| format!("installation owner verification failed: {}", e))?;
        if !resp.status().is_success() {
            return Err(format!(
                "installation owner verification failed: GitHub returned {}",
                resp.status()
            ));
        }
        let installation: Installation = resp
            .json()
            .await
            .map_err(|e| format!("installation owner response parse failed: {}", e))?;
        let actual = installation
            .account
            .ok_or_else(|| "installation owner response missing account".to_string())?
            .login
            .to_lowercase();
        if actual != expected {
            return Err(format!(
                "installation {} belongs to owner '{}', not configured owner '{}'",
                installation_id, actual, expected_owner
            ));
        }
        *self.verified_owner.lock().unwrap() = Some((actual, unix_now()));
        Ok(())
    }

    async fn resolve_installation(&self, jwt: &str) -> Result<u64, String> {
        if let Some(id) = *self.installation_id.lock().unwrap() {
            return Ok(id);
        }
        let owner = self.owner.as_ref().expect("checked in new()");
        // Try org installation first, then user installation.
        for path in [
            format!("{}/orgs/{}/installation", self.api_base, owner),
            format!("{}/users/{}/installation", self.api_base, owner),
        ] {
            let resp = self
                .http
                .get(&path)
                .header("Authorization", format!("Bearer {}", jwt))
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", concat!("ghpool/", env!("CARGO_PKG_VERSION")))
                .send()
                .await
                .map_err(|e| format!("installation discovery failed: {}", e))?;
            if resp.status().is_success() {
                let inst: Installation = resp
                    .json()
                    .await
                    .map_err(|e| format!("installation response parse failed: {}", e))?;
                tracing::info!("discovered App installation {} for owner {}", inst.id, owner);
                *self.installation_id.lock().unwrap() = Some(inst.id);
                return Ok(inst.id);
            }
        }
        Err(format!("no App installation found for owner {}", owner))
    }

    fn sign_jwt(&self) -> Result<String, String> {
        let now = unix_now() as i64;
        let claims = serde_json::json!({
            "iat": now - 60,        // 60s backdate for clock skew
            "exp": now + 540,       // 9 min (GitHub max is 10)
            "iss": self.app_id,
        });
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &self.encoding_key,
        )
        .map_err(|e| format!("JWT signing failed: {}", e))
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RFC 3339 → unix seconds ("2026-07-13T04:05:06Z"). GitHub always returns
/// UTC with a Z suffix.
fn parse_rfc3339_unix(s: &str) -> Option<u64> {
    let parsed =
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    u64::try_from(parsed.unix_timestamp()).ok()
}

/// Multi-app mode: one `AppTokenProvider` per repository owner, enabling
/// owner-based routing of tool calls to distinct GitHub App installations.
///
/// Critical correctness property: upstream MCP sessions are credential-pinned,
/// so each owner's installation gets its own upstream session. The
/// `MultiAppTokenProvider` never swaps tokens within a single upstream session.
pub struct MultiAppTokenProvider {
    /// owner (normalized lowercase) → provider
    providers: HashMap<String, AppTokenProvider>,
}

impl MultiAppTokenProvider {
    /// Construct from config entries. Returns Err on invalid PEM or missing
    /// installation_id/owner.
    pub fn new(
        entries: &[crate::config::GithubAppsEntry],
        api_base: String,
    ) -> Result<Self, String> {
        let mut providers = HashMap::new();
        for entry in entries {
            let owner = entry.owner.trim().to_lowercase();
            let provider = AppTokenProvider::new(
                entry.app_id.clone(),
                &entry.private_key,
                entry.installation_id,
                Some(owner.clone()),
                api_base.clone(),
            )?;
            providers.insert(owner, provider);
        }
        Ok(Self { providers })
    }

    /// Get the provider for a given owner (case-insensitive lookup).
    /// Returns None when no App is configured for this owner.
    pub fn get(&self, owner: &str) -> Option<&AppTokenProvider> {
        self.providers.get(&owner.to_lowercase())
    }

    /// All configured owners (normalized lowercase).
    #[cfg(test)]
    pub fn owners(&self) -> impl Iterator<Item = &String> {
        self.providers.keys()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// 2048-bit RSA key generated for tests only — NOT a real secret.
    pub const TEST_RSA_PEM: &str = include_str!("../testdata/test-app-key.pem");

    #[test]
    fn test_parse_rfc3339() {
        assert_eq!(parse_rfc3339_unix("1970-01-01T00:01:00Z"), Some(60));
        assert!(parse_rfc3339_unix("2026-07-13T04:05:06Z").unwrap() > 1_700_000_000);
        assert_eq!(parse_rfc3339_unix("garbage"), None);
    }

    #[test]
    fn test_new_requires_installation_or_owner() {
        let err =
            AppTokenProvider::new("123".into(), TEST_RSA_PEM, None, None, "http://x".into())
                .err()
                .unwrap();
        assert!(err.contains("installation_id or owner"));
    }

    #[test]
    fn test_new_rejects_bad_pem() {
        let err = AppTokenProvider::new("123".into(), "not a pem", Some(1), None, "http://x".into())
            .err()
            .unwrap();
        assert!(err.contains("invalid GitHub App private key"));
    }

    #[test]
    fn test_multi_provider_owner_lookup_is_case_insensitive() {
        let entries = vec![crate::config::GithubAppsEntry {
            app_id: "1".into(),
            private_key: TEST_RSA_PEM.into(),
            installation_id: Some(1),
            owner: "OpenABdev".into(),
        }];
        let m = MultiAppTokenProvider::new(&entries, "http://x".into()).unwrap();
        assert!(m.get("openabdev").is_some());
        assert!(m.get("OPENABDEV").is_some());
        assert!(m.get("oablab").is_none());
        assert_eq!(m.owners().count(), 1);
    }

    #[test]
    fn test_sign_jwt_shape() {
        let p = AppTokenProvider::new("12345".into(), TEST_RSA_PEM, Some(1), None, "http://x".into())
            .unwrap();
        let jwt = p.sign_jwt().unwrap();
        // header.payload.signature, non-trivial signature length
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[2].len() > 100);
    }

    #[tokio::test]
    async fn test_token_caching_and_refresh_via_mock() {
        use axum::{routing::post, Router};
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        static MINTS: AtomicU32 = AtomicU32::new(0);
        let app = Router::new().route(
            "/app/installations/42/access_tokens",
            post(|| async {
                MINTS.fetch_add(1, Ordering::SeqCst);
                let exp = time::OffsetDateTime::from_unix_timestamp(
                    (super::unix_now() + 3600) as i64,
                )
                .unwrap()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
                axum::Json(serde_json::json!({
                    "token": format!("ghs_mock_{}", MINTS.load(Ordering::SeqCst)),
                    "expires_at": exp,
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let p = Arc::new(
            AppTokenProvider::new(
                "12345".into(),
                TEST_RSA_PEM,
                Some(42),
                None,
                format!("http://{}", addr),
            )
            .unwrap(),
        );

        let t1 = p.token().await.unwrap();
        assert_eq!(t1.token, "ghs_mock_1");
        assert!(t1.expires_at > unix_now() + 3000);

        // Cached: no second mint
        let t2 = p.token().await.unwrap();
        assert_eq!(t2.token, "ghs_mock_1");
        assert_eq!(MINTS.load(Ordering::SeqCst), 1);

        // Force near-expiry → refresh mints again
        p.cached.lock().unwrap().insert(
            "mcp:".to_string(),
            AppToken { token: "ghs_mock_1".into(), expires_at: unix_now() + 10 },
        );
        let t3 = p.token().await.unwrap();
        assert_eq!(t3.token, "ghs_mock_2");
        assert_eq!(MINTS.load(Ordering::SeqCst), 2);

        // Scoped envelopes are cached independently of installation-wide
        let s1 = p.token_scoped(&["ghpool".into()]).await.unwrap();
        assert_eq!(s1.token, "ghs_mock_3");
        // same envelope (different order) hits the cache
        let s2 = p.token_scoped(&["ghpool".into()]).await.unwrap();
        assert_eq!(s2.token, "ghs_mock_3");
        assert_eq!(MINTS.load(Ordering::SeqCst), 3);
        // different envelope mints separately
        let s3 = p.token_scoped(&["ghpool".into(), "openab".into()]).await.unwrap();
        assert_eq!(s3.token, "ghs_mock_4");
        assert_eq!(MINTS.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn test_git_token_downscopes_permissions_and_isolates_cache() {
        use axum::{extract::State, routing::post, Json, Router};
        use std::sync::Arc;

        type Bodies = Arc<Mutex<Vec<serde_json::Value>>>;
        async fn mint(
            State(bodies): State<Bodies>,
            Json(body): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            bodies.lock().unwrap().push(body);
            let n = bodies.lock().unwrap().len();
            let exp = time::OffsetDateTime::from_unix_timestamp((unix_now() + 3600) as i64)
                .unwrap()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
            Json(serde_json::json!({
                "token": format!("ghs_scope_{}", n),
                "expires_at": exp,
            }))
        }

        let bodies: Bodies = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/app/installations/42/access_tokens", post(mint))
            .with_state(bodies.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let p = AppTokenProvider::new(
            "123".into(),
            TEST_RSA_PEM,
            Some(42),
            None,
            format!("http://{}", addr),
        )
        .unwrap();

        // MCP token first: same repo, default App permissions.
        let mcp = p.token_scoped(&["openab".into()]).await.unwrap();
        // Git token MUST mint separately despite identical repo envelope.
        let git = p.token_git("openab").await.unwrap();
        assert_ne!(mcp.token, git.token);
        // Repeated git lookup hits its own cache.
        assert_eq!(p.token_git("openab").await.unwrap().token, git.token);

        let seen = bodies.lock().unwrap();
        assert_eq!(seen.len(), 2, "MCP and git cache namespaces must not overlap");
        assert_eq!(seen[0]["repositories"], serde_json::json!(["openab"]));
        assert!(seen[0].get("permissions").is_none());
        assert_eq!(seen[1]["repositories"], serde_json::json!(["openab"]));
        assert_eq!(
            seen[1]["permissions"],
            serde_json::json!({"contents": "write"})
        );
    }

    #[tokio::test]
    async fn test_verify_owner_binds_explicit_installation_id() {
        use axum::{routing::get, Router};
        use std::sync::atomic::{AtomicU32, Ordering};

        static HITS: AtomicU32 = AtomicU32::new(0);
        let app = Router::new().route(
            "/app/installations/42",
            get(|| async {
                HITS.fetch_add(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({
                    "id": 42,
                    "account": {"login": "openabdev"}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let p = AppTokenProvider::new(
            "123".into(),
            TEST_RSA_PEM,
            Some(42),
            Some("openabdev".into()),
            format!("http://{}", addr),
        )
        .unwrap();

        p.verify_owner("OpenABdev").await.unwrap();
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        // fresh verification is cached — no second API call
        p.verify_owner("openabdev").await.unwrap();
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        // a stale verification (past VERIFY_TTL) is re-checked with GitHub:
        // orgs can rename, so the binding must not live forever
        *p.verified_owner.lock().unwrap() =
            Some(("openabdev".into(), unix_now() - VERIFY_TTL.as_secs() - 1));
        p.verify_owner("openabdev").await.unwrap();
        assert_eq!(HITS.load(Ordering::SeqCst), 2);

        let err = p.verify_owner("oablab").await.unwrap_err();
        assert!(err.contains("belongs to owner 'openabdev'"));
        assert!(err.contains("not configured owner 'oablab'"));
    }

    #[tokio::test]
    async fn test_concurrent_misses_mint_once() {
        use axum::{routing::post, Router};
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        static MINTS2: AtomicU32 = AtomicU32::new(0);
        let app = Router::new().route(
            "/app/installations/7/access_tokens",
            post(|| async {
                MINTS2.fetch_add(1, Ordering::SeqCst);
                // slow mint so concurrent callers overlap the await
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let exp = time::OffsetDateTime::from_unix_timestamp((unix_now() + 3600) as i64)
                    .unwrap()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap();
                axum::Json(serde_json::json!({"token": "ghs_single", "expires_at": exp}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let p = Arc::new(
            AppTokenProvider::new(
                "123".into(),
                TEST_RSA_PEM,
                Some(7),
                None,
                format!("http://{}", addr),
            )
            .unwrap(),
        );
        let (a, b, c) = tokio::join!(
            p.token_git("openab"),
            p.token_git("openab"),
            p.token_git("openab"),
        );
        assert_eq!(a.unwrap().token, "ghs_single");
        assert_eq!(b.unwrap().token, "ghs_single");
        assert_eq!(c.unwrap().token, "ghs_single");
        assert_eq!(
            MINTS2.load(Ordering::SeqCst),
            1,
            "singleflight: concurrent misses must mint exactly once"
        );
    }

    #[tokio::test]
    async fn test_distinct_keys_mint_in_parallel() {
        use axum::{routing::post, Json, Router};
        use std::sync::Arc;
        use std::time::Instant;

        // The "slowrepo" mint stalls; "fastrepo" answers immediately. A
        // slow mint for one key must not delay issuance for another key.
        async fn mint(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
            let repos = body["repositories"].as_array().cloned().unwrap_or_default();
            if repos.iter().any(|r| r == "slowrepo") {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            let exp = time::OffsetDateTime::from_unix_timestamp((unix_now() + 3600) as i64)
                .unwrap()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
            Json(serde_json::json!({
                "token": format!("ghs_{}", repos[0].as_str().unwrap()),
                "expires_at": exp,
            }))
        }
        let app = Router::new().route("/app/installations/8/access_tokens", post(mint));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let p = Arc::new(
            AppTokenProvider::new(
                "123".into(),
                TEST_RSA_PEM,
                Some(8),
                None,
                format!("http://{}", addr),
            )
            .unwrap(),
        );
        let start = Instant::now();
        let slow = {
            let p = p.clone();
            tokio::spawn(async move { p.token_git("slowrepo").await })
        };
        // give the slow mint a head start so its lock is held
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let fast = p.token_git("fastrepo").await.unwrap();
        let fast_elapsed = start.elapsed();
        assert_eq!(fast.token, "ghs_fastrepo");
        assert!(
            fast_elapsed < std::time::Duration::from_millis(400),
            "distinct key must not wait behind a slow mint (took {:?})",
            fast_elapsed
        );
        let slow = slow.await.unwrap().unwrap();
        assert_eq!(slow.token, "ghs_slowrepo");
        assert!(start.elapsed() >= std::time::Duration::from_millis(500));
        // singleflight entries are evicted once mints complete — the map
        // must not grow with every key ever requested
        assert!(p.mint_locks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_mint_locks_evicted_after_success_and_failure() {
        use axum::{routing::post, Json, Router};

        // "badrepo*" fails to mint; "goodrepo" succeeds.
        async fn mint(Json(body): Json<serde_json::Value>) -> axum::response::Response {
            let repos = body["repositories"].as_array().cloned().unwrap_or_default();
            if repos.iter().any(|r| r.as_str().unwrap().starts_with("badrepo")) {
                return axum::response::Response::builder()
                    .status(422)
                    .body(axum::body::Body::from("{\"message\":\"not found\"}"))
                    .unwrap();
            }
            let exp = time::OffsetDateTime::from_unix_timestamp((unix_now() + 3600) as i64)
                .unwrap()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"token": "ghs_good", "expires_at": exp}).to_string(),
                ))
                .unwrap()
        }
        let app = Router::new().route("/app/installations/9/access_tokens", post(mint));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let p = AppTokenProvider::new(
            "123".into(),
            TEST_RSA_PEM,
            Some(9),
            None,
            format!("http://{}", addr),
        )
        .unwrap();

        p.token_git("goodrepo").await.unwrap();
        assert!(p.mint_locks.lock().unwrap().is_empty(), "evicted on success");

        // A wildcard-allowlisted agent can request arbitrary names; failed
        // mints must not leave lock entries behind (unbounded growth).
        for i in 0..5 {
            p.token_git(&format!("badrepo{}", i)).await.unwrap_err();
        }
        assert!(p.mint_locks.lock().unwrap().is_empty(), "evicted on failure");
    }
}
