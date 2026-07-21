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
    /// Cache keyed by scope envelope ("" = installation-wide; otherwise the
    /// sorted repo list). One credential per policy envelope.
    cached: Mutex<HashMap<String, AppToken>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    expires_at: String, // RFC 3339
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
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
            http: reqwest::Client::new(),
            cached: Mutex::new(HashMap::new()),
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
        let mut envelope: Vec<String> = repositories.to_vec();
        envelope.sort();
        let key = envelope.join(",");

        let now = unix_now();
        if let Some(t) = self.cached.lock().unwrap().get(&key) {
            if t.expires_at > now + REFRESH_MARGIN.as_secs() {
                return Ok(t.clone());
            }
        }
        let fresh = self.mint(&envelope).await?;
        self.cached.lock().unwrap().insert(key, fresh.clone());
        Ok(fresh)
    }

    async fn mint(&self, repositories: &[String]) -> Result<AppToken, String> {
        let jwt = self.sign_jwt()?;
        let installation_id = self.resolve_installation(&jwt).await?;

        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.api_base, installation_id
        );
        let mut req = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", jwt))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", concat!("ghpool/", env!("CARGO_PKG_VERSION")));
        if !repositories.is_empty() {
            // Scope the token to explicit repositories (names within the
            // installation's owner). GitHub rejects unknown repos at mint.
            req = req.json(&serde_json::json!({ "repositories": repositories }));
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
            String::new(),
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
}
