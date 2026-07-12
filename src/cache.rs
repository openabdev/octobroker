use moka::future::Cache as MokaCache;
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashMap, sync::atomic::{AtomicU64, Ordering}, time::Duration};

use crate::config::CacheConfig;

#[derive(Clone, Copy)]
pub enum RouteKind {
    PrView,
    PrList,
    IssueView,
    IssueList,
    RunList,
    RunView,
    CommitList,
    RepoView,
    Other,
}

pub struct Cache {
    store: MokaCache<String, Value>,
    raw_store: MokaCache<String, String>,
    ttls: CacheTtls,
    hits: AtomicU64,
    misses: AtomicU64,
}

struct CacheTtls {
    pr_view: Duration,
    issue_list: Duration,
    run_list: Duration,
    commit_list: Duration,
    repo_view: Duration,
    default: Duration,
}

impl Cache {
    pub fn new(config: &CacheConfig) -> Self {
        let store = MokaCache::builder()
            .max_capacity(config.max_entries)
            .time_to_live(Duration::from_secs(config.default_ttl_secs))
            .build();
        // Raw (diff/patch) cache: bounded primarily by total bytes via a
        // weigher, since diff bodies can be multi-MB (unlike JSON metadata
        // responses). moka's max_capacity here tracks weighted bytes, not
        // entry count.
        let raw_store = MokaCache::builder()
            .max_capacity(config.raw_max_bytes)
            .weigher(move |key: &String, value: &String| -> u32 {
                (key.len() + value.len()).min(u32::MAX as usize) as u32
            })
            .time_to_live(Duration::from_secs(config.raw_ttl_secs))
            .build();
        tracing::debug!(
            raw_max_bytes = config.raw_max_bytes,
            raw_ttl_secs = config.raw_ttl_secs,
            "raw cache configured"
        );
        Self {
            store,
            raw_store,
            ttls: CacheTtls {
                pr_view: Duration::from_secs(config.pr_view_ttl_secs),
                issue_list: Duration::from_secs(config.issue_list_ttl_secs),
                run_list: Duration::from_secs(config.run_list_ttl_secs),
                commit_list: Duration::from_secs(config.commit_list_ttl_secs),
                repo_view: Duration::from_secs(config.repo_view_ttl_secs),
                default: Duration::from_secs(config.default_ttl_secs),
            },
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub async fn get(&self, key: &str) -> Option<Value> {
        match self.store.get(key).await {
            Some(v) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(v)
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    pub async fn insert(&self, key: &str, value: &Value, kind: RouteKind) {
        let ttl = match kind {
            RouteKind::PrView | RouteKind::PrList => self.ttls.pr_view,
            RouteKind::IssueView | RouteKind::IssueList => self.ttls.issue_list,
            RouteKind::RunList | RouteKind::RunView => self.ttls.run_list,
            RouteKind::CommitList => self.ttls.commit_list,
            RouteKind::RepoView => self.ttls.repo_view,
            RouteKind::Other => self.ttls.default,
        };
        self.store.insert(key.to_string(), value.clone()).await;
        // Moka uses global TTL; for per-entry TTL we expire via policy
        // For simplicity, use the global TTL from config. Per-entry TTL
        // would require moka's `policy` feature or a wrapper.
        let _ = ttl; // TTL differentiation noted for future enhancement
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            entries: self.store.entry_count() + self.raw_store.entry_count(),
        }
    }

    /// Fetch-or-compute with stampede protection: concurrent callers with the
    /// same key share a single in-flight future via moka's `entry` API,
    /// so N simultaneous cache misses only trigger one upstream request.
    /// Uses `is_fresh()` to correctly distinguish hits from misses.
    pub async fn get_or_insert_raw<F, E>(
        &self,
        key: &str,
        init: F,
    ) -> Result<String, E>
    where
        F: std::future::Future<Output = Result<String, E>>,
        E: Clone + std::fmt::Debug + Send + Sync + 'static,
    {
        match self.raw_store.entry_by_ref(key).or_try_insert_with(init).await {
            Ok(entry) => {
                if entry.is_fresh() {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                }
                Ok(entry.into_value())
            }
            Err(e) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                Err((*e).clone())
            }
        }
    }
}

#[derive(Serialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
}

pub fn build_key(path: &str, query: &HashMap<String, String>) -> String {
    let mut parts: Vec<(&str, &str)> = query.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    parts.sort();
    let qs: String = parts.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&");
    if qs.is_empty() { path.to_string() } else { format!("{}?{}", path, qs) }
}

/// Build a cache key for raw (non-JSON) responses.
///
/// Includes:
/// - `path` + sorted `query` params (consistent with `build_key`, fixes a gap
///   where paginated raw requests would previously collide on the same key)
/// - normalized `accept` header (lowercased, so `Application/Vnd.Github.V3.Diff`
///   and `application/vnd.github.v3.diff` share one cache entry)
/// - `identity_scope`: a caller-supplied token identifying which PAT/identity's
///   access scope produced the response. This prevents cross-identity leakage
///   when the pool holds PATs with different repo access — a response fetched
///   with a broadly-scoped PAT must never be served to a caller whose own PAT
///   would have been denied access.
pub fn build_raw_key(path: &str, query: &HashMap<String, String>, accept: &str, identity_scope: &str) -> String {
    let mut parts: Vec<(&str, &str)> = query.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    parts.sort();
    let qs: String = parts.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&");
    let normalized_accept = accept.trim().to_ascii_lowercase();
    if qs.is_empty() {
        format!("raw:{}:{}:{}", path, normalized_accept, identity_scope)
    } else {
        format!("raw:{}?{}:{}:{}", path, qs, normalized_accept, identity_scope)
    }
}

pub fn build_graphql_key(body: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

pub fn classify_route(path: &str) -> RouteKind {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 4 { return RouteKind::Other; }
    match parts.get(3).copied() {
        Some("pulls") => if parts.len() == 5 { RouteKind::PrView } else { RouteKind::PrList },
        Some("issues") => if parts.len() == 5 { RouteKind::IssueView } else { RouteKind::IssueList },
        Some("commits") => RouteKind::CommitList,
        Some("actions") => match parts.get(4).copied() {
            Some("runs") => if parts.len() == 6 { RouteKind::RunView } else { RouteKind::RunList },
            _ => RouteKind::Other,
        },
        _ if parts.len() == 4 => RouteKind::RepoView,
        _ => RouteKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_query() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn test_build_raw_key_no_query() {
        let key = build_raw_key("/repos/o/r/pulls/1", &empty_query(), "application/vnd.github.v3.diff", "id1");
        assert_eq!(key, "raw:/repos/o/r/pulls/1:application/vnd.github.v3.diff:id1");
    }

    #[test]
    fn test_build_raw_key_normalizes_accept_case() {
        let a = build_raw_key("/repos/o/r/pulls/1", &empty_query(), "Application/Vnd.Github.V3.Diff", "id1");
        let b = build_raw_key("/repos/o/r/pulls/1", &empty_query(), "application/vnd.github.v3.diff", "id1");
        assert_eq!(a, b);
    }

    #[test]
    fn test_build_raw_key_includes_query_params() {
        let mut q = HashMap::new();
        q.insert("page".to_string(), "2".to_string());
        let key = build_raw_key("/repos/o/r/pulls/1", &q, "application/vnd.github.v3.diff", "id1");
        assert_eq!(key, "raw:/repos/o/r/pulls/1?page=2:application/vnd.github.v3.diff:id1");
    }

    #[test]
    fn test_build_raw_key_differs_by_query() {
        let mut q1 = HashMap::new();
        q1.insert("page".to_string(), "1".to_string());
        let mut q2 = HashMap::new();
        q2.insert("page".to_string(), "2".to_string());
        let k1 = build_raw_key("/repos/o/r/pulls/1", &q1, "application/vnd.github.v3.diff", "id1");
        let k2 = build_raw_key("/repos/o/r/pulls/1", &q2, "application/vnd.github.v3.diff", "id1");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_build_raw_key_differs_by_identity_scope() {
        let k1 = build_raw_key("/repos/o/r/pulls/1", &empty_query(), "application/vnd.github.v3.diff", "id1");
        let k2 = build_raw_key("/repos/o/r/pulls/1", &empty_query(), "application/vnd.github.v3.diff", "id2");
        assert_ne!(k1, k2, "responses from different identity scopes must not share a cache entry");
    }

    #[test]
    fn test_build_raw_key_differs_by_accept() {
        let k1 = build_raw_key("/repos/o/r/pulls/1", &empty_query(), "application/vnd.github.v3.diff", "id1");
        let k2 = build_raw_key("/repos/o/r/pulls/1", &empty_query(), "application/json", "id1");
        assert_ne!(k1, k2);
    }

    #[tokio::test]
    async fn test_cache_raw_get_insert_roundtrip() {
        let cfg = CacheConfig::default();
        let cache = Cache::new(&cfg);
        let key = build_raw_key("/repos/o/r/pulls/1", &empty_query(), "application/vnd.github.v3.diff", "id1");
        let call_count = std::sync::Arc::new(AtomicU64::new(0));
        let cc1 = call_count.clone();
        let v1 = cache
            .get_or_insert_raw(&key, async move {
                cc1.fetch_add(1, Ordering::SeqCst);
                Ok::<String, String>("diff content".to_string())
            })
            .await
            .unwrap();
        assert_eq!(v1, "diff content");
        // First call should be a miss (fresh insert).
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().hits, 0);
        // Second call should hit cache, not invoke init again.
        let cc2 = call_count.clone();
        let v2 = cache
            .get_or_insert_raw(&key, async move {
                cc2.fetch_add(1, Ordering::SeqCst);
                Ok::<String, String>("should not be used".to_string())
            })
            .await
            .unwrap();
        assert_eq!(v2, "diff content");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(cache.stats().hits, 1);
        assert_eq!(cache.stats().misses, 1);
    }

    #[tokio::test]
    async fn test_cache_raw_stampede_dedup() {
        // Concurrent callers requesting the same uncached key should only
        // trigger the init closure once (moka's entry API coalesces).
        let cfg = CacheConfig::default();
        let cache = std::sync::Arc::new(Cache::new(&cfg));
        let call_count = std::sync::Arc::new(AtomicU64::new(0));
        let key = build_raw_key("/repos/o/r/pulls/1", &empty_query(), "application/vnd.github.v3.diff", "id1");

        let mut handles = Vec::new();
        for _ in 0..10 {
            let cache = cache.clone();
            let call_count = call_count.clone();
            let key = key.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_insert_raw(&key, async move {
                        call_count.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok::<String, String>("diff".to_string())
                    })
                    .await
            }));
        }
        for h in handles {
            h.await.unwrap().unwrap();
        }
        // With entry API, all concurrent calls coalesce: only 1 init runs.
        // The one that evaluated is_fresh()=true counts as a miss.
        // The rest see is_fresh()=false and count as hits.
        let stats = cache.stats();
        assert_eq!(stats.misses, 1, "only one call should be a miss (the one that ran init)");
        assert_eq!(stats.hits, 9, "the rest should be hits (served from cache after init completed)");
    }
}
