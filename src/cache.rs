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
        let raw_store = MokaCache::builder()
            .max_capacity(config.max_entries / 2)
            .time_to_live(Duration::from_secs(30))
            .build();
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

    pub async fn get_raw(&self, key: &str) -> Option<String> {
        match self.raw_store.get(key).await {
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

    pub async fn insert_raw(&self, key: &str, value: &str) {
        self.raw_store.insert(key.to_string(), value.to_string()).await;
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

pub fn build_raw_key(path: &str, accept: &str) -> String {
    format!("raw:{}:{}", path, accept)
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
