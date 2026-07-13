//! MCP tool policy: read/write classification and repository-level
//! authorization (Phase 2b, #17).
//!
//! Classification is rule-based and deliberately conservative: a tool is a
//! READ only if its name matches the read-only surface's naming conventions
//! (verified against the hosted server's /readonly toolset); everything
//! else — including tools we have never seen — is treated as a WRITE.
//! Misclassifying a read as a write is an inconvenience (fix the rule);
//! misclassifying a write as a read would be a security bug.

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ToolKind {
    Read,
    Write,
}

/// Classify a tool by name.
///
/// The hosted /readonly surface (observed in #22) consists entirely of
/// `get_*`, `list_*`, `search_*` and `*_read` names. Write-capable tools use
/// action prefixes (`create_*`, `update_*`, `delete_*`, `add_*`, `merge_*`,
/// `push_*`, …) or `*_write` names — none of which match the read rules.
pub fn classify_tool(name: &str) -> ToolKind {
    if name.starts_with("get_")
        || name.starts_with("list_")
        || name.starts_with("search_")
        || name.ends_with("_read")
    {
        ToolKind::Read
    } else {
        ToolKind::Write
    }
}

/// Extract the target repository from tools/call arguments.
/// GitHub's MCP tools consistently use `owner` + `repo` argument names.
/// Returns None when the call has no resolvable repository target (e.g.
/// `get_me`, cross-repo search) — for repo-restricted agents such calls are
/// DENIED (deny-if-unresolvable, RFC Revision 2).
pub fn resolve_repo(arguments: Option<&serde_json::Value>) -> Option<(String, String)> {
    let args = arguments?;
    let owner = args.get("owner")?.as_str()?.trim();
    let repo = args.get("repo")?.as_str()?.trim();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

/// Check a resolved repo against an agent's allowlist.
/// Supported entry forms (case-insensitive, GitHub semantics):
/// - `owner/repo` — exact
/// - `owner/*`    — any repo under that owner
///
/// An EMPTY allowlist means "no repository restriction" — repos is an
/// additional constraint on top of the tool allowlist, and requiring it
/// would break existing agent configs.
pub fn repo_allowed(allowlist: &[String], owner: &str, repo: &str) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    let owner = owner.to_lowercase();
    let repo = repo.to_lowercase();
    allowlist.iter().any(|entry| {
        let entry = entry.to_lowercase();
        match entry.split_once('/') {
            Some((o, "*")) => o == owner,
            Some((o, r)) => o == owner && r == repo,
            None => false, // malformed entry never matches (fail closed)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_read_tools() {
        // The observed /readonly surface shapes
        for name in [
            "issue_read",
            "pull_request_read",
            "get_file_contents",
            "get_me",
            "get_commit",
            "list_issues",
            "list_branches",
            "search_code",
        ] {
            assert_eq!(classify_tool(name), ToolKind::Read, "{}", name);
        }
    }

    #[test]
    fn test_classify_write_tools() {
        for name in [
            "create_issue",
            "add_issue_comment",
            "update_issue",
            "merge_pull_request",
            "push_files",
            "delete_file",
            "fork_repository",
            "issue_write",
            "create_or_update_file",
        ] {
            assert_eq!(classify_tool(name), ToolKind::Write, "{}", name);
        }
    }

    #[test]
    fn test_classify_unknown_is_write() {
        // Conservative default: never-seen names are writes
        assert_eq!(classify_tool("frobnicate_widget"), ToolKind::Write);
        assert_eq!(classify_tool(""), ToolKind::Write);
    }

    #[test]
    fn test_resolve_repo() {
        let args = serde_json::json!({"owner": "openabdev", "repo": "ghpool", "issue_number": 15});
        assert_eq!(
            resolve_repo(Some(&args)),
            Some(("openabdev".to_string(), "ghpool".to_string()))
        );

        // unresolvable shapes
        assert_eq!(resolve_repo(None), None);
        assert_eq!(resolve_repo(Some(&serde_json::json!({}))), None);
        assert_eq!(resolve_repo(Some(&serde_json::json!({"owner": "x"}))), None);
        assert_eq!(resolve_repo(Some(&serde_json::json!({"owner": "", "repo": "y"}))), None);
        assert_eq!(resolve_repo(Some(&serde_json::json!({"owner": 1, "repo": 2}))), None);
        // query-only tools have no repo target
        assert_eq!(resolve_repo(Some(&serde_json::json!({"query": "foo"}))), None);
    }

    #[test]
    fn test_repo_allowed_exact_and_wildcard() {
        let allow = vec!["openabdev/ghpool".to_string(), "oablab/*".to_string()];
        assert!(repo_allowed(&allow, "openabdev", "ghpool"));
        assert!(repo_allowed(&allow, "OpenABdev", "GHPool")); // case-insensitive
        assert!(repo_allowed(&allow, "oablab", "chi"));
        assert!(repo_allowed(&allow, "oablab", "anything"));
        assert!(!repo_allowed(&allow, "openabdev", "openab"));
        assert!(!repo_allowed(&allow, "evil", "ghpool"));
    }

    #[test]
    fn test_repo_allowed_empty_is_unrestricted() {
        assert!(repo_allowed(&[], "anyone", "anything"));
    }

    #[test]
    fn test_repo_allowed_malformed_entry_fails_closed() {
        let allow = vec!["justanowner".to_string()];
        assert!(!repo_allowed(&allow, "justanowner", "repo"));
    }
}
