//! Durable, fail-closed audit trail for write-classified MCP calls
//! (Phase 2b, #17).
//!
//! Two records per write call, appended as JSON Lines and fsync'd:
//! - `phase:"request"` — written BEFORE the call is forwarded. If this
//!   record cannot be persisted, the call is rejected (fail-closed).
//! - `phase:"result"` — written after the upstream response has been
//!   buffered and parsed. Captures BOTH the transport status and the
//!   MCP tool outcome: a failed GitHub operation arrives as
//!   `result.isError` inside an HTTP 200/SSE response, so HTTP status
//!   alone is not a success signal (community review, #17).
//!
//! Privacy: argument VALUES are never recorded — only the argument key
//! names plus the already-resolved repo target.
//!
//! Reads keep the existing best-effort tracing logs; this sink is only in
//! the path of write-classified calls.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct AuditSink {
    file: Mutex<File>,
    path: String,
}

/// Everything identifying one write call, shared by both record phases.
pub struct CallInfo<'a> {
    pub rpc_id: Option<&'a serde_json::Value>,
    pub session: Option<&'a str>,
    pub agent: Option<&'a str>,
    pub credential: &'a str,
    pub tool: &'a str,
    pub repo: Option<&'a (String, String)>,
}

/// Parsed outcome of a buffered upstream response.
#[derive(Debug, PartialEq)]
pub struct CallOutcome {
    pub http_status: u16,
    /// MCP tool outcome: Some(true)=tool reported an error, Some(false)=ok,
    /// None=undeterminable (unparseable/oversize body, or JSON-RPC error).
    pub tool_error: Option<bool>,
}

impl AuditSink {
    /// Opens (creates) the JSONL file in append mode. Fails loudly on an
    /// unusable path — operators must know audit is broken at startup, not
    /// at the first write call.
    pub fn open(path: &str) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("cannot open audit log {}: {}", path, e))?;
        Ok(Self { file: Mutex::new(file), path: path.to_string() })
    }

    /// A sink whose writes always fail (read-only fd) — for fail-closed tests.
    #[cfg(test)]
    pub fn failing_for_tests() -> Self {
        Self {
            file: Mutex::new(File::open("/dev/null").unwrap()),
            path: "/dev/null (read-only)".to_string(),
        }
    }

    /// Pre-flight record. An Err here MUST reject the call (fail-closed).
    pub fn record_request(&self, call: &CallInfo, arg_keys: &[String]) -> Result<(), String> {
        self.append(serde_json::json!({
            "ts": unix_now_ms(),
            "phase": "request",
            "rpc_id": call.rpc_id,
            "session": call.session,
            "agent": call.agent,
            "cred": call.credential,
            "tool": call.tool,
            "repo": call.repo.map(|(o, r)| format!("{}/{}", o, r)),
            "arg_keys": arg_keys,
            "decision": "allow",
        }))
    }

    /// Post-response record. The upstream call has already happened; a
    /// persistence failure here is logged loudly but cannot unwind the call.
    pub fn record_result(&self, call: &CallInfo, outcome: &CallOutcome) -> Result<(), String> {
        self.append(serde_json::json!({
            "ts": unix_now_ms(),
            "phase": "result",
            "rpc_id": call.rpc_id,
            "session": call.session,
            "agent": call.agent,
            "tool": call.tool,
            "http_status": outcome.http_status,
            "tool_error": outcome.tool_error,
        }))
    }

    /// Append one JSONL record and fsync. Small blocking write on the async
    /// path — acceptable: write calls are rare and records are <1 KB.
    fn append(&self, record: serde_json::Value) -> Result<(), String> {
        let mut line = record.to_string();
        line.push('\n');
        let mut f = self.file.lock().unwrap();
        f.write_all(line.as_bytes())
            .and_then(|_| f.sync_data())
            .map_err(|e| format!("audit append failed ({}): {}", self.path, e))
    }
}

/// Extract the MCP tool outcome from a buffered upstream response body
/// (plain JSON or SSE-framed). Returns None when undeterminable.
pub fn parse_tool_outcome(content_type: Option<&str>, body: &[u8]) -> Option<bool> {
    let json_payload: serde_json::Value = if content_type
        .map(|c| c.starts_with("text/event-stream"))
        .unwrap_or(false)
    {
        // Last `data:` frame carries the response for tools/call
        let text = std::str::from_utf8(body).ok()?;
        let last_data = text
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim_start)
            .next_back()?;
        serde_json::from_str(last_data).ok()?
    } else {
        serde_json::from_slice(body).ok()?
    };

    if json_payload.get("error").is_some() {
        // JSON-RPC level error (e.g. unknown tool) — the operation failed
        return Some(true);
    }
    json_payload
        .get("result")
        .map(|r| r.get("isError").and_then(|e| e.as_bool()).unwrap_or(false))
}

/// Argument key names only — values are never recorded.
pub fn redacted_arg_keys(arguments: Option<&serde_json::Value>) -> Vec<String> {
    arguments
        .and_then(|a| a.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

fn unix_now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("ghpool-audit-{}-{}.jsonl", name, std::process::id()))
            .to_str()
            .unwrap()
            .to_string()
    }

    fn call<'a>(tool: &'a str, repo: Option<&'a (String, String)>) -> CallInfo<'a> {
        CallInfo {
            rpc_id: None,
            session: Some("sess-1"),
            agent: Some("bot-a"),
            credential: "github-app",
            tool,
            repo,
        }
    }

    #[test]
    fn test_records_roundtrip() {
        let path = tmp_path("roundtrip");
        let sink = AuditSink::open(&path).unwrap();
        let repo = ("openabdev".to_string(), "ghpool".to_string());

        sink.record_request(&call("create_issue", Some(&repo)), &["owner".into(), "title".into()])
            .unwrap();
        sink.record_result(
            &call("create_issue", Some(&repo)),
            &CallOutcome { http_status: 200, tool_error: Some(false) },
        )
        .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["phase"], "request");
        assert_eq!(lines[0]["tool"], "create_issue");
        assert_eq!(lines[0]["repo"], "openabdev/ghpool");
        assert_eq!(lines[0]["arg_keys"], serde_json::json!(["owner", "title"]));
        assert_eq!(lines[0]["agent"], "bot-a");
        assert_eq!(lines[1]["phase"], "result");
        assert_eq!(lines[1]["http_status"], 200);
        assert_eq!(lines[1]["tool_error"], false);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_open_bad_path_fails_loudly() {
        let err = AuditSink::open("/nonexistent-dir/audit.jsonl").err().unwrap();
        assert!(err.contains("cannot open audit log"));
    }

    #[test]
    fn test_parse_tool_outcome_plain_json() {
        assert_eq!(
            parse_tool_outcome(Some("application/json"), br#"{"jsonrpc":"2.0","id":1,"result":{"isError":false,"content":[]}}"#),
            Some(false)
        );
        assert_eq!(
            parse_tool_outcome(Some("application/json"), br#"{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[]}}"#),
            Some(true)
        );
        // result without isError = success
        assert_eq!(
            parse_tool_outcome(Some("application/json"), br#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            Some(false)
        );
        // JSON-RPC error object = failure
        assert_eq!(
            parse_tool_outcome(Some("application/json"), br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}"#),
            Some(true)
        );
        // garbage = undeterminable
        assert_eq!(parse_tool_outcome(Some("application/json"), b"not json"), None);
    }

    #[test]
    fn test_parse_tool_outcome_sse() {
        let body = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"isError\":true}}\n\n";
        assert_eq!(parse_tool_outcome(Some("text/event-stream"), body), Some(true));

        // multiple frames: last data frame wins
        let body = b"data: {\"x\":1}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"isError\":false}}\n\n";
        assert_eq!(parse_tool_outcome(Some("text/event-stream"), body), Some(false));
    }

    #[test]
    fn test_redacted_arg_keys() {
        let args = serde_json::json!({"owner":"o","repo":"r","title":"secret text","body":"secret"});
        let mut keys = redacted_arg_keys(Some(&args));
        keys.sort();
        assert_eq!(keys, vec!["body", "owner", "repo", "title"]);
        assert!(redacted_arg_keys(None).is_empty());
    }
}
