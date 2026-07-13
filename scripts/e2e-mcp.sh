#!/usr/bin/env bash
# E2E test: ghpool MCP reverse proxy against GitHub's hosted MCP server.
#
# Requires:
#   GITHUB_TOKEN  — a user token (PAT or `gh auth token`); the Actions built-in
#                   installation token is NOT accepted by the hosted MCP server.
#   GHPOOL_BIN    — path to the ghpool binary (default: ./target/debug/ghpool)
#   jq, python3
#
# Usage: GITHUB_TOKEN=$(gh auth token) ./scripts/e2e-mcp.sh
#
# NOTE: no `set -e` — assertions are accumulated via check() and the script
# exits non-zero at the end if any failed. Hard setup errors abort explicitly.
set -uo pipefail

BIN="${GHPOOL_BIN:-./target/debug/ghpool}"
WORKDIR="$(mktemp -d)"
LOG="${WORKDIR}/ghpool.log"
# --max-time must exceed ghpool's upstream POST timeout (120s) so a slow but
# healthy upstream call is not cut off client-side.
CURL=(curl -s --connect-timeout 5 --max-time 130)

pass=0
fail=0
# check <description> <command...> — runs the command, records pass/fail
check() {
  local desc="$1"; shift
  if "$@"; then
    echo "  ✓ ${desc}"; pass=$((pass + 1))
  else
    echo "  ✗ ${desc}"; fail=$((fail + 1))
  fi
}

cleanup() {
  [ -n "${GHPOOL_PID:-}" ] && kill "${GHPOOL_PID}" 2>/dev/null
  # Preserve the server logs for CI artifact upload on failure
  [ "${fail:-1}" -gt 0 ] && [ -f "${LOG}" ] && cp "${LOG}" ./ghpool-e2e.log 2>/dev/null
  [ "${fail:-1}" -gt 0 ] && [ -f "${WORKDIR}/ghpool-app.log" ] && cp "${WORKDIR}/ghpool-app.log" ./ghpool-e2e-app.log 2>/dev/null
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "GITHUB_TOKEN not set — skipping e2e (this is expected on forks)"
  exit 0
fi

# Pick a free port to avoid CI collisions
PORT="${PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')}"
# Bind and connect over IPv4 explicitly: ghpool binds 0.0.0.0, but "localhost"
# can resolve to ::1 on dual-stack hosts and fail to connect.
BASE="http://127.0.0.1:${PORT}"

cat > "${WORKDIR}/config.toml" <<EOF
port = ${PORT}
allowed_owners = ["openabdev"]
[[identities]]
id = "e2e"
token = "env:GITHUB_TOKEN"
[mcp]
enabled = true
EOF

echo "starting ghpool (${BIN}) on :${PORT}"
GHPOOL_CONFIG="${WORKDIR}/config.toml" "${BIN}" > "${LOG}" 2>&1 &
GHPOOL_PID=$!

for _ in $(seq 1 20); do
  "${CURL[@]}" -f "${BASE}/healthz" > /dev/null 2>&1 && break
  sleep 0.5
done
"${CURL[@]}" -f "${BASE}/healthz" > /dev/null || { echo "ghpool failed to start"; cat "${LOG}"; exit 1; }

JSON_H=(-H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")

# Extract the JSON payload from a response body. Handles both SSE framing
# (one or more `data:` lines; the space after the colon is optional per spec)
# and a plain application/json body.
sse_json() {
  if grep -q "^data:" "$1"; then
    grep "^data:" "$1" | sed 's/^data: \{0,1\}//' | tail -1
  else
    cat "$1"
  fi
}

# jq_ok <filter> <file> — true if the filter matches; jq's own stdout is
# suppressed internally so it does not swallow check()'s result line.
jq_ok() { jq -e "$1" "$2" > /dev/null 2>&1; }

echo "1. initialize (no client Authorization header)"
"${CURL[@]}" -D "${WORKDIR}/init-headers.txt" -o "${WORKDIR}/init-body.txt" \
  -X POST "${BASE}/mcp" "${JSON_H[@]}" \
  -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ghpool-e2e","version":"0"}}}'
check "initialize returns 200" grep -q "^HTTP/1.1 200" "${WORKDIR}/init-headers.txt"
SID="$(grep -i "^mcp-session-id:" "${WORKDIR}/init-headers.txt" | tr -d '\r' | awk '{print $2}')"
check "Mcp-Session-Id returned" test -n "${SID}"
sse_json "${WORKDIR}/init-body.txt" > "${WORKDIR}/init.json"
check "initialize result frame streamed" jq_ok '.result.capabilities' "${WORKDIR}/init.json"

# Per MCP Streamable HTTP spec, subsequent requests carry the negotiated
# protocol version as an HTTP header (from the initialize response, falling
# back to what we requested).
PROTO="$(grep -i "^mcp-protocol-version:" "${WORKDIR}/init-headers.txt" | tr -d '\r' | awk '{print $2}')"
PROTO="${PROTO:-2025-06-18}"
SESS_H=(-H "Mcp-Session-Id: ${SID}" -H "MCP-Protocol-Version: ${PROTO}")

echo "2. notifications/initialized"
CODE="$("${CURL[@]}" -o /dev/null -w "%{http_code}" -X POST "${BASE}/mcp" "${JSON_H[@]}" "${SESS_H[@]}" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}')"
check "initialized accepted (${CODE})" test "${CODE}" = "202" -o "${CODE}" = "200"

echo "3. tools/list (structured via jq)"
"${CURL[@]}" -X POST "${BASE}/mcp" "${JSON_H[@]}" "${SESS_H[@]}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' -o "${WORKDIR}/tools-raw.txt"
sse_json "${WORKDIR}/tools-raw.txt" > "${WORKDIR}/tools.json"
check "read tool present (issue_read)" \
  jq_ok '.result.tools[] | select(.name == "issue_read")' "${WORKDIR}/tools.json"
check "no write tools listed — readonly enforced" \
  jq_ok '[.result.tools[].name | select(test("^(create_|update_|delete_|add_)"))] | length == 0' "${WORKDIR}/tools.json"

echo "4. tools/call issue_read on openabdev/ghpool#15"
"${CURL[@]}" -X POST "${BASE}/mcp" "${JSON_H[@]}" "${SESS_H[@]}" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"issue_read","arguments":{"method":"get","owner":"openabdev","repo":"ghpool","issue_number":15}}}' \
  -o "${WORKDIR}/issue-raw.txt"
sse_json "${WORKDIR}/issue-raw.txt" > "${WORKDIR}/issue.json"
check "issue_read returned issue #15" \
  jq_ok '.result.content[0].text | fromjson | .number == 15' "${WORKDIR}/issue.json"

echo "5. negative: write tool call is rejected"
"${CURL[@]}" -X POST "${BASE}/mcp" "${JSON_H[@]}" "${SESS_H[@]}" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"openabdev","repo":"ghpool","title":"e2e-must-not-exist"}}}' \
  -o "${WORKDIR}/write-raw.txt"
sse_json "${WORKDIR}/write-raw.txt" > "${WORKDIR}/write.json"
check "create_issue rejected (error or unknown tool)" \
  jq_ok '(.error != null) or (.result.isError == true)' "${WORKDIR}/write.json"

echo "6. unknown session returns 404 (MCP spec)"
CODE="$("${CURL[@]}" -o /dev/null -w "%{http_code}" -X POST "${BASE}/mcp" "${JSON_H[@]}" \
  -H "Mcp-Session-Id: ghost-session-e2e" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/list"}')"
check "unknown session → 404 (got ${CODE})" test "${CODE}" = "404"

echo "7. DELETE terminates session"
CODE="$("${CURL[@]}" -o /dev/null -w "%{http_code}" -X DELETE "${BASE}/mcp" "${SESS_H[@]}")"
check "DELETE accepted 2xx (got ${CODE})" test "${CODE}" = "200" -o "${CODE}" = "202" -o "${CODE}" = "204"
CODE="$("${CURL[@]}" -o /dev/null -w "%{http_code}" -X POST "${BASE}/mcp" "${JSON_H[@]}" "${SESS_H[@]}" \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/list"}')"
check "terminated session unpinned → 404 (got ${CODE})" test "${CODE}" = "404"

echo "8. server-side behavior"
check "session pinned in audit log" grep -q "MCP session pinned" "${LOG}"
check "tools/call audit-logged" grep -q "MCP tools/call issue_read" "${LOG}"

# ── Optional: GitHub App credential backend mode (2b) ────────────────────
# Runs when App credentials are provided (CI passes the repo secrets).
if [ -n "${APP_ID:-}" ] && [ -n "${APP_PRIVATE_KEY:-}" ]; then
  echo "9. App-backend mode (ghpool mints installation tokens itself)"
  APP_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
  APP_BASE="http://127.0.0.1:${APP_PORT}"
  APP_LOG="${WORKDIR}/ghpool-app.log"
  cat > "${WORKDIR}/config-app.toml" <<EOF
port = ${APP_PORT}
allowed_owners = ["openabdev"]
[mcp]
enabled = true
[mcp.github_app]
app_id = "${APP_ID}"
private_key = "env:APP_PRIVATE_KEY"
owner = "openabdev"
EOF
  GHPOOL_CONFIG="${WORKDIR}/config-app.toml" "${BIN}" > "${APP_LOG}" 2>&1 &
  APP_PID=$!
  trap '[ -n "${APP_PID:-}" ] && kill "${APP_PID}" 2>/dev/null; cleanup' EXIT

  for _ in $(seq 1 20); do
    "${CURL[@]}" -f "${APP_BASE}/healthz" > /dev/null 2>&1 && break
    sleep 0.5
  done
  "${CURL[@]}" -f "${APP_BASE}/healthz" > /dev/null || { echo "app-mode ghpool failed to start"; cat "${APP_LOG}"; exit 1; }

  "${CURL[@]}" -D "${WORKDIR}/app-init-h.txt" -o "${WORKDIR}/app-init-b.txt" \
    -X POST "${APP_BASE}/mcp" "${JSON_H[@]}" \
    -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ghpool-e2e-app","version":"0"}}}'
  check "app-mode initialize returns 200" grep -q "^HTTP/1.1 200" "${WORKDIR}/app-init-h.txt"
  ASID="$(grep -i "^mcp-session-id:" "${WORKDIR}/app-init-h.txt" | tr -d '\r' | awk '{print $2}')"
  check "app-mode session established" test -n "${ASID}"
  check "installation token minted" grep -q "minted GitHub App installation token" "${APP_LOG}"
  check "session pinned to App credential" grep -q "MCP session pinned to credential github-app" "${APP_LOG}"

  "${CURL[@]}" -X POST "${APP_BASE}/mcp" "${JSON_H[@]}" -H "Mcp-Session-Id: ${ASID}" -H "MCP-Protocol-Version: ${PROTO}" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_read","arguments":{"method":"get","owner":"openabdev","repo":"ghpool","issue_number":15}}}' \
    -o "${WORKDIR}/app-issue-raw.txt"
  sse_json "${WORKDIR}/app-issue-raw.txt" > "${WORKDIR}/app-issue.json"
  check "app-mode issue_read works" \
    jq_ok '.result.content[0].text | fromjson | .number == 15' "${WORKDIR}/app-issue.json"

  kill "${APP_PID}" 2>/dev/null; APP_PID=""
else
  echo "9. App-backend mode skipped (APP_ID/APP_PRIVATE_KEY not set)"
fi

echo
echo "e2e result: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
