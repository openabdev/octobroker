# Getting Started with octobroker

octobroker is a GitHub API proxy for teams running **AI coding agents**: it pools
GitHub credentials server-side, caches read traffic, and (via MCP) gives
agents GitHub's official tool surface **without any GitHub credential in the
agent container**. This guide takes you from zero to a working setup in
stages — each stage is independently useful.

- [Stage 0: five-minute local run](#stage-0-five-minute-local-run)
- [Stage 1: connect an MCP agent (read-only, no agent auth)](#stage-1-connect-an-mcp-agent)
- [Stage 2: per-agent authentication + tool allowlists](#stage-2-per-agent-authentication)
- [Stage 3: GitHub App backend](#stage-3-github-app-backend)
- [Stage 4: enabling writes](#stage-4-enabling-writes)
- [Deploying on Kubernetes / ECS](#deploying-on-kubernetes--ecs)
- [Troubleshooting](#troubleshooting)

## Stage 0: five-minute local run

Prereqs: a GitHub PAT (classic or fine-grained) with read access to the
repos you care about.

```sh
# grab a binary from releases, or: cargo build --release
export OCTOBROKER_PORT=8080
export OCTOBROKER_ALLOWED_OWNERS=your-org
export OCTOBROKER_PAT_MAIN=ghp_xxxx          # any OCTOBROKER_PAT_<ID> env var joins the pool
export OCTOBROKER_MCP_ENABLED=true
./octobroker
# INFO octobroker: MCP reverse proxy enabled → https://api.githubcopilot.com/mcp/readonly
# INFO octobroker: octobroker listening on 0.0.0.0:8080
```

Smoke-test both surfaces:

```sh
# REST (pooled + cached)
curl -s localhost:8080/repos/your-org/your-repo | jq .full_name
# pool + cache stats
curl -s localhost:8080/stats | jq .
```

For anything beyond env-var basics, use a config file. Search order:
`OCTOBROKER_CONFIG` env var → `./config.toml` → `~/.config/octobroker/config.toml`.
Start from [config.example.toml](../config.example.toml).

```toml
# config.toml — minimal
port = 8080
allowed_owners = ["your-org"]

[[identities]]
id = "main"
token = "env:GITHUB_TOKEN"     # env:/aws:secretsmanager:/k8s: refs — no literals needed

[mcp]
enabled = true
```

## Stage 1: connect an MCP agent

Point any Streamable-HTTP MCP client at octobroker. The agent needs **no GitHub
token, no gh CLI, no git credentials** — this is the whole point.

Kiro CLI (`~/.kiro/settings/mcp.json`) and most JSON-configured clients:

```json
{ "mcpServers": { "github": { "url": "http://localhost:8080/mcp" } } }
```

Claude Code:

```sh
claude mcp add --transport http github http://localhost:8080/mcp
```

Ask the agent to list issues in one of your repos. Watch octobroker's log:

```
MCP initialize [via main]
MCP session pinned to credential main [session=7b86a7eb]
MCP tools/list [via main] [session=7b86a7eb]
MCP tools/call list_issues repo=your-org/your-repo [via main] [session=7b86a7eb]
```

Notes for this stage:

- The upstream is GitHub's hosted **read-only** tool surface. Tool names
  differ from the write server (`issue_read`, not `get_issue`) — agents
  discover them via `tools/list`.
- **Anyone who can reach `/mcp` gets this read access** (network-trust
  model). Keep octobroker cluster-internal; go to Stage 2 before widening.

## Stage 2: per-agent authentication

Add `[[mcp.agents]]` entries. The moment one exists, every `/mcp` request
must present a valid `X-Octobroker-Key`, and each agent is confined to an exact
tool allowlist (default-deny — new upstream tools are denied until listed):

```toml
[[mcp.agents]]
id = "my-bot"
key = "env:OCTOBROKER_KEY_MYBOT"             # 256-bit random; openssl rand -hex 32
tools = ["issue_read", "list_issues", "get_file_contents"]
repos = ["your-org/your-repo"]           # optional; omit = no repo restriction
```

Agent config gains one line (deliver the key via your secret machinery —
most MCP clients expand `${ENV}`):

```json
{ "mcpServers": { "github": {
    "url": "http://octobroker:8080/mcp",
    "headers": { "X-Octobroker-Key": "${OCTOBROKER_KEY}" } } } }
```

The key is a **octobroker credential, not a GitHub credential**: a leak is
bounded by the agent's allowlist and revoked by editing octobroker config.
Rotate with zero downtime via `keys = ["env:OLD", "env:NEW"]`.
Sessions are bound to the agent that opened them — another agent presenting
the same session ID gets 403.

Terminate TLS in front of octobroker in production — the key travels in a header.

## Stage 3: GitHub App backend

Recommended for production even while read-only: short-lived installation
tokens instead of long-lived PATs, and rate limits that scale with the
installation.

1. Create a GitHub App (Settings → Developer settings → GitHub Apps), grant
   it the permissions your agents' tools need (see the
   [permission table](../README.md#write-access-phase-2b)), and install it
   on your org.
2. Store the private key in your secret backend.
3. Configure:

```toml
[mcp.github_app]
app_id = "123456"
private_key = "aws:secretsmanager:octobroker/app:private_key"
owner = "your-org"          # installation auto-discovered (or set installation_id)
```

octobroker now mints and refreshes tokens itself (`minted GitHub App
installation token … expires in 3599s` in the log). Sessions never outlive
the token they started with — at expiry the client transparently
re-initializes. The PAT pool keeps serving REST/GraphQL.

## Stage 4: enabling writes

Writes are opt-in and hard-gated: startup **fails** unless agents, the App
backend, and the audit sink are all configured.

```toml
[mcp]
enabled = true
enable_writes = true
# max_inflight_writes = 4        # per-agent concurrency cap

[mcp.audit]
path = "/var/lib/octobroker/mcp-audit.jsonl"

[[mcp.agents]]
id = "my-bot"
key = "env:OCTOBROKER_KEY_MYBOT"
tools = ["issue_read", "create_issue", "add_issue_comment"]
repos = ["your-org/your-repo"]   # exact entries → GitHub-enforced token scoping
```

What you get:

- A write call passes: key auth → tool allowlist → write classification →
  repo allowlist → concurrency cap → **fail-closed audit record** → forward
  with a **repo-scoped installation token**.
- Two fsync'd JSONL audit records per write. The result record captures the
  MCP tool outcome — an operation that failed inside an HTTP 200 is recorded
  as `tool_error: true`. Argument values are never written to the log.
- If the audit file can't be written, the write is rejected (503) before
  reaching GitHub.

Read the audit log:

```sh
jq -c 'select(.phase=="result")' /var/lib/octobroker/mcp-audit.jsonl | tail
```

## Deploying on Kubernetes / ECS

Single replica while MCP is enabled (session pins are in-process; a rolling
deploy just forces clients to re-initialize). Minimal K8s shape:

```yaml
# Secret for the pool credential (or use IRSA + aws:secretsmanager: refs)
apiVersion: v1
kind: Secret
metadata: { name: octobroker-secrets, namespace: octobroker }
stringData: { pat: ghp_xxx, agent-key: <openssl rand -hex 32> }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: octobroker, namespace: octobroker }
spec:
  replicas: 1
  selector: { matchLabels: { app: octobroker } }
  template:
    metadata: { labels: { app: octobroker } }
    spec:
      containers:
        - name: octobroker
          image: ghcr.io/openabdev/octobroker:latest   # or your build
          env:
            - { name: OCTOBROKER_CONFIG, value: /etc/octobroker/config.toml }
            - name: GITHUB_TOKEN
              valueFrom: { secretKeyRef: { name: octobroker-secrets, key: pat } }
            - name: OCTOBROKER_KEY_MYBOT
              valueFrom: { secretKeyRef: { name: octobroker-secrets, key: agent-key } }
          volumeMounts: [{ name: config, mountPath: /etc/octobroker }]
          readinessProbe: { httpGet: { path: /healthz, port: 8080 } }
      volumes:
        - name: config
          configMap: { name: octobroker-config }
---
apiVersion: v1
kind: Service
metadata: { name: octobroker, namespace: octobroker }
spec:
  type: ClusterIP      # cluster-internal only
  selector: { app: octobroker }
  ports: [{ port: 8080, targetPort: 8080 }]
```

Agents in the cluster use `http://octobroker.octobroker.svc.cluster.local:8080/mcp`.
On ECS, run it as a Service Connect service and use
`http://octobroker.<namespace>:8080/mcp`. Egress required:
`api.github.com` + `api.githubcopilot.com`.

## Troubleshooting

Policy denials of `tools/call` are returned as *tool errors* (HTTP 200, JSON-RPC
result with `isError: true`, request id echoed) so the calling model sees the
denial and can adapt. Protocol-level failures (auth, sessions) remain HTTP
error codes.

| Symptom | Meaning | Fix |
|---------|---------|-----|
| `401 X-Octobroker-Key header required` | Agents are configured; request has no/invalid key | Add the header to the client config; check the secret value |
| Tool result `octobroker policy denied this call: tool not permitted by agent policy` | Tool not on the agent's `tools` allowlist | Add it (deliberate: new tools are denied by default) |
| Tool result `… write tools are not enabled` | Write-classified tool without `enable_writes` | Complete Stage 4 |
| Tool result `… call has no resolvable repository target` | Agent has `repos` but the call's arguments name no repo (e.g. `search_code`) | Expected: repo-restricted agents can't use repo-less tools; remove `repos` or use repo-scoped tools |
| Tool result `… repository not permitted by agent policy` | Call targets a repo outside the agent's `repos` allowlist | Add the repo (or `owner/*`) to the agent's `repos`, or have the agent use a public fetch instead |
| `403 session not owned by this agent` | Session ID reused by a different agent | Each agent keeps its own session; re-initialize |
| `404 session not found or expired` | Pin evicted (TTL/restart) or credential expired | Normal: MCP clients re-initialize transparently |
| `429 agent write concurrency limit reached` | In-flight cap hit | Raise `max_inflight_writes` or let calls drain |
| `503 audit backend unavailable — write rejected` | Fail-closed audit: record couldn't be persisted | Fix disk/permissions for `[mcp.audit].path` — this is by design |
| Startup panic: `enable_writes requires …` | Write gate validation | Configure the missing section (agents / github_app / audit) |
| Tools missing from `tools/list` | Per-agent `X-MCP-Tools` filtering, or the App lacks a permission | Check the agent's `tools` list and the App's permission grants |
