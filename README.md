<p align="center">
  <img src="docs/assets/logo.png" alt="octobroker — Secure GitHub Gateway for AI Agents" width="360">
</p>

A secure, cloud-native GitHub gateway for AI coding agents. Agents get GitHub's official MCP tools, REST/GraphQL reads, and even `git push` — **without holding a single GitHub credential**. octobroker authenticates each agent with a revocable key, enforces per-agent default-deny tool and repo policy, and mints short-lived, repo-scoped GitHub App tokens on demand — across multiple orgs from one endpoint. PAT pooling and read caching included for high-throughput REST traffic.

> [octobroker.dev](https://octobroker.dev) · Design: [docs/DESIGN.md](docs/DESIGN.md) · Onboarding: [docs/getting-started.md](docs/getting-started.md) · RFC history: [#15](https://github.com/openabdev/octobroker/issues/15)

## Design Principles

- **No GitHub credential on the agent** — agents hold at most an octobroker API key (revocable, policy-bounded, not a GitHub credential). The GitHub credentials live in exactly one place: octobroker.
- **Default-deny policy engine** — each agent gets an exact tool allowlist and repository allowlist; new upstream tools are denied until explicitly granted. GitHub's own scoped installation tokens enforce the repo boundary independently of octobroker's parsing.
- **Short-lived credentials first** — GitHub App installation tokens (1h, auto-refreshed, repo-scoped at mint) are the recommended backend. Long-lived PAT pooling remains for REST read caching and legacy setups.
- **Cloud-native** — runs on any Kubernetes (Amazon EKS, Google Cloud GKE, self-managed k8s) and Amazon ECS. Single static binary, no runtime dependencies.
- **Secrets-first** — credentials are resolved at runtime from AWS Secrets Manager or Kubernetes secrets. No plain text tokens at rest.
- **Private network isolation** — designed to run inside your trusted network (VPC, service mesh). No public endpoints; egress only to GitHub.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Private Network / VPC                        │
│                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                           │
│  │ Agent A  │  │ Agent B  │  │ gh CLI   │                           │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                           │
│       │              │              │                               │
│       └──────────────┼──────────────┘                               │
│                      │                                              │
│                      ▼                                              │
│           ┌──────────────────────────────────┐                      │
│           │              octobroker              │                      │
│           │                                  │                      │
│           │  ┌────────────────────────────┐  │                      │
│           │  │ Agent authn (X-Octobroker-Key) │  │                      │
│           │  │ + default-deny policy      │  │  ┌────────────────┐  │
│           │  │   tools / repos per agent  │  │  │ Secrets Manager│  │
│           │  └────────────────────────────┘  │  │ (AWS/K8s/Env)  │  │
│           │  ┌─────────────┐ ┌────────────┐  │  └───────┬────────┘  │
│           │  │ GitHub App  │ │  PAT Pool  │◄─┼──────────┘           │
│           │  │ tokens (1h, │ │ (REST read │  │                      │
│           │  │ repo-scoped)│ │  budget)   │  │                      │
│           │  └─────────────┘ └────────────┘  │                      │
│           │  ┌─────────────┐ ┌────────────┐  │                      │
│           │  │ Fail-closed │ │   Cache    │  │                      │
│           │  │ write audit │ │  (in-mem)  │  │                      │
│           │  └─────────────┘ └────────────┘  │                      │
│           └───────┬──────────────────┬───────┘                      │
│                   │                  │                              │
└───────────────────┼──────────────────┼──────────────────────────────┘
                    │                  │
                    ▼                  ▼
        ┌─────────────────────┐  ┌───────────────────┐
        │ api.githubcopilot   │  │  api.github.com   │
        │ .com/mcp/  (MCP)    │  │  (REST/GraphQL)   │
        └─────────────────────┘  └───────────────────┘

Request Flow:

  GET /repos/org/repo/pulls
    → cache HIT? return cached
    → cache MISS: select PAT with highest remaining budget
    → forward to GitHub, cache response, update rate limits

  POST /graphql (query)
    → cache HIT? return cached
    → cache MISS: select pooled PAT, forward, cache response

  POST /graphql (mutation)
    → require client Authorization header
    → passthrough to GitHub (no pooling, no caching)
    → resolve + log GitHub username from token

  POST /mcp (opt-in; read-only by default, writes behind a hard gate)
    → MCP Streamable HTTP reverse proxy to GitHub's hosted MCP server
    → authenticate agent (X-Octobroker-Key) → default-deny tool/repo policy
    → inject scoped GitHub App token (or pooled PAT), pin per session
    → audit-log every tools/call; writes fail-closed audited
```

## What it does

- Pools multiple GitHub PATs and routes each read request through the identity with the most remaining rate limit budget
- Caches GitHub REST and GraphQL query responses in memory with configurable TTLs
- Proxies GraphQL mutations with passthrough auth (client's own token, no caching)
- **MCP reverse proxy** (opt-in) — agents connect an MCP client to `/mcp` and get GitHub's official MCP tools with **no GitHub credential on the agent**; per-agent keys + default-deny tool/repo allowlists, GitHub App credentials, and hard-gated audited writes
- **Git credential broker** (opt-in) — `obk` acts as a git credential helper: at `git push` time it exchanges the agent's octobroker key for a short-lived, single-repo, Contents-only GitHub App token — no stored git credential in the agent container
- Mirrors the GitHub API path structure — clients just change the base URL
- Restricts access to configured org/owner repos only
- Auto-resolves GitHub username from tokens for audit logging

## Quick start

> **New here? Follow the [Getting Started guide](docs/getting-started.md)** — it walks from a five-minute local run through per-agent authentication, the GitHub App backend, and enabling audited writes.

```sh
cp config.example.toml config.toml
# Edit config.toml with your PATs and allowed owners

cargo run --release
# Listening on 0.0.0.0:8080

curl http://localhost:8080/repos/openclaw/chi/pulls/123
curl http://localhost:8080/stats
```

## Configuration

### TOML file

Config file search order:

1. `OCTOBROKER_CONFIG` env var (explicit path — always wins)
2. `./config.toml` (current directory)
3. `$XDG_CONFIG_HOME/octobroker/config.toml` (defaults to `~/.config/octobroker/config.toml`)
4. No file → environment variables only (see below)

The loaded path is logged at startup. For configs in your home directory, prefer secret references (`env:`, `aws:secretsmanager:`, `k8s:`) over plain token literals.

See [config.example.toml](config.example.toml) for all options.

### Secret references

The `token` field in `[[identities]]` supports multiple secret sources, so credentials never need to exist in plain text on disk:

| Format | Source |
|--------|--------|
| `ghp_xxx...` | Plain literal (local dev only) |
| `env:VAR_NAME` | Environment variable |
| `aws:secretsmanager:secret-name:json-key` | AWS Secrets Manager |
| `k8s:namespace/secret-name:key` | Kubernetes secret (mounted volume) |

#### AWS Secrets Manager

Store PATs as a JSON object in a single secret:

```sh
aws secretsmanager create-secret --name octobroker/pats \
  --secret-string '{"pat_alice":"ghp_xxx","pat_bob":"ghp_yyy"}'
```

```toml
[[identities]]
id = "alice"
token = "aws:secretsmanager:octobroker/pats:pat_alice"
```

octobroker uses the standard AWS credential chain (instance profile, ECS task role, SSO, env vars).

#### Google Cloud Secret Manager (planned)

```toml
[[identities]]
id = "alice"
token = "gcp:secretmanager:projects/my-proj/secrets/octobroker-pat:latest"
```

GCP support is on the roadmap. Contributions welcome.

#### Kubernetes Secrets

Mount your secret as a volume at `/etc/secrets/` and reference it:

```yaml
# K8s Secret
apiVersion: v1
kind: Secret
metadata:
  name: octobroker-pats
  namespace: default
stringData:
  pat_alice: ghp_xxx
```

```toml
[[identities]]
id = "alice"
token = "k8s:default/octobroker-pats:pat_alice"
```

Works with any Kubernetes distribution — EKS, GKE, AKS, k3s, or self-managed.

### Environment variables only

```sh
export OCTOBROKER_PORT=8080
export OCTOBROKER_ALLOWED_OWNERS=openclaw,openabdev
export OCTOBROKER_PAT_ALICE=ghp_xxx
export OCTOBROKER_PAT_BOB=ghp_yyy
```

PATs are discovered from any env var matching `OCTOBROKER_PAT_<ID>=<token>`.

## Deployment

### Docker

```sh
docker build -t octobroker .
docker run -p 8080:8080 -v ./config.toml:/config.toml octobroker
```

### ECS (Service Connect)

Deploy as a service in your ECS cluster with Cloud Map namespace. Other services access it via:
```
http://octobroker.<namespace>:8080/repos/owner/repo/pulls/123
```

### Kubernetes

Deploy as a ClusterIP Service. Other pods access it via:
```
http://octobroker.<namespace>.svc.cluster.local:8080/repos/owner/repo/pulls/123
```

## API

### REST (GET)

All GitHub REST API GET paths are proxied transparently with PAT pooling and caching:

```
GET /<github-api-path>
```

### GraphQL (POST /graphql)

```
POST /graphql
```

- **Queries** — routed through pooled PATs, responses cached
- **Mutations** — client's own `Authorization` header passed through to GitHub (no pooling, no caching)

If a mutation request has no `Authorization` header, octobroker returns `401`.

```
  ┌────────────────────────────────────────────────────────────────┐
  │                    POST /graphql                               │
  │                                                                │
  │  Parse request body → extract "query" field                    │
  │                                                                │
  │  ┌─────────────────────┐       ┌────────────────────────────┐  │
  │  │ starts with "query" │       │ starts with "mutation"     │  │
  │  └──────────┬──────────┘       └──────────────┬─────────────┘  │
  │             │                                  │               │
  │             ▼                                  ▼               │
  │  ┌─────────────────────┐       ┌────────────────────────────┐  │
  │  │ Check cache         │       │ Require client             │  │
  │  │  HIT → return       │       │ Authorization header       │  │
  │  │  MISS ↓             │       │  missing → 401             │  │
  │  └──────────┬──────────┘       └──────────────┬─────────────┘  │
  │             │                                  │               │
  │             ▼                                  ▼               │
  │  ┌─────────────────────┐       ┌────────────────────────────┐  │
  │  │ Select pooled PAT   │       │ Passthrough client's token │  │
  │  │ (highest budget)    │       │ (identity preserved)       │  │
  │  └──────────┬──────────┘       └──────────────┬─────────────┘  │
  │             │                                  │               │
  │             ▼                                  ▼               │
  │  ┌─────────────────────┐       ┌────────────────────────────┐  │
  │  │ Forward to GitHub   │       │ Forward to GitHub          │  │
  │  │ Cache response      │       │ No caching                 │  │
  │  │ Update rate limits  │       │ Log resolved username      │  │
  │  └─────────────────────┘       └────────────────────────────┘  │
  └────────────────────────────────────────────────────────────────┘
```

### MCP (POST/GET/DELETE /mcp) — opt-in

Reverse proxy to [GitHub's hosted MCP server](https://github.com/github/github-mcp-server): agents connect a Model Context Protocol client to octobroker and get GitHub's official MCP tools — **with no GitHub credential on the agent**. octobroker strips any client `Authorization` header and injects a pooled credential upstream.

> **Status: writes available behind a hard gate.** Read-only by default; `enable_writes` unlocks write tools for authenticated agents only, and requires the GitHub App backend plus fail-closed audit (validated at startup). See the [RFC](https://github.com/openabdev/octobroker/issues/15).

```
┌───────────────── Private Network / VPC ─────────────────┐
│                                                         │
│  ┌───────────────────┐         ┌────────────────────┐   │
│  │  MCP client       │         │  octobroker            │   │
│  │  (agent)          │  MCP    │                    │   │
│  │                   │ ──────► │  1. strip client   │   │
│  │  no GitHub        │  HTTP   │     Authorization  │   │
│  │  credential       │ ◄────── │  2. pin pooled     │   │
│  └───────────────────┘         │     token/session  │   │
│                                │  3. audit-log      │   │
│                                │     tools/call     │   │
│                                └─────────┬──────────┘   │
└──────────────────────────────────────────┼──────────────┘
                                           │ Bearer <pooled credential>
                                           ▼
                            ┌──────────────────────────────┐
                            │ api.githubcopilot.com/mcp/   │
                            │ readonly    (hosted, GitHub- │
                            │ maintained tool schemas)     │
                            └──────────────────────────────┘
```

Enable it in `config.toml` (or `OCTOBROKER_MCP_ENABLED=true`):

```toml
[mcp]
enabled = true
# upstream = "https://api.githubcopilot.com/mcp/readonly"  # default
# toolsets = ["issues", "pull_requests", "repos"]          # optional coarse filter
# session_ttl_secs = 3600                                  # session pin idle TTL
```

Behavior notes:

- **Sessions are pinned** — the pooled identity is selected at `initialize` and reused for the whole MCP session. An unknown or expired session gets `404` (per MCP spec) and the client re-initializes transparently.
- **Tool names differ from the write server** — the readonly surface uses e.g. `issue_read`, not `get_issue`. Discover them via `tools/list`.
- **Audit log** — every JSON-RPC frame is logged with method, tool name, identity, and session: `MCP tools/call issue_read [via alice] [session=7b86a7eb]`.
- **`allowed_owners` is not enforced on `/mcp`** — without `[[mcp.agents]]` configured, access is bounded only by the pooled credential's own permissions and the read-only upstream. For repo-level control, configure per-agent `repos` allowlists (below).

#### Per-agent authentication (Phase 2a)

Add `[[mcp.agents]]` entries to require an API key on every `/mcp` request and enforce a **default-deny tool allowlist** per agent:

```toml
[[mcp.agents]]
id = "openab-bot"
key = "aws:secretsmanager:octobroker/mcp-keys:openab"   # env:/k8s: refs also work
tools = ["issue_read", "list_issues", "pull_request_read"]
```

- With any agent configured, requests without a valid `X-Octobroker-Key` get `401`; a `tools/call` for a tool not on the agent's allowlist gets `403` at the proxy — it never reaches GitHub. The allowlist is also injected upstream as `X-MCP-Tools`, so `tools/list` natively shows the agent only its permitted tools.
- New upstream tools are **denied by default** until added to an agent's `tools` list.
- The key is a **octobroker credential, not a GitHub credential** — a leak is bounded by that agent's allowlist and revoked by editing octobroker config, without touching GitHub.
- Audit lines include the agent: `MCP tools/call issue_read [agent=openab-bot via alice] [session=…]`.
- Terminate TLS in front of octobroker (ALB, ingress, mesh) in production — the key travels in a header.

Client config gains one line:

```json
{
  "mcpServers": {
    "github": {
      "url": "http://octobroker.<namespace>:8080/mcp",
      "headers": { "X-Octobroker-Key": "${OCTOBROKER_KEY}" }
    }
  }
}
```

Deliver `OCTOBROKER_KEY` to the agent container via ECS task secrets / K8s Secrets — most MCP clients expand `${ENV}` in config.

#### Write access (Phase 2b)

```toml
[mcp]
enabled = true
enable_writes = true          # startup FAILS unless all three sections below exist
# max_inflight_writes = 4     # per-agent write concurrency cap (0 = unlimited)

[mcp.github_app]              # writes never run on pooled PATs
app_id = "123456"
private_key = "aws:secretsmanager:octobroker/app:private_key"
owner = "openabdev"

[mcp.audit]                   # writes are fail-closed audited
path = "/var/lib/octobroker/mcp-audit.jsonl"

[[mcp.agents]]                # writes are only for authenticated agents
id = "openab-bot"
key = "aws:secretsmanager:octobroker/mcp-keys:openab"
tools = ["issue_read", "create_issue", "add_issue_comment", "octobroker_review_minimize_comment"]
repos = ["openabdev/octobroker", "openabdev/openab"]
```

How the write path is bounded:

- **Default-deny stack**: agent key → tool allowlist → write classification → repo allowlist (deny-if-unresolvable) → per-agent in-flight cap → fail-closed audit record → forward.
- **Scoped credentials**: when an agent's `repos` are all exact entries under one owner, its installation token is minted with the API's `repositories` parameter — **GitHub itself enforces the repo boundary**, independent of octobroker's argument parsing. Wildcard or mixed-owner allowlists fall back to an installation-wide token (proxy-side checks still apply).
- **Audit**: two fsync'd JSONL records per write (pre-flight + result). The result captures the MCP tool outcome (`result.isError`) — HTTP 200 alone is not treated as success. If the pre-flight record cannot be persisted, the write is rejected (503) without reaching GitHub. Argument values are never recorded.
- **No auto-retry**: octobroker never retries a forwarded call; an ambiguous write outcome (e.g. connection lost mid-response) is recorded as undeterminable and surfaced to the client — retry decisions belong to the caller.
- **Revocation**: session pins live in process memory; key rotation uses dual `keys`, and any config change (agent disabled, policy tightened) takes effect by restart, which clears all sessions. Upstream session DELETE is a no-op at GitHub — octobroker's pin cache is the session authority.

Required GitHub App permissions (grant only what your agents' tools need):

| Tools | App permission |
|-------|----------------|
| `issue_read`, `list_issues`, `create_issue`, `add_issue_comment` | Issues: read / write |
| `octobroker_review_minimize_comment` | Issues: write and Pull requests: write |
| `octobroker_commit_status_set` | Commit statuses: write |
| `pull_request_read`, `create_pull_request`, `merge_pull_request` | Pull requests: read / write |
| `get_file_contents`, `create_or_update_file`, `push_files` | Contents: read / write |
| `list_workflows`, `run_workflow` | Actions: read / write |


#### octobroker-owned review tools (issue #44 MVP)

When writes are enabled and an authenticated agent explicitly includes a tool in its allowlist, `tools/list` also advertises it. For example:

```toml
[[mcp.agents]]
id = "review-bot"
key = "env:OCTOBROKER_REVIEW_KEY"
tools = ["issue_read", "list_issues", "octobroker_review_minimize_comment", "octobroker_commit_status_set"]
repos = ["openabdev/octobroker"]
```

`octobroker_review_minimize_comment` accepts `owner`, `repo`, `node_id`, and a `classifier` (`ABUSE`, `DUPLICATE`, `OFF_TOPIC`, `OUTDATED`, `RESOLVED`, or `SPAM`). It supports issue and pull-request comments authored by the current GitHub App bot identity; it does not minimize human-authored comments or unsupported node types. Before mutating, it verifies both the App-bot author and the exact repository owner/name against the policy arguments, then executes GitHub's `minimizeComment` GraphQL mutation locally through octobroker's scoped GitHub App credential. The operation is not forwarded to the upstream MCP server. The call uses the same repository policy, write gate, in-flight limit, and fail-closed audit as upstream write tools. Agents that do not explicitly allowlist the name, or that have writes disabled, neither see it in `tools/list` nor can call it.

`octobroker_commit_status_set` creates a [commit status](https://docs.github.com/en/rest/commits/statuses) — the upstream GitHub MCP server offers no commit-status mutation at all (only the read-only `get_status`), so review agents that need to publish a verdict as a status check (e.g. `context: "OpenAB PR Review"`, `state: failure`) use this broker-owned tool instead. It accepts `owner`, `repo`, a full commit `sha`, a `state` (`error`, `failure`, `pending`, or `success`), a non-empty `context`, and optional `description` (≤ 140 chars) and http(s) `target_url`. Arguments are strictly validated (the SHA and repository become URL path segments), then octobroker executes `POST /repos/{owner}/{repo}/statuses/{sha}` locally through the scoped GitHub App credential; only HTTP 201 counts as success. The same explicit allowlist, repository policy, write gate, in-flight limit, and fail-closed audit apply. Requires **Commit statuses: write** on the App.

This is intentionally a narrow surface: octobroker does not expose arbitrary GraphQL or REST, and upstream GitHub MCP tools remain unchanged. Any future octobroker-owned tool must preserve the same explicit allowlist, repository binding, write gate, and audit requirements.

The tool surface returned by `tools/list` shrinks to match the App's actual permissions (verified in the [#22 spike](https://github.com/openabdev/octobroker/issues/22)) — grant conservatively and expand as agents need more.

#### Multi-installation routing (one key, many orgs)

One agent, one `X-Octobroker-Key`, one MCP server entry — repositories in several
organizations. Replace the singular `[mcp.github_app]` with one
`[[mcp.github_apps]]` entry per installation (the same App installed in each
org, or one App per org):

```toml
[[mcp.github_apps]]
app_id = "123456"
private_key = "aws:secretsmanager:octobroker/app:private_key"
owner = "openabdev"            # routing key — unique per entry
installation_id = 11111111     # recommended: skip discovery

[[mcp.github_apps]]
app_id = "123456"
private_key = "aws:secretsmanager:octobroker/app:private_key"
owner = "oablab"
installation_id = 22222222

[[mcp.agents]]
id = "b0"
key = "aws:secretsmanager:octobroker/mcp-keys:b0"
tools = ["issue_read", "list_issues", "create_issue", "add_issue_comment"]
repos = ["openabdev/openab", "oablab/chi"]   # owners select the installations
```

How it works:

```
b0 initialize (one downstream session)
  ├─ upstream session A ← repo-scoped token, openabdev installation
  └─ upstream session B ← repo-scoped token, oablab installation

tools/call {owner: "openabdev", …} → session A (openabdev token)
tools/call {owner: "oablab", …}    → session B (oablab token)
```

- **Routing is argument-derived** — the installation is selected by the
  repository owner resolved from the call's `owner`/`repo` arguments, never
  by anything the agent chooses directly. Owners outside the agent's `repos`
  allowlist are denied before any credential is touched.
- **Eager fan-out at `initialize`** — one repo-scoped token is minted and one
  upstream session opened per owner in the agent's allowlist, fail-closed: if
  any installation can't mint or initialize, the whole `initialize` fails and
  any upstream sessions already opened are cleaned up (best-effort DELETE).
  Tokens are never mixed within one upstream session, preserving the pinning
  invariant per installation.
- **One downstream session** — the client sees a single session ID; octobroker
  maps it to the per-installation upstream sessions. `DELETE` and
  `notifications/*` fan out to every route (best-effort for secondaries).
  When a pinned token expires the session gets 404 and the client
  re-initializes (fresh tokens all around).
- **Primary route** — the alphabetically first owner in the agent's `repos`
  allowlist. Its upstream session ID doubles as the downstream session ID
  and serves non-repo traffic (`tools/list`, GET streams).
- **Primary-only server-initiated traffic** — GET stream resumption and any
  client→server JSON-RPC responses ride the primary route's upstream
  session. GitHub's hosted MCP server answers `tools/call` directly in the
  POST response, so tool calls are unaffected; server-initiated
  interactions on secondary routes are not supported.
- **Grant identical App permissions to every installation** — `tools/list`
  is served by the primary installation, so a permission mismatch would
  advertise tools that fail with a permission error on the other org.
- **Startup validation** — duplicate owners, agents without `repos`, and repo
  owners with no matching installation are all configuration errors.
- **Audit attribution** — write records carry the exact installation:
  `"cred": "github-app:openabdev"`.
- Multi-installation mode requires `[[mcp.agents]]` — there is no
  network-trust variant.

Trade-off vs. one key per org: a leaked key reaches the allowlisted repos of
**all** configured installations. Prefer separate agents/keys when you want
per-org blast-radius isolation.

#### Git over HTTPS via App tokens (`/git-credential`)

MCP covers issues and PRs, but `git push` speaks the Git protocol — it needs
a real credential at push time. `enable_git_credentials` lets a
repository-scoped agent exchange its octobroker key for a **short-lived,
single-repo** App installation token, eliminating the last long-lived GitHub
credential in the agent container:

```toml
[mcp]
enable_git_credentials = true   # same hard gate as writes:
                                # agents + App backend + [mcp.audit]
```

The App needs **Contents: Read & write** on the target repositories. With
the singular `[mcp.github_app]` form, `owner` is **required** when git
credentials are enabled — the explicit `installation_id` is verified against
the installation's actual account before any token is issued.

**Read-only (clone without push).** For an agent that should be able to
`git clone`/fetch a private repo but never `git push`, set:

```toml
[mcp]
enable_git_credentials = true
git_credentials_read_only = true   # mint contents:read instead of write
```

The issued token then carries **`contents: read`** only — clone and fetch
work, pushes are rejected by GitHub. In this mode the App only needs
**Contents: read** on the target repositories. Default is `false`
(push-capable, unchanged behavior).

**Per-agent override.** Mixed fleets set the mode per agent instead: a
`git_credentials_read_only` key on an `[[mcp.agents]]` entry wins over the
global default, in either direction. The recommended posture for a fleet
with one pusher is a read-only global default plus one explicit exception:

```toml
[mcp]
enable_git_credentials = true
git_credentials_read_only = true    # fleet default: clone-only

[[mcp.agents]]
id = "deployer"
keys = ["aws:secretsmanager:octobroker/mcp-keys:deployer"]
repos = ["openabdev/openab"]
git_credentials_read_only = false   # the one push-capable agent

[[mcp.agents]]
id = "reviewer"
keys = ["aws:secretsmanager:octobroker/mcp-keys:reviewer"]
repos = ["openabdev/*"]
# no override — inherits the read-only default
```

Omitting the per-agent key inherits the global flag. Both values are
operator-set config — an agent can never choose its own mode. Read and write
tokens are cached under separate namespaces, so agents with different modes
never share credentials even for the same repository. Note the App itself
must hold **Contents: Read & write** whenever any agent is push-capable.

Agent side, `obk` doubles as a standard git credential helper. Register it
as the **only** helper for `github.com` — `--replace-all` with an empty
first entry clears any inherited helpers (osxkeychain, GCM, `gh auth
git-credential`) that would otherwise supply broader credentials:

```sh
git config --global --replace-all credential."https://github.com".helper ""
git config --global --add credential."https://github.com".helper "!obk git-credential"
git config --global credential."https://github.com".useHttpPath true
```

Every `git push` then flows:

```
git push → obk git-credential (OCTOBROKER_KEY from env)
         → GET /git-credential?repo=owner/name   (X-Octobroker-Key)
         → key auth → repo allowlist → installation routing
         → durable audit preflight (phase: git_credential_request)
         → installation owner verified against GitHub
         → Contents-only single-repo token (~1h, GitHub-enforced scope)
         → audit result (phase: git_credential_result)
         → push authenticated as <app>[bot]
```

Properties:

- **Single-repo, Contents-only tokens** — each credential is minted with
  exactly the repo being pushed and `contents: write` only (or `contents:
  read` under `git_credentials_read_only`), never the App's full permission
  set; GitHub itself enforces both boundaries. Git tokens are cached
  separately from MCP tokens, and read-only tokens under their own namespace
  distinct from write tokens.
- **Owner binding** — the configured owner label is verified against the
  actual installation account (`GET /app/installations/{id}`) before
  issuance and re-verified hourly (accounts can rename); a mislabeled
  installation ID is refused.
- **Fail-closed audit** — a request record is persisted *before* any mint or
  cache lookup, and a result record before the token is returned; if either
  write fails, no credential (503). The token value is never written to the
  audit log.
- **Deny-by-default** — repo-less agents, off-allowlist repos, and owners
  without an installation are refused before any mint.
- **Fail-closed helper** — once a request is recognized as `github.com`
  HTTPS, any failure (missing `OCTOBROKER_KEY`, missing path, policy denial,
  network error) makes `obk` emit `quit=true`, telling git to stop the
  helper cascade instead of falling through to broader stored credentials
  or prompting. Non-GitHub hosts are declined quietly so other helpers can
  serve them. `gist.github.com` is not supported.
- **Nothing to store** — `store`/`erase` are no-ops; tokens expire on their
  own. `cache-control: no-store` on the response.

Deployment notes:

- Requires egress to `api.githubcopilot.com` (the only additional external dependency).
- Run a **single replica** while MCP is enabled — session pins live in process memory. A rolling deploy terminates sessions; clients recover by re-initializing.
- Inside a trusted network, any workload that can reach `/mcp` gets the same read-only access (same trust model as octobroker's REST reads). Put TLS and agent authentication in front before any write-capable phase.
- If the hosted endpoint is unreachable from your network, point `upstream` at a self-hosted [`github-mcp-server`](https://github.com/github/github-mcp-server) instead — same protocol and headers.

### Management

| Path | Description |
|------|-------------|
| `GET /healthz` | Health check |
| `GET /stats` | Pool and cache statistics |

## How clients use it

### obk CLI (recommended)

`obk` is a drop-in `gh` shim that routes read commands through octobroker's REST API (pooled + cached) and falls through to the real `gh` for writes.

```sh
export OCTOBROKER_URL=http://octobroker.openab.local:8080

# Reads — through octobroker (pooled + cached)
obk api repos/org/repo --jq .stargazers_count
obk issue list -R org/repo -L 10
obk pr list -R org/repo
obk pr view 123 -R org/repo
obk run list -R org/repo

# Writes — falls through to real gh (direct to GitHub)
obk issue create -R org/repo -t "title" -b "body"
obk issue comment 123 -R org/repo -b "comment"
obk pr create -R org/repo -t "title" -b "body"
```

To replace `gh` transparently:

```sh
ln -sf $(which obk) ~/bin/gh
export PATH=~/bin:$PATH
```

### gh CLI

```sh
export GITHUB_API_URL=http://localhost:8080
```

REST calls (`gh api repos/...`) route through octobroker. Note: `gh` CLI's built-in commands (`gh issue list`, `gh pr list`) use GraphQL internally and bypass `GITHUB_API_URL` — use `obk` for full coverage.

### Coding agents

Set the GitHub API base URL to point at octobroker:

```sh
export GITHUB_API_BASE=http://localhost:8080
```

### MCP clients (agents)

Point any Streamable-HTTP MCP client at octobroker — no GitHub token, no `gh` CLI, no git credentials in the agent container.

Kiro CLI (`~/.kiro/settings/mcp.json`) and most JSON-configured clients:

```json
{
  "mcpServers": {
    "github": {
      "url": "http://octobroker.<namespace>:8080/mcp",
      "headers": { "X-Octobroker-Key": "${OCTOBROKER_KEY}" }
    }
  }
}
```

With `[[mcp.agents]]` configured (recommended), every request needs the agent's `X-Octobroker-Key` — deliver it via ECS task secrets / K8s Secrets. Without any agents configured (network-trust mode), the `headers` line can be dropped.

Claude Code:

```sh
claude mcp add --transport http github http://octobroker.<namespace>:8080/mcp \
  --header "X-Octobroker-Key: ${OCTOBROKER_KEY}"
```

Verify from the container (no GitHub credential anywhere):

```sh
curl -s -X POST http://octobroker:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Octobroker-Key: $OCTOBROKER_KEY" \
  -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' -i | grep -i mcp-session-id
```

### Direct curl

```sh
# REST
curl http://localhost:8080/repos/org/repo/pulls/123

# GraphQL query
curl -X POST http://localhost:8080/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query { repository(owner:\"org\", name:\"repo\") { stargazerCount }}"}'

# GraphQL mutation (requires your own auth)
curl -X POST http://localhost:8080/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ghp_your_token" \
  -d '{"query":"mutation { addStar(input:{starrableId:\"...\"}) { clientMutationId }}"}'
```

## License

MIT
