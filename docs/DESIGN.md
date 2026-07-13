# ghpool Design

> Living distillation of [RFC #15](https://github.com/openabdev/ghpool/issues/15)
> (Revision 2) and the [Phase 0 spike findings](https://github.com/openabdev/ghpool/issues/22),
> as actually shipped. For onboarding, see [getting-started.md](getting-started.md).

## Problem

AI coding agents need GitHub access. Every conventional approach puts a
GitHub credential inside the agent's environment:

| Approach | Weakness |
|----------|----------|
| PAT in the container | Long-lived, exfiltratable, org-wide blast radius, attribution collapses to the PAT owner |
| Token vending machine | Agent still holds a live token for its lifetime; misusable within scope |
| Per-agent fine-grained PATs | Management burden; still long-lived; single-org |

ghpool's position: **the agent never holds any GitHub credential.** It holds
at most a ghpool API key — revocable centrally, bounded by policy, useless
against GitHub directly.

## Architecture

ghpool is a **credential-swapping reverse proxy with a default-deny policy
engine**, sitting between agents and two GitHub surfaces:

- **MCP** (`/mcp`) → GitHub's hosted MCP server (`api.githubcopilot.com/mcp/`).
  ghpool proxies the official tool schemas verbatim — it defines no tools of
  its own (the Revision 1→2 pivot). Zero schema maintenance; new upstream
  tools appear automatically but are **denied by default** until granted.
- **REST/GraphQL** (`/{path}`, `/graphql`) → `api.github.com`, with PAT
  pooling (budget-aware selection) and in-memory read caching. GraphQL
  mutations pass through with the client's own token (full attribution).

### Request path (MCP)

```
agent → [authn: X-Ghpool-Key] → [session binding] → [tool allowlist]
      → [write classification] → [repo allowlist (deny-if-unresolvable)]
      → [in-flight cap] → [fail-closed audit] → forward with scoped token
      → [buffer+parse write outcomes] → audit result
```

Every layer is independent; a request must clear all of them.

## Credential model

**GitHub App installation tokens are the primary credential** (the PAT pool
remains for REST reads and legacy setups). Decided in Phase 0 after the
PAT-pooling compliance concern (GitHub ToS §H rate-limit aggregation) was
raised in review:

- Minted by ghpool from the App private key (RS256 JWT → installation
  token), cached, auto-refreshed 5 minutes before the 1-hour expiry.
- **Scoped at mint**: an agent whose repo allowlist is exact entries under
  one owner gets tokens minted with the API's `repositories` parameter —
  GitHub itself enforces the repo boundary, independent of ghpool's
  argument parsing (which remains as defense-in-depth). One credential per
  policy envelope.
- **Writes never run on PATs** — enforced by startup validation, not
  convention.

## Session model

Sessions (`Mcp-Session-Id`) are pinned to `(credential, agent)` at
`initialize`:

- Identity never rotates mid-session; an unknown/expired session gets 404
  (per MCP spec) and the client re-initializes transparently.
- A session presented by a different agent — even with a valid key — gets
  403 (binding violation).
- A session cannot outlive its credential: expired App-token pins terminate
  the session. Provider refreshes don't disturb in-flight sessions.
- **ghpool's pin cache is the sole session authority.** Phase 0 measured the
  hosted endpoint's own session semantics as fail-open: upstream DELETE is a
  no-op (the session remains usable), and unknown sessions get 400 not 404.
  Nothing about session validity is delegated upstream.
- Pins are in-process memory → single replica while MCP is enabled; config
  change = restart = all sessions revoked (the current revocation story).

## Policy model

Per-agent, default-deny, enforced at the proxy and mirrored upstream:

```toml
[[mcp.agents]]
id    = "my-bot"
keys  = ["env:KEY_CURRENT", "env:KEY_NEXT"]   # rotation: both valid
tools = ["issue_read", "create_issue"]        # exact names, default-deny
repos = ["my-org/repo-a", "my-org/*"]         # exact or owner wildcard
```

- The tool allowlist is injected upstream as **`X-MCP-Tools`** (exact
  per-tool filtering, discovered and verified in Phase 0). We deliberately
  do NOT use `X-MCP-Toolsets` for enforcement: Phase 0 found invalid
  toolset names are silently ignored — fail-open.
- All client-supplied `X-MCP-*` headers are stripped; the upstream header
  set is built from scratch (a client cannot widen its own permissions).
- Repo authorization is deny-if-unresolvable: a repo-restricted agent's
  call whose arguments name no repository is rejected.
- Write classification is rule-based and conservative: only
  `get_*`/`list_*`/`search_*`/`*_read` names are reads; **everything else,
  including unknown names, is a write**.

## Write gate

`enable_writes = true` requires — validated at boot, or the process refuses
to start:

1. `[[mcp.agents]]` (writes never exist in network-trust mode)
2. `[mcp.github_app]` (writes never run on PATs)
3. `[mcp.audit]` (writes are never unaudited)

The audit trail is **fail-closed**: a pre-flight JSONL record is fsync'd
before the call is forwarded; if it cannot be persisted, the write is
rejected (503) without side effects. The result record captures the **MCP
tool outcome** — `result.isError` arrives inside HTTP 200/SSE, so transport
status alone is never treated as success. Argument values are never logged
(key names + resolved repo only). ghpool never auto-retries a forwarded
call; ambiguous outcomes are recorded as undeterminable and surfaced to the
caller.

## Known constraints & non-goals

- **Single replica** (MCP): session pins are in-process. Horizontal scaling
  (shared session state) is Phase 3 (#18).
- **No rate-limit headers on the hosted MCP endpoint** (Phase 0 finding) —
  budget accounting stays REST-driven; per-agent quotas are Phase 3.
- **GitHub-side write attribution is the App identity**, not the individual
  agent. The ghpool audit log is the per-agent ledger; GraphQL mutation
  passthrough remains the right path when GitHub-side per-human attribution
  matters.
- **Contract-drift risk**: the hosted MCP surface (tool names, headers like
  `X-MCP-Tools`) is partially undocumented. A daily e2e canary exercises
  the full flow — including real App-token minting — against the live
  endpoint.
- Phase 3 (#18): SigV4/STS secretless agent auth via a stdio shim,
  horizontal scaling, quotas/circuit-breaking, cache authorization.

## Decision log

| Decision | Where | Why |
|----------|-------|-----|
| Proxy official schemas, define no tools | RFC Rev 1 | Zero schema maintenance; GitHub owns the surface |
| GitHub App primary, PAT pool legacy | RFC Rev 2 / #22 | ToS compliance, short-lived creds, scoped mint |
| `X-MCP-Tools` not `X-MCP-Toolsets` | #22 finding F | Toolsets fail open on invalid names |
| ghpool is session authority | #22 finding I | Upstream DELETE is a no-op |
| 404 on unknown session, never rotate identity | #20 review | MCP spec; no silent actor switching |
| Buffer + parse write responses | #17 review | `isError` inside HTTP 200; audit must record tool outcome |
| Scoped installation tokens per policy envelope | #17 review | GitHub enforces the repo boundary, not just our parser |
| Writes: App + audit + agents required in code | #17 review | Hard rules, not documented hopes |
