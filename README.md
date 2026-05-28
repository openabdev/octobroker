# ghpool

A secure, cloud-native GitHub API proxy that pools PATs for rate limit sharing, caches read responses, and passes through mutations — built for coding agents running in private networks.

## Design Principles

- **Cloud-native** — runs on any Kubernetes (Amazon EKS, Google Cloud GKE, self-managed k8s) and Amazon ECS. Single static binary, no runtime dependencies.
- **Built for agents, not humans** — optimized for high-throughput, concurrent API access from multiple coding agents sharing the same repos.
- **Secrets-first** — credentials are resolved at runtime from AWS Secrets Manager, Google Cloud Secret Manager, or Kubernetes secrets. No plain text tokens stored at rest or in transit.
- **Private network isolation** — designed to run inside your trusted network (on-premises, cloud VPC, or service mesh). No public endpoints, no external dependencies beyond GitHub API.

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
│            ┌───────────────────┐                                    │
│            │      ghpool       │                                    │
│            │                   │                                    │
│            │  ┌─────────────┐  │      ┌──────────────────────┐      │
│            │  │  PAT Pool   │  │      │  Secrets Manager     │      │
│            │  │             │◄─┼──────│  (AWS/K8s/Env)       │      │
│            │  │ chaodu: 4998│  │      └──────────────────────┘      │
│            │  │ thepagent:  │  │                                    │
│            │  │         1889│  │                                    │
│            │  └─────────────┘  │                                    │
│            │  ┌─────────────┐  │                                    │
│            │  │    Cache    │  │                                    │
│            │  │  (in-mem)   │  │                                    │
│            │  └─────────────┘  │                                    │
│            └────────┬──────────┘                                    │
│                     │                                               │
└─────────────────────┼───────────────────────────────────────────────┘
                      │
                      ▼
            ┌───────────────────┐
            │  api.github.com   │
            └───────────────────┘

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
```

## What it does

- Pools multiple GitHub PATs and routes each read request through the identity with the most remaining rate limit budget
- Caches GitHub REST and GraphQL query responses in memory with configurable TTLs
- Proxies GraphQL mutations with passthrough auth (client's own token, no caching)
- Mirrors the GitHub API path structure — clients just change the base URL
- Restricts access to configured org/owner repos only
- Auto-resolves GitHub username from tokens for audit logging

## Quick start

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

Set `GHPOOL_CONFIG` env var to point to your config file (defaults to `config.toml`).

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
aws secretsmanager create-secret --name ghpool/pats \
  --secret-string '{"pat_alice":"ghp_xxx","pat_bob":"ghp_yyy"}'
```

```toml
[[identities]]
id = "alice"
token = "aws:secretsmanager:ghpool/pats:pat_alice"
```

ghpool uses the standard AWS credential chain (instance profile, ECS task role, SSO, env vars).

#### Google Cloud Secret Manager (planned)

```toml
[[identities]]
id = "alice"
token = "gcp:secretmanager:projects/my-proj/secrets/ghpool-pat:latest"
```

GCP support is on the roadmap. Contributions welcome.

#### Kubernetes Secrets

Mount your secret as a volume at `/etc/secrets/` and reference it:

```yaml
# K8s Secret
apiVersion: v1
kind: Secret
metadata:
  name: ghpool-pats
  namespace: default
stringData:
  pat_alice: ghp_xxx
```

```toml
[[identities]]
id = "alice"
token = "k8s:default/ghpool-pats:pat_alice"
```

Works with any Kubernetes distribution — EKS, GKE, AKS, k3s, or self-managed.

### Environment variables only

```sh
export GHPOOL_PORT=8080
export GHPOOL_ALLOWED_OWNERS=openclaw,openabdev
export GHPOOL_PAT_ALICE=ghp_xxx
export GHPOOL_PAT_BOB=ghp_yyy
```

PATs are discovered from any env var matching `GHPOOL_PAT_<ID>=<token>`.

## Deployment

### Docker

```sh
docker build -t ghpool .
docker run -p 8080:8080 -v ./config.toml:/config.toml ghpool
```

### ECS (Service Connect)

Deploy as a service in your ECS cluster with Cloud Map namespace. Other services access it via:
```
http://ghpool.<namespace>:8080/repos/owner/repo/pulls/123
```

### Kubernetes

Deploy as a ClusterIP Service. Other pods access it via:
```
http://ghpool.<namespace>.svc.cluster.local:8080/repos/owner/repo/pulls/123
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

If a mutation request has no `Authorization` header, ghpool returns `401`.

```
  ┌────────────────────────────────────────────────────────────────┐
  │                    POST /graphql                                │
  │                                                                │
  │  Parse request body → extract "query" field                    │
  │                                                                │
  │  ┌─────────────────────┐       ┌────────────────────────────┐  │
  │  │ starts with "query" │       │ starts with "mutation"     │  │
  │  └──────────┬──────────┘       └──────────────┬─────────────┘  │
  │             │                                  │                │
  │             ▼                                  ▼                │
  │  ┌─────────────────────┐       ┌────────────────────────────┐  │
  │  │ Check cache         │       │ Require client             │  │
  │  │  HIT → return       │       │ Authorization header       │  │
  │  │  MISS ↓             │       │  missing → 401             │  │
  │  └──────────┬──────────┘       └──────────────┬─────────────┘  │
  │             │                                  │                │
  │             ▼                                  ▼                │
  │  ┌─────────────────────┐       ┌────────────────────────────┐  │
  │  │ Select pooled PAT   │       │ Passthrough client's token │  │
  │  │ (highest budget)    │       │ (identity preserved)       │  │
  │  └──────────┬──────────┘       └──────────────┬─────────────┘  │
  │             │                                  │                │
  │             ▼                                  ▼                │
  │  ┌─────────────────────┐       ┌────────────────────────────┐  │
  │  │ Forward to GitHub   │       │ Forward to GitHub           │  │
  │  │ Cache response      │       │ No caching                 │  │
  │  │ Update rate limits  │       │ Log resolved username      │  │
  │  └─────────────────────┘       └────────────────────────────┘  │
  └────────────────────────────────────────────────────────────────┘
```

### Management

| Path | Description |
|------|-------------|
| `GET /healthz` | Health check |
| `GET /stats` | Pool and cache statistics |

## How clients use it

### gh CLI

```sh
export GITHUB_API_URL=http://localhost:8080
export GITHUB_GRAPHQL_URL=http://localhost:8080/graphql
```

All `gh` commands work transparently — reads are pooled+cached, writes use your own auth.

### Coding agents

Set the GitHub API base URL to point at ghpool:

```sh
export GITHUB_API_BASE=http://localhost:8080
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
