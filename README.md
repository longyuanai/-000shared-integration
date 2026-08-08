# shared-integration

Integration gateway for the longyuanai AI Security Agent suite.

The service composes the six product CLIs behind the frozen
`shared-llm-core` v0.5 `IntegrationGateway` contract.

The researched v1.0 architecture, open-source project comparison, target data
model, API, RBAC, deployment topology, and M0–M5 implementation plan are in
[docs/architecture.md](docs/architecture.md).

## Current capabilities

- six subprocess-isolated product adapters;
- persistent, scrypt-hashed API keys with tenant status, expiry, revocation,
  scopes, and `viewer`/`analyst`/`admin` roles;
- separately hashed identity bridge clients plus five-minute opaque user sessions;
- BFF identity exchange, self/bridge session revocation, per-request Membership
  revalidation, request IDs, generic auth errors, and exchange rate limiting;
- Tenant/User/Membership persistence plus a bootstrap and migration CLI;
- PostgreSQL/SQLAlchemy persistence with Alembic migrations and explicit tenant keys;
- Finding fingerprint deduplication, lifecycle status, assignment, audit, and cursor paging;
- SSE updates isolated by tenant;
- `/v1` persisted scan jobs with idempotency, cancellation, events, and adapter capabilities;
- Celery/Valkey routing across `fast`, `analysis`, and `sandbox` worker queues;
- per-adapter timeout, concurrency, input/output limits, and payload-file isolation;
- an OCI image that packages the gateway and all six product CLIs.

## Local run

```powershell
$env:PYTHONPATH = "src;../000shared-llm-core/src"
$env:INTEGRATION_DATABASE_URL = "sqlite+pysqlite:///./gateway.sqlite3"
$env:INTEGRATION_AUTO_CREATE_SCHEMA = "true" # local development only
$env:INTEGRATION_AUTH_TOKENS = '{"local-development-token-1234":{"tenant":"local","role":"admin"}}'
python -m shared_integration.gateway
```

The gateway listens on port `8080` and exposes:

- `GET /v0.5/health`
- `POST /v0.5/{source}/scan`
- `GET /v0.5/findings`

- `GET /v0.5/correlations`
- `GET /v0.5/stream`
- `POST /v1/scans`
- `GET /v1/scans/{job_id}`
- `POST /v1/scans/{job_id}/cancel`
- `GET /v1/scans/{job_id}/events`
- `GET /v1/findings`
- `PATCH /v1/findings/{finding_id}`
- `GET /v1/adapters`
- `POST /v1/auth/exchange`
- `POST /v1/auth/session/revoke`
- `GET /livez` and authenticated `GET /readyz`

### Real browser RBAC fixture

`docker-compose.rbac-e2e.yml` is an isolated test-only stack used by the Web
Dashboard's `npm run test:e2e:rbac` gate. It creates ephemeral PostgreSQL and
Valkey storage, applies Alembic migrations, and mounts the current Integration
source read-only. Fixture tenants, users, identity clients, sessions, jobs, and
findings all use an `e2e-rbac` run label and are deleted after every browser
round; the Compose project is then removed with its temporary storage.

The bridge credential is captured by the test orchestrator and redacted from
logs. Do not reuse this Compose file, its generated identities, or its local
development cookie mode for deployment.

Production migration, identity-client rotation, rollback, session cleanup, and
troubleshooting are documented in
[`docs/m3-auth-rollout-rollback.md`](docs/m3-auth-rollout-rollback.md).

Example health check:

```powershell
curl.exe -H "Authorization: Bearer local-development-token-1234" `
  http://localhost:8080/v0.5/findings
```

`GET /v0.5/health` remains unauthenticated for platform probes. Other routes
require a configured bearer token when `INTEGRATION_AUTH_TOKENS` is set.

Production uses `INTEGRATION_AUTH_BACKEND=database`. After applying Alembic
migrations, bootstrap the first tenant and key (the key is printed only once):

```powershell
$env:INTEGRATION_DATABASE_URL = "postgresql+psycopg://integration:...@localhost/integration"
shared-integration-admin tenant-create --tenant longyuan --slug longyuan --name "Longyuan"
shared-integration-admin api-key-issue --tenant longyuan --role admin --scope "gateway:*"
```

`INTEGRATION_AUTH_BACKEND=hybrid` accepts both persistent keys and the legacy
`INTEGRATION_AUTH_TOKENS`; use it only as a rotation bridge. See
[DEPLOYMENT.md](DEPLOYMENT.md) for SQLite migration and backup/restore steps.

`INTEGRATION_AUTH_EXCHANGE_RATE_LIMIT` defaults to 20 attempts per
`INTEGRATION_AUTH_EXCHANGE_RATE_WINDOW_SECONDS` (default 60). The limiter keys on
the non-secret bridge prefix and client address; multi-instance production must
place an equivalent shared edge limit in front of the Gateway.

## Container deployment

Build from the suite root:

```powershell
docker build -f .\000shared-integration\Dockerfile `
  -t longyuan/integration-gateway:0.8.0 .
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for volume, secret, and dashboard wiring.

## Test

```powershell
python -m pytest tests/ --basetemp=workspace/pytest-current -q -o addopts=
```
