# IntegrationGateway deployment

The v1 execution unit uses one OCI image with separate API and Celery Worker
commands. Build context remains the suite root because the adapters execute the
six sibling product CLIs.

## Production-style single-node deployment

Copy `.env.example` to `.env`, replace `INTEGRATION_AUTH_TOKENS` with at least
32 random bytes from a secret manager, then run from this repository:

```powershell
docker compose up --build -d
```

The Compose topology starts:

- `gateway`: FastAPI control plane on port 8080;
- `worker-fast`: short SOC-style jobs, concurrency 4;
- `worker-analysis`: vulnerability and code analysis, concurrency 2;
- `worker-sandbox`: lab, reverse, and firmware work, concurrency 1;
- `valkey`: Celery broker, result backend, and durable append-only queue state.

API and workers share `/data/gateway.sqlite3` during M1. SQLite WAL and a busy
timeout make this suitable for a single-node transition, but M2 must migrate the
job and Finding repositories to PostgreSQL before horizontal scaling.

## Manual image build

Build from the suite root:

```powershell
docker build `
  -f .\000shared-integration\Dockerfile `
  -t longyuan/integration-gateway:0.7.0 `
  .
```

Run a local inline API without Celery only for development:

```powershell
$env:INTEGRATION_JOB_MODE = "inline"
$env:INTEGRATION_DB_PATH = ".\gateway.sqlite3"
$env:INTEGRATION_AUTH_TOKENS = '{"local-development-token-at-least-32-bytes":{"tenant":"local","role":"admin"}}'
python -m shared_integration.gateway
```

## Platform requirements

Production hosting must provide:

- an HTTPS service URL and port injection through `PORT`;
- persistent storage mounted at `/data` during M1;
- `INTEGRATION_AUTH_TOKENS` from its secret manager;
- private Valkey access, never exposed to the public network;
- liveness probes against `/livez` and authenticated readiness probes against
  `/readyz`;
- no public exposure of Worker or product CLI processes;
- resource limits and stronger isolation for the `sandbox` queue.

After deployment, set the dashboard's server-side `GATEWAY_URL` to the HTTPS
origin and use a server-side credential only. Never expose a token as a
`NEXT_PUBLIC_*` variable. The M3 identity migration will replace the shared
dashboard token with OIDC/BFF user context and scoped machine API keys.
