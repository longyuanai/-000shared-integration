# shared-integration

Integration gateway for the longyuanai AI Security Agent suite.

The service composes the six product CLIs behind the frozen
`shared-llm-core` v0.5 `IntegrationGateway` contract.

## Current capabilities

- six subprocess-isolated product adapters;
- tenant-scoped bearer authentication with `viewer`, `analyst`, and `admin` roles;
- tenant-isolated SQLite persistence for Findings and correlations;
- SSE updates isolated by tenant;
- an OCI image that packages the gateway and all six product CLIs.

## Local run

```powershell
$env:PYTHONPATH = "src;../000shared-llm-core/src"
$env:INTEGRATION_DB_PATH = ".\gateway.sqlite3"
$env:INTEGRATION_AUTH_TOKENS = '{"local-development-token-1234":{"tenant":"local","role":"admin"}}'
python -m shared_integration.gateway
```

The gateway listens on port `8080` and exposes:

- `GET /v0.5/health`
- `POST /v0.5/{source}/scan`
- `GET /v0.5/findings`
- `GET /v0.5/correlations`
- `GET /v0.5/stream`

Example health check:

```powershell
curl.exe -H "Authorization: Bearer local-development-token-1234" `
  http://localhost:8080/v0.5/findings
```

`GET /v0.5/health` remains unauthenticated for platform probes. Other routes
require a configured bearer token when `INTEGRATION_AUTH_TOKENS` is set.

## Container deployment

Build from the suite root:

```powershell
docker build -f .\000shared-integration\Dockerfile `
  -t longyuan/integration-gateway:0.6.0 .
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for volume, secret, and dashboard wiring.

## Test

```powershell
python -m pytest tests/ --basetemp=workspace/pytest-current -q -o addopts=
```
