# IntegrationGateway deployment

The v1 execution unit uses one OCI image with separate API and Celery Worker
commands. Build context remains the suite root because the adapters execute the
six sibling product CLIs.

## Production-style single-node deployment

Copy `.env.example` to `.env`, replace `POSTGRES_PASSWORD` with a random value
from a secret manager, and keep `INTEGRATION_AUTH_BACKEND=database`. Then run
from this repository:

```powershell
docker compose up --build -d
```

The API starts fail-closed: public health checks work, but protected routes
return `401` until a persistent key exists. Bootstrap the first tenant and key:

```powershell
docker compose run --rm gateway shared-integration-admin tenant-create `
  --tenant longyuan --slug longyuan --name "Longyuan"
docker compose run --rm gateway shared-integration-admin api-key-issue `
  --tenant longyuan --role admin --scope "gateway:*"
```

The second command returns the token once. Move it directly into the consuming
service's secret manager; PostgreSQL stores only its prefix and scrypt hash.

The Compose topology starts:

- `gateway`: FastAPI control plane on port 8080;
- `worker-fast`: short SOC-style jobs, concurrency 4;
- `worker-analysis`: vulnerability and code analysis, concurrency 2;
- `worker-sandbox`: lab, reverse, and firmware work, concurrency 1;
- `valkey`: Celery broker, result backend, and durable append-only queue state;
- `postgres`: durable tenant, Job, Finding, correlation, and audit storage;
- `migrate`: one-shot Alembic upgrade that must succeed before API/Workers start.

PostgreSQL is the production source of truth. SQLite remains available only as
a compatibility/local-development backend through `INTEGRATION_DB_PATH`.
Back up PostgreSQL before every migration or image rollback.

## Manual image build

Build from the suite root:

```powershell
docker build `
  -f .\000shared-integration\Dockerfile `
  -t longyuan/integration-gateway:0.8.0 `
  .
```

Run a local inline API without Celery only for development:

```powershell
$env:INTEGRATION_JOB_MODE = "inline"
$env:INTEGRATION_DATABASE_URL = "sqlite+pysqlite:///./gateway.sqlite3"
$env:INTEGRATION_AUTO_CREATE_SCHEMA = "true"
$env:INTEGRATION_AUTH_TOKENS = '{"local-development-token-at-least-32-bytes":{"tenant":"local","role":"admin"}}'
python -m shared_integration.gateway
```

## Platform requirements

Production hosting must provide:

- an HTTPS service URL and port injection through `PORT`;
- persistent PostgreSQL and Valkey volumes with tested backups;
- `INTEGRATION_AUTH_BACKEND=database` and persistent, rotated API keys;
- private Valkey access, never exposed to the public network;
- liveness probes against `/livez` and authenticated readiness probes against
  `/readyz`;
- no public exposure of Worker or product CLI processes;
- resource limits and stronger isolation for the `sandbox` queue.

Run migrations explicitly outside Compose with:

```powershell
$env:INTEGRATION_DATABASE_URL = "postgresql+psycopg://..."
alembic -c alembic.ini upgrade head
```

`INTEGRATION_AUTO_CREATE_SCHEMA` is only a test/development escape hatch and
must remain disabled in production.

## Legacy SQLite import

Stop writes to the old gateway and copy its SQLite database plus `-wal` file as
a backup. Mount that immutable copy into the admin container. The command is a
dry run unless `--apply` is present:

```powershell
docker compose run --rm -v "C:\backup:/import:ro" gateway `
  shared-integration-admin migrate-sqlite /import/gateway.sqlite3
docker compose run --rm -v "C:\backup:/import:ro" gateway `
  shared-integration-admin migrate-sqlite /import/gateway.sqlite3 --apply
```

The import is one transaction and is safe to rerun: existing jobs/events,
fingerprint-equivalent Findings, correlations, tenants, and migration audit
records are skipped. Keep the legacy database read-only until row counts and
tenant queries have been checked.

## PostgreSQL backup and restore drill

Create a custom-format backup without exposing the password on the command
line:

```powershell
New-Item -ItemType Directory -Force .\backups | Out-Null
docker compose exec -T postgres pg_dump -U integration -d integration `
  --format=custom --file=/tmp/integration.dump
docker compose cp postgres:/tmp/integration.dump .\backups\integration.dump
```

Verify it against a separate database; never test restore by overwriting the
live database:

```powershell
docker compose exec -T postgres createdb -U integration integration_restore_verify
docker compose cp .\backups\integration.dump postgres:/tmp/integration.dump
docker compose exec -T postgres pg_restore -U integration `
  --dbname=integration_restore_verify --exit-on-error /tmp/integration.dump
docker compose exec -T postgres psql -U integration `
  -d integration_restore_verify -c "SELECT count(*) FROM tenants;"
docker compose exec -T postgres dropdb -U integration integration_restore_verify
```

Record the backup checksum, schema revision, row counts, restore duration, and
drill date. Perform the drill before every schema release and at least monthly.

After deployment, set the dashboard's server-side `GATEWAY_URL` to the HTTPS
origin and use a server-side credential only. Never expose a token as a
`NEXT_PUBLIC_*` variable. Persistent machine API keys are available now. M3
will replace the shared Dashboard credential with OIDC/BFF user context backed
by Membership roles.
