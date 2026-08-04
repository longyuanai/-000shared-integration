# IntegrationGateway deployment

The production unit is one OCI image containing the gateway and the six product
CLIs. Build it from the suite root because the adapters execute those sibling
repositories as isolated subprocesses.

```powershell
docker build `
  -f .\000shared-integration\Dockerfile `
  -t longyuan/integration-gateway:0.6.0 `
  .
```

Create a token with at least 32 random bytes and configure it as a JSON mapping:

```json
{
  "replace-with-a-random-secret": {
    "tenant": "longyuan",
    "role": "admin"
  }
}
```

Run the image with a persistent volume:

```powershell
docker volume create longyuan-gateway-data
docker run --rm -p 8080:8080 `
  --name longyuan-integration-gateway `
  --read-only `
  --tmpfs /tmp `
  --security-opt no-new-privileges `
  --mount source=longyuan-gateway-data,target=/data `
  --env "INTEGRATION_AUTH_TOKENS=<JSON_FROM_SECRET_STORE>" `
  longyuan/integration-gateway:0.6.0
```

Production hosting must provide:

- an HTTPS service URL and port injection through `PORT`;
- a persistent volume mounted at `/data`;
- `INTEGRATION_AUTH_TOKENS` from its secret manager;
- health probes against `/v0.5/health`;
- no public exposure of the six product CLI processes.

After deployment, set the dashboard's server-side `GATEWAY_URL` to the HTTPS
origin and `GATEWAY_TOKEN` to a tenant token from the same mapping. Never expose
the token as a `NEXT_PUBLIC_*` variable.
