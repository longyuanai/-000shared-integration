# shared-integration

Integration gateway for the longyuanai AI Security Agent suite.

The service composes the six product CLIs behind the frozen
`shared-llm-core` v0.5 `IntegrationGateway` contract.

## Requirements

- Python 3.11+
- The sibling `../000shared-llm-core` repository

## Run

```powershell
$env:PYTHONPATH = "src;../000shared-llm-core/src"
C:\Users\15072\AppData\Local\Programs\Python\Python314\python.exe -m shared_integration.gateway
```

The gateway listens on port `8080` and exposes:

- `GET /v0.5/health`
- `POST /v0.5/{source}/scan`
- `GET /v0.5/findings`
- `GET /v0.5/correlations`
- `GET /v0.5/stream`

Example health check:

```powershell
curl.exe http://localhost:8080/v0.5/health
```

## Test

```powershell
python -m pytest tests/ --basetemp=C:/pytest-tmp/shared-integration -q --tb=no -o addopts=
```
