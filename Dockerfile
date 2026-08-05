FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    INTEGRATION_DB_PATH=/data/gateway.sqlite3 \
    INTEGRATION_AUTH_REQUIRED=true \
    PORT=8080

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin gateway \
    && mkdir -p /suite /data \
    && chown gateway:gateway /data

WORKDIR /suite

COPY ["000shared-llm-core/", "/suite/000shared-llm-core/"]
COPY ["000shared-integration/", "/suite/000shared-integration/"]
COPY ["001AI-SOC-Agent/", "/suite/001AI-SOC-Agent/"]
COPY ["002AI-Vulnerability-Agent/", "/suite/002AI-Vulnerability-Agent/"]
COPY ["003AI Agent安全靶场/", "/suite/003AI Agent安全靶场/"]
COPY ["004AI代码审计/", "/suite/004AI-Code-Audit/"]
COPY ["005AI逆向Agent/", "/suite/005AI-Reverse-Agent/"]
COPY ["006AI-Firmware-Security-Agent/", "/suite/006AI-Firmware-Security-Agent/"]

RUN python -m pip install --no-cache-dir \
    /suite/000shared-llm-core \
    /suite/000shared-integration \
    /suite/001AI-SOC-Agent \
    /suite/002AI-Vulnerability-Agent \
    "/suite/003AI Agent安全靶场" \
    /suite/004AI-Code-Audit/004AI-CodeGuard-upgrade \
    /suite/005AI-Reverse-Agent \
    /suite/006AI-Firmware-Security-Agent

WORKDIR /suite/000shared-integration
USER gateway

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/livez', timeout=3)"

CMD ["python", "-m", "shared_integration.gateway"]
