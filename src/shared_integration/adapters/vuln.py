"""002 AI-Vulnerability-Agent subprocess adapter."""

from shared_llm_core import FindingSource

from shared_integration.adapters.base import JSONSubprocessAdapter


class VulnAdapter(JSONSubprocessAdapter):
    """Invoke ``ai_vuln_agent.cli`` without importing product internals."""

    source = FindingSource.VULN
    module = "ai_vuln_agent.cli"
    product_id = "002-vuln"
    queue = "analysis"
    default_timeout_seconds = 180.0
