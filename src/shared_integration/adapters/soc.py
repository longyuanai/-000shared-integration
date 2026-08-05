"""001 AI-SOC-Agent subprocess adapter."""

from shared_llm_core import FindingSource

from shared_integration.adapters.base import JSONSubprocessAdapter


class SOCAdapter(JSONSubprocessAdapter):
    """Invoke ``ai_soc_agent.cli`` without importing product internals."""

    source = FindingSource.SOC
    module = "ai_soc_agent.cli"
    product_id = "001-soc"
    queue = "fast"
    default_timeout_seconds = 60.0
    default_max_concurrency = 4
