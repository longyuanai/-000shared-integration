"""005 AI Reverse Agent subprocess adapter."""

from shared_llm_core import FindingSource

from shared_integration.adapters.base import JSONSubprocessAdapter


class ReverseAdapter(JSONSubprocessAdapter):
    """Invoke ``ai_reverse_agent.cli`` without importing product internals."""

    source = FindingSource.REVERSE
    module = "ai_reverse_agent.cli"
    product_id = "005-reverse"
