"""003 AI Agent Security Lab subprocess adapter."""

from shared_llm_core import FindingSource

from shared_integration.adapters.base import JSONSubprocessAdapter


class LabAdapter(JSONSubprocessAdapter):
    """Invoke ``ai_agent_lab.cli`` without importing product internals."""

    source = FindingSource.LAB
    module = "ai_agent_lab.cli"
    product_id = "003-lab"
