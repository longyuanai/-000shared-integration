"""004 AI-CodeGuard subprocess adapter."""

from shared_llm_core import FindingSource

from shared_integration.adapters.base import JSONSubprocessAdapter


class CodeAdapter(JSONSubprocessAdapter):
    """Invoke ``codeguard.cli`` without importing product internals."""

    source = FindingSource.CODE
    module = "codeguard.cli"
    product_id = "004-code"
    queue = "analysis"
    default_timeout_seconds = 300.0
