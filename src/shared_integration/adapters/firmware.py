"""006 AI Firmware Security Agent subprocess adapter."""

from shared_llm_core import FindingSource

from shared_integration.adapters.base import JSONSubprocessAdapter


class FirmwareAdapter(JSONSubprocessAdapter):
    """Invoke ``ai_firmware_agent.cli`` without importing product internals."""

    source = FindingSource.FIRMWARE
    module = "ai_firmware_agent.cli"
    product_id = "006-firmware"
