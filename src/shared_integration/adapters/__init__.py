"""Product CLI adapters."""

from shared_integration.adapters.base import (
    AdapterCapabilities,
    ProductAdapter,
    ProductCLIError,
    ProductOutputLimitError,
    ProductTimeoutError,
    ProductUnavailableError,
)
from shared_integration.adapters.code import CodeAdapter
from shared_integration.adapters.firmware import FirmwareAdapter
from shared_integration.adapters.lab import LabAdapter
from shared_integration.adapters.reverse import ReverseAdapter
from shared_integration.adapters.soc import SOCAdapter
from shared_integration.adapters.vuln import VulnAdapter

__all__ = [
    "AdapterCapabilities",
    "CodeAdapter",
    "FirmwareAdapter",
    "LabAdapter",
    "ProductAdapter",
    "ProductCLIError",
    "ProductOutputLimitError",
    "ProductTimeoutError",
    "ProductUnavailableError",
    "ReverseAdapter",
    "SOCAdapter",
    "VulnAdapter",
]
