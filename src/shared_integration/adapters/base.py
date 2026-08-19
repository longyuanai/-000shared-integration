"""Subprocess-isolated product adapter primitives."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Literal

from shared_llm_core import Finding, FindingSource
from shared_llm_core import ProductAdapter as CoreProductAdapter
from shared_llm_core.telemetry import span, trace_context_environment

AdapterQueue = Literal["fast", "analysis", "sandbox"]


@dataclass(frozen=True)
class AdapterCapabilities:
    source: FindingSource
    product_id: str
    version: str
    queue: AdapterQueue
    timeout_seconds: float
    max_concurrency: int
    max_input_bytes: int
    max_output_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.value,
            "product_id": self.product_id,
            "version": self.version,
            "queue": self.queue,
            "timeout_seconds": self.timeout_seconds,
            "max_concurrency": self.max_concurrency,
            "max_input_bytes": self.max_input_bytes,
            "max_output_bytes": self.max_output_bytes,
        }


class ProductCLIError(RuntimeError):
    """Raised when a product CLI exits unsuccessfully or emits invalid JSON."""

    code = "PRODUCT_CLI_ERROR"
    retryable = False


class ProductTimeoutError(ProductCLIError):
    code = "ADAPTER_TIMEOUT"
    retryable = True


class ProductOutputLimitError(ProductCLIError):
    code = "ADAPTER_OUTPUT_LIMIT"


class ProductUnavailableError(ProductCLIError):
    code = "ADAPTER_UNAVAILABLE"
    retryable = True


class ProductAdapter(CoreProductAdapter, ABC):
    """Local adapter contract backed by shared-llm-core's v0.5 ABC."""

    source: FindingSource

    @abstractmethod
    async def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        """Run a product CLI in a subprocess and yield normalized findings."""
        if False:  # pragma: no cover - makes this an async generator contract
            yield

    @abstractmethod
    def health(self) -> dict[str, Any]:
        """Return the adapter health state."""

    @abstractmethod
    def capabilities(self) -> AdapterCapabilities:
        """Describe execution limits and routing without running the product."""


class JSONSubprocessAdapter(ProductAdapter):
    """Shared implementation for product CLIs that emit a Finding JSON envelope."""

    module: ClassVar[str]
    product_id: ClassVar[str]
    version: ClassVar[str] = "0.6.0"
    queue: ClassVar[AdapterQueue] = "analysis"
    default_timeout_seconds: ClassVar[float] = 300.0
    default_max_concurrency: ClassVar[int] = 2
    default_max_input_bytes: ClassVar[int] = 1_048_576
    default_max_output_bytes: ClassVar[int] = 10_485_760

    def __init__(
        self,
        cli_path: Path,
        *,
        timeout_seconds: float | None = None,
        max_concurrency: int | None = None,
        max_input_bytes: int | None = None,
        max_output_bytes: int | None = None,
    ) -> None:
        self._cli = cli_path.resolve()
        self._timeout_seconds = (
            self.default_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        self._max_concurrency = (
            self.default_max_concurrency
            if max_concurrency is None
            else max_concurrency
        )
        self._max_input_bytes = max_input_bytes or self.default_max_input_bytes
        self._max_output_bytes = max_output_bytes or self.default_max_output_bytes
        if self._timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self._max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        self._semaphore = asyncio.Semaphore(self._max_concurrency)

    async def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        with span(
            "gateway.product_cli",
            attributes={"gateway.product_id": self.product_id},
        ) as product_span:
            started = time.perf_counter()
            try:
                if not self._cli.is_dir():
                    raise ProductUnavailableError(
                        f"{self.product_id} CLI directory is unavailable"
                    )

                payload_path = self._write_payload(payload)
                try:
                    async with self._semaphore:
                        decoded = await self._execute(payload_path)
                finally:
                    payload_path.unlink(missing_ok=True)

                items = decoded if isinstance(decoded, list) else decoded.get("findings", [])
                if not isinstance(items, list):
                    raise ProductCLIError(
                        f"{self.product_id} CLI 'findings' must be a list"
                    )

                for item in items:
                    if not isinstance(item, dict):
                        raise ProductCLIError(
                            f"{self.product_id} CLI finding must be an object"
                        )
                    normalized = {
                        **item,
                        "id": item.get("id", ""),
                        "source": self.source.value,
                        "severity": item.get("severity", "medium"),
                        "confidence": item.get("confidence", 0.5),
                        "title": item.get("title", "Untitled finding"),
                    }
                    yield Finding.from_dict(normalized)
            except BaseException:
                product_span.set_attribute("gateway.status", "error")
                raise
            else:
                product_span.set_attribute("gateway.status", "ok")
            finally:
                product_span.set_attribute(
                    "gateway.latency_ms",
                    int((time.perf_counter() - started) * 1000),
                )

    async def _execute(self, payload_path: Path) -> list[Any] | dict[str, Any]:
        env = os.environ.copy()
        product_src = str(self._cli / "src")
        current_pythonpath = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (
            os.pathsep.join((product_src, current_pythonpath))
            if current_pythonpath
            else product_src
        )
        env.update(trace_context_environment())
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "shared_integration.adapters.worker",
                "--module",
                self.module,
                "--input-file",
                str(payload_path),
                "--max-input-bytes",
                str(self._max_input_bytes),
                cwd=str(self._cli),
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise ProductUnavailableError(
                f"{self.product_id} CLI could not be started"
            ) from exc

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._timeout_seconds
            )
        except TimeoutError as exc:
            await _stop_process(proc)
            raise ProductTimeoutError(
                f"{self.product_id} CLI exceeded {self._timeout_seconds:g}s"
            ) from exc
        except asyncio.CancelledError:
            await _stop_process(proc)
            raise

        if len(stdout) > self._max_output_bytes:
            raise ProductOutputLimitError(
                f"{self.product_id} CLI output exceeded {self._max_output_bytes} bytes"
            )
        if proc.returncode != 0:
            detail = stderr[:65_536].decode("utf-8", errors="replace").strip()
            raise ProductCLIError(
                f"{self.product_id} CLI exited with {proc.returncode}: {detail}"
            )
        try:
            decoded = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProductCLIError(f"{self.product_id} CLI emitted invalid JSON") from exc
        if not isinstance(decoded, (dict, list)):
            raise ProductCLIError(f"{self.product_id} CLI output must be an object or list")
        return decoded

    def health(self) -> dict[str, Any]:
        available = self._cli.is_dir()
        return {
            "status": "ok" if available else "degraded",
            "source": self.product_id,
            "available": available,
            "queue": self.queue,
        }

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            source=self.source,
            product_id=self.product_id,
            version=self.version,
            queue=self.queue,
            timeout_seconds=self._timeout_seconds,
            max_concurrency=self._max_concurrency,
            max_input_bytes=self._max_input_bytes,
            max_output_bytes=self._max_output_bytes,
        )

    def _write_payload(self, payload: dict[str, Any]) -> Path:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        if len(encoded) > self._max_input_bytes:
            raise ProductCLIError(
                f"{self.product_id} input exceeded {self._max_input_bytes} bytes"
            )
        temporary_root = os.getenv("INTEGRATION_TMP_DIR")
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix="integration-input-",
            suffix=".json",
            dir=temporary_root,
            delete=False,
        ) as stream:
            stream.write(encoded)
            path = Path(stream.name)
        try:
            path.chmod(0o600)
        except OSError:  # pragma: no cover - platform-specific permission support
            pass
        return path


async def _stop_process(proc: Any) -> None:
    """Terminate a subprocess and escalate to kill after a short grace period."""
    if getattr(proc, "returncode", None) is not None:
        return
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except TimeoutError:
        proc.kill()
        await proc.wait()


__all__ = [
    "AdapterCapabilities",
    "ProductAdapter",
    "ProductCLIError",
    "ProductOutputLimitError",
    "ProductTimeoutError",
    "ProductUnavailableError",
]
