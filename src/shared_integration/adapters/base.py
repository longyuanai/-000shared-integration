"""Subprocess-isolated product adapter primitives."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, AsyncIterator, ClassVar

from shared_llm_core import Finding, FindingSource
from shared_llm_core import ProductAdapter as CoreProductAdapter


class ProductCLIError(RuntimeError):
    """Raised when a product CLI exits unsuccessfully or emits invalid JSON."""


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


class JSONSubprocessAdapter(ProductAdapter):
    """Shared implementation for product CLIs that emit a Finding JSON envelope."""

    module: ClassVar[str]
    product_id: ClassVar[str]

    def __init__(self, cli_path: Path) -> None:
        self._cli = cli_path.resolve()

    async def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        env = os.environ.copy()
        product_src = str(self._cli / "src")
        current_pythonpath = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (
            os.pathsep.join((product_src, current_pythonpath))
            if current_pythonpath
            else product_src
        )
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            self.module,
            "--input",
            json.dumps(payload, ensure_ascii=False),
            "--json",
            cwd=str(self._cli),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace").strip()
            raise ProductCLIError(
                f"{self.product_id} CLI exited with {proc.returncode}: {detail}"
            )
        try:
            decoded = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProductCLIError(f"{self.product_id} CLI emitted invalid JSON") from exc

        items = decoded if isinstance(decoded, list) else decoded.get("findings", [])
        if not isinstance(items, list):
            raise ProductCLIError(f"{self.product_id} CLI 'findings' must be a list")

        for item in items:
            if not isinstance(item, dict):
                raise ProductCLIError(f"{self.product_id} CLI finding must be an object")
            normalized = {
                **item,
                "id": item.get("id", ""),
                "source": self.source.value,
                "severity": item.get("severity", "medium"),
                "confidence": item.get("confidence", 0.5),
                "title": item.get("title", "Untitled finding"),
            }
            yield Finding.from_dict(normalized)

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "source": self.product_id,
            "available": self._cli.is_dir(),
            "path": str(self._cli),
        }
