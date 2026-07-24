"""Make both src-layout sibling packages importable without installation."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = PROJECT_ROOT.parent / "000shared-llm-core"

sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(CORE_ROOT / "src"))
