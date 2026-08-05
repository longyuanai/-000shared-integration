"""Private subprocess wrapper that keeps scan payloads out of OS arguments."""

from __future__ import annotations

import argparse
import json
import runpy
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--module", required=True)
    parser.add_argument("--input-file", required=True)
    parser.add_argument("--max-input-bytes", type=int, required=True)
    args = parser.parse_args()

    path = Path(args.input_file)
    if path.stat().st_size > args.max_input_bytes:
        raise SystemExit("integration payload exceeds configured limit")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit("integration payload must be a JSON object")

    sys.argv = [args.module, "--input", json.dumps(payload, ensure_ascii=False), "--json"]
    runpy.run_module(args.module, run_name="__main__")


if __name__ == "__main__":
    main()
