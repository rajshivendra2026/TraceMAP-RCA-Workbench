#!/usr/bin/env python
"""TraceMAP production preflight.

Checks the local runtime before analysts upload PCAPs. This intentionally
matches the dashboard Release Health panel so CLI and UI tell the same story.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / ".cache" / "matplotlib"))

from src.app.health import build_system_health  # noqa: E402
from src.config import cfg_path  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TraceMAP production-readiness preflight checks.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as failures.")
    args = parser.parse_args()

    health = build_system_health(model_status=_load_model_status())
    if args.json:
        print(json.dumps(health, indent=2))
    else:
        _print_human(health)

    if health["status"] == "fail":
        return 1
    if args.strict and health["status"] == "warn":
        return 1
    return 0


def _print_human(health: dict) -> None:
    release = health.get("release", {})
    print("TraceMAP Production Preflight")
    print("=" * 34)
    print(f"Version : {release.get('version', 'unknown')}")
    print(f"Branch  : {release.get('branch', 'unknown')}")
    print(f"Commit  : {release.get('commit', 'unknown')}")
    print(f"Status  : {health.get('status', 'unknown').upper()} ({health.get('score', 0)}/100)")
    print()
    for check in health.get("checks", []):
        status = str(check.get("status", "unknown")).upper()
        print(f"[{status:4}] {check.get('label', 'Check')}: {check.get('summary', '')}")
        detail = check.get("detail")
        if detail:
            print(f"       {detail}")
    actions = health.get("actions") or []
    if actions:
        print()
        print("Recommended actions:")
        for action in actions:
            print(f"- {action}")


def _load_model_status() -> dict:
    model_path = Path(cfg_path("model.path", "data/models/rca_model.pkl"))
    encoder_path = Path(cfg_path("model.encoder_path", "data/models/label_encoder.pkl"))
    return {
        "trained": model_path.exists() and encoder_path.exists(),
        "model_path": str(model_path),
        "encoder_path": str(encoder_path),
    }


if __name__ == "__main__":
    raise SystemExit(main())
