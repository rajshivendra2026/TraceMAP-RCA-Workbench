"""Cross-trace time-series intelligence for recurring RCA patterns."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from src.config import cfg_path


class TimeSeriesIntelligenceEngine:
    """Tracks recurring failures and periodic anomalies across traces."""

    def __init__(self, base_dir: str | None = None):
        self.base_dir = Path(base_dir or cfg_path("data.knowledge_base", "data/knowledge_base"))
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.base_dir / "timeseries_intelligence.json"
        self.state = self._load()

    def record_session(self, session: dict, final_rca: dict) -> dict:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session.get("session_id") or session.get("call_id"),
            "pcap_source": session.get("pcap_source"),
            "root_cause": final_rca.get("rca_label", "UNKNOWN"),
            "protocols": session.get("protocols", []),
            "signature": (session.get("trace_intelligence") or {}).get("failure_signature"),
        }
        self.state["events"].append(event)
        self.state["events"] = self.state["events"][-5000:]
        self.state["last_updated"] = event["timestamp"]
        recurring = self.detect_recurring_failures()
        self.state["recurring_summary"] = recurring
        self._save()
        return recurring

    def detect_recurring_failures(self) -> dict:
        labels = Counter(event.get("root_cause", "UNKNOWN") for event in self.state.get("events", []))
        signatures = Counter(event.get("signature") for event in self.state.get("events", []) if event.get("signature"))
        recurring = [
            {"root_cause": label, "count": count}
            for label, count in labels.items()
            if count >= 3 and label != "NORMAL_CALL"
        ]
        periodic = [
            {"signature": signature, "count": count}
            for signature, count in signatures.items()
            if count >= 3
        ]
        return {
            "recurring_failures": recurring[:10],
            "periodic_signatures": periodic[:10],
        }

    def _load(self) -> dict:
        if not self.path.exists():
            return {"events": [], "last_updated": None, "recurring_summary": {}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {"events": [], "last_updated": None, "recurring_summary": {}}

    def _save(self) -> None:
        self.path.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
