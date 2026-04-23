"""Near real-time RCA pipeline over streaming packet batches."""

from __future__ import annotations

from src.autonomous.engine import AutonomousRCAEngine
from src.correlation.session_builder import build_sessions
from src.intelligence.learning_loop import run_learning_cycle
from src.rules.rca_rules import label_sessions


class RealTimeRCAPipeline:
    """Processes micro-batches of parsed packets in near real time."""

    def __init__(self, autonomous_engine: AutonomousRCAEngine | None = None):
        self.autonomous = autonomous_engine or AutonomousRCAEngine()

    def process_batch(self, parsed_batch: dict) -> dict:
        sessions = label_sessions(build_sessions(parsed_batch))
        learning = run_learning_cycle(
            sessions,
            compact=False,
            export_skills=False,
            knowledge_engine=self.autonomous.knowledge_engine,
            autonomous_engine=self.autonomous,
        )
        return {
            "sessions": learning["sessions"],
            "metrics": learning["metrics"],
            "knowledge_health": learning.get("doctor"),
        }
