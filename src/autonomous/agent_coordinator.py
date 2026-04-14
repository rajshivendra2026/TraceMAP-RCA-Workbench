"""Coordinator for multi-agent RCA hypothesis generation."""

from __future__ import annotations

from collections import defaultdict

from src.autonomous.agents import DiameterAgent, GTPAgent, NASAgent, SIPAgent, TransportAgent


class AgentCoordinator:
    """Runs protocol specialists and merges their hypotheses."""

    def __init__(self, agents: list | None = None):
        self.agents = agents or [
            GTPAgent(),
            DiameterAgent(),
            NASAgent(),
            SIPAgent(),
            TransportAgent(),
        ]

    def analyze(self, session: dict) -> dict:
        hypotheses = []
        for agent in self.agents:
            if not agent.supports(session):
                continue
            result = agent.analyze(session)
            if result:
                hypotheses.append(result)

        by_label = defaultdict(float)
        for item in hypotheses:
            by_label[item.get("label", "UNKNOWN")] += float(item.get("confidence", 0.0))

        top_hypothesis = max(hypotheses, key=lambda item: item.get("confidence", 0.0)) if hypotheses else None
        ordered = sorted(by_label.items(), key=lambda item: item[1], reverse=True)
        conflict = len(ordered) > 1 and ordered[0][0] != ordered[1][0] and abs(ordered[0][1] - ordered[1][1]) < 0.18
        consensus = 0.0
        if hypotheses and top_hypothesis:
            aligned = [h for h in hypotheses if h.get("label") == top_hypothesis.get("label")]
            consensus = round(sum(h.get("confidence", 0.0) for h in aligned) / max(len(hypotheses), 1), 4)

        return {
            "hypotheses": hypotheses,
            "top_hypothesis": top_hypothesis,
            "label_scores": dict(ordered),
            "consensus_score": consensus,
            "is_conflicted": conflict,
        }
