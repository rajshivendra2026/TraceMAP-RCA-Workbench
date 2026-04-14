"""Autonomous RCA orchestration across agents, causal graph, and graph memory."""

from __future__ import annotations

from copy import deepcopy

from src.autonomous.agent_coordinator import AgentCoordinator
from src.autonomous.causal_graph import CausalGraphEngine
from src.autonomous.causal_inference import CausalInferenceEngine
from src.autonomous.confidence_engine import ConfidenceEngine
from src.autonomous.knowledge_graph import TelecomKnowledgeGraph
from src.autonomous.timeseries_engine import TimeSeriesIntelligenceEngine
from src.config import cfg
from src.intelligence.knowledge_engine import KnowledgeEngine
from src.rules.rca_rules import RCA_METADATA


class AutonomousRCAEngine:
    """Higher-order RCA that adds causal and agentic reasoning to the baseline engine."""

    def __init__(
        self,
        knowledge_engine: KnowledgeEngine | None = None,
        knowledge_graph: TelecomKnowledgeGraph | None = None,
        timeseries_engine: TimeSeriesIntelligenceEngine | None = None,
        agent_coordinator: AgentCoordinator | None = None,
        causal_graph: CausalGraphEngine | None = None,
        causal_inference: CausalInferenceEngine | None = None,
        confidence_engine: ConfidenceEngine | None = None,
    ):
        self.knowledge_engine = knowledge_engine or KnowledgeEngine()
        self.knowledge_graph = knowledge_graph or TelecomKnowledgeGraph()
        self.timeseries_engine = timeseries_engine or TimeSeriesIntelligenceEngine()
        self.agent_coordinator = agent_coordinator or AgentCoordinator()
        self.causal_graph = causal_graph or CausalGraphEngine(
            temporal_window_ms=float(cfg("autonomous.causal_window_ms", 5000))
        )
        self.causal_inference = causal_inference or CausalInferenceEngine()
        self.confidence_engine = confidence_engine or ConfidenceEngine()

    def analyze_session(
        self,
        session: dict,
        *,
        pattern_match: dict | None = None,
        anomaly_result: dict | None = None,
    ) -> dict:
        agentic = self.agent_coordinator.analyze(session)
        graph = self.causal_graph.build_session_graph(session, knowledge_graph=self.knowledge_graph)
        causal = self.causal_inference.infer(
            session,
            graph,
            agentic_result=agentic,
            rule_rca=session.get("rca", {}),
            pattern_match=pattern_match,
        )
        confidence = self.confidence_engine.score(
            rule_rca=session.get("rca", {}),
            pattern_match=pattern_match,
            anomaly_result=anomaly_result,
            causal_result=causal,
            agent_result=agentic,
        )
        meta = RCA_METADATA.get(confidence["final_label"], RCA_METADATA["UNKNOWN"])
        result = {
            "rca_label": confidence["final_label"],
            "rca_title": meta["title"],
            "rca_summary": meta["summary"],
            "rca_detail": meta["details"],
            "confidence_pct": confidence["confidence_pct"],
            "agentic_analysis": agentic,
            "causal_analysis": causal,
            "confidence_model": confidence,
            "session_causal_graph": graph,
        }
        graph_summary = self.knowledge_graph.update_from_session(session, final_rca=result, agentic=agentic, causal=causal)
        recurring = self.timeseries_engine.record_session(session, result)
        result["knowledge_graph_summary"] = graph_summary
        result["timeseries_summary"] = recurring
        return deepcopy(result)
