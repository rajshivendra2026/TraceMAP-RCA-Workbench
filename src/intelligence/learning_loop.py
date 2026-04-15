"""Controlled self-learning loop for RCA knowledge reinforcement."""

from __future__ import annotations

from collections import Counter

from src.config import cfg
from src.features.feature_engineer import (
    build_session_embedding,
    detect_session_anomaly,
    extract_features,
    extract_trace_intelligence,
)
from src.autonomous.engine import AutonomousRCAEngine
from src.intelligence.compaction_engine import KnowledgeCompactor
from src.intelligence.knowledge_engine import KnowledgeEngine
from src.intelligence.llm_explainer import build_llm_explanation
from src.intelligence.skill_exporter import SkillExporter
from src.ml.ranking import score_session_priority
from src.rules.rca_rules import blend_hybrid_rca


class LearningLoop:
    """Processes sessions into reusable knowledge with validation controls."""

    def __init__(
        self,
        knowledge_engine: KnowledgeEngine | None = None,
        autonomous_engine: AutonomousRCAEngine | None = None,
    ):
        self.knowledge = knowledge_engine or KnowledgeEngine()
        self.autonomous = autonomous_engine or AutonomousRCAEngine(knowledge_engine=self.knowledge)

    def process_sessions(
        self,
        sessions: list[dict],
        compact: bool = False,
        export_skills: bool = False,
    ) -> dict:
        metrics = Counter()
        for session in sessions:
            features = extract_features(session)
            intelligence = extract_trace_intelligence(session)
            embedding = build_session_embedding(session, features=features, intelligence=intelligence)
            context = self.knowledge.build_context(session, intelligence)
            matches = self.knowledge.query_similar(
                embedding,
                protocols=session.get("protocols", []),
                context=context,
                top_k=3,
            )
            best_match = matches[0] if matches else None
            anomaly = detect_session_anomaly(session, features=features, intelligence=intelligence)
            autonomous = self.autonomous.analyze_session(
                session,
                pattern_match=best_match,
                anomaly_result=anomaly,
            )
            rule_rca = session.get("rca", {})
            hybrid = blend_hybrid_rca(
                rule_rca=rule_rca,
                pattern_match=best_match,
                anomaly_result=anomaly,
                causal_result=autonomous.get("causal_analysis"),
                agent_result=autonomous.get("agentic_analysis"),
                confidence_result=autonomous.get("confidence_model"),
                session=session,
            )
            hybrid["pattern_match"] = best_match
            hybrid["anomaly"] = anomaly
            hybrid["knowledge_context"] = context
            hybrid["agentic_analysis"] = autonomous.get("agentic_analysis")
            hybrid["causal_analysis"] = autonomous.get("causal_analysis")
            hybrid["confidence_model"] = autonomous.get("confidence_model")
            hybrid["knowledge_graph_summary"] = autonomous.get("knowledge_graph_summary")
            hybrid["timeseries_summary"] = autonomous.get("timeseries_summary")
            hybrid["llm_explanation"] = build_llm_explanation(session, hybrid, intelligence)

            session["features"] = features
            session["trace_intelligence"] = intelligence
            session["embedding_vector"] = embedding
            session["autonomous_rca"] = autonomous
            session["hybrid_rca"] = hybrid
            priority = score_session_priority(
                session,
                features=features,
                intelligence=intelligence,
                hybrid_rca=hybrid,
                anomaly_result=anomaly,
                pattern_match=best_match,
                confidence_model=autonomous.get("confidence_model"),
            )
            session.update(priority)
            hybrid.update(priority)

            confidence_model = autonomous.get("confidence_model", {})
            confidence_score = float(confidence_model.get("confidence_score", 0.0))
            is_conflicted = bool((autonomous.get("agentic_analysis") or {}).get("is_conflicted"))
            if confidence_score < float(cfg("autonomous.validation_confidence_threshold", 0.58)) or is_conflicted:
                self.knowledge.queue_validation(
                    {
                        "session_id": session.get("session_id") or session.get("call_id"),
                        "rule_root_cause": rule_rca.get("rca_label"),
                        "hybrid_root_cause": hybrid.get("rca_label"),
                        "confidence_score": confidence_score,
                        "uncertainty": confidence_model.get("uncertainty"),
                        "agent_conflict": is_conflicted,
                        "context": context,
                    }
                )
                metrics["queued_uncertain"] += 1

            if best_match and float(best_match.get("similarity", 0)) >= 0.92:
                if best_match.get("root_cause") == hybrid.get("rca_label"):
                    self.knowledge.reinforce_pattern(best_match["pattern_id"])
                    metrics["reinforced_patterns"] += 1
                else:
                    self.knowledge.queue_validation(
                        {
                            "session_id": session.get("session_id") or session.get("call_id"),
                            "pattern_id": best_match["pattern_id"],
                            "rule_root_cause": rule_rca.get("rca_label"),
                            "hybrid_root_cause": hybrid.get("rca_label"),
                            "knowledge_root_cause": best_match.get("root_cause"),
                            "similarity": best_match.get("similarity"),
                            "context": context,
                        }
                    )
                    metrics["queued_conflicts"] += 1
            else:
                candidate = {
                    "protocols": session.get("protocols", []),
                    "scenario": intelligence.get("scenario", "Observed Telecom Session Pattern"),
                    "signature": intelligence.get("sequence_signature", []),
                    "root_cause": hybrid.get("rca_label", rule_rca.get("rca_label", "UNKNOWN")),
                    "confidence": min(0.8, max(0.4, float(hybrid.get("confidence_pct", 50)) / 100)),
                    "evidence_template": "; ".join(hybrid.get("evidence", [])[:3]),
                    "embedding_vector": embedding,
                    "context": context,
                    "historical_success": max(0.45, float(hybrid.get("confidence_pct", 50)) / 100),
                    "source_sessions": [session.get("session_id") or session.get("call_id")],
                    "anomaly_profile": anomaly,
                }
                self.knowledge.add_candidate_pattern(candidate)
                metrics["candidate_patterns"] += 1

        if compact:
            result = KnowledgeCompactor(self.knowledge).compact()
            metrics["compacted_removed"] = result["removed"]
        if export_skills:
            SkillExporter(self.knowledge).export()
            metrics["skill_exports"] += 1
        self.knowledge.save()
        return dict(metrics)


def run_learning_cycle(
    sessions: list[dict],
    compact: bool = False,
    export_skills: bool = False,
    knowledge_engine: KnowledgeEngine | None = None,
    autonomous_engine: AutonomousRCAEngine | None = None,
) -> dict:
    loop = LearningLoop(knowledge_engine=knowledge_engine, autonomous_engine=autonomous_engine)
    metrics = loop.process_sessions(sessions, compact=compact, export_skills=export_skills)
    return {
        "sessions": sessions,
        "metrics": metrics,
    }
