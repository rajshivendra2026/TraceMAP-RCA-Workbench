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
from src.intelligence.knowledge_doctor import KnowledgeBaseDoctor
from src.intelligence.knowledge_engine import KnowledgeEngine
from src.intelligence.llm_explainer import build_llm_explanation
from src.intelligence.skill_exporter import SkillExporter
from src.ml.calibration import apply_confidence_calibration
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
            hybrid["raw_confidence_pct"] = hybrid.get("confidence_pct", 0)
            hybrid = apply_confidence_calibration(hybrid, use_model=True)

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
                use_model=True,
            )
            session.update(priority)
            hybrid.update(priority)

            confidence_model = autonomous.get("confidence_model", {})
            confidence_score = float(confidence_model.get("confidence_score", 0.0))
            is_conflicted = bool((autonomous.get("agentic_analysis") or {}).get("is_conflicted"))
            snapshot = _validation_snapshot(
                session,
                hybrid=hybrid,
                features=features,
                intelligence=intelligence,
                anomaly=anomaly,
                best_match=best_match,
            )
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
                        "session_snapshot": snapshot,
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
                            "session_snapshot": snapshot,
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
    run_doctor: bool | None = None,
    doctor_repair: bool | None = None,
    doctor_strict: bool | None = None,
) -> dict:
    loop = LearningLoop(knowledge_engine=knowledge_engine, autonomous_engine=autonomous_engine)
    metrics = loop.process_sessions(sessions, compact=compact, export_skills=export_skills)
    doctor_report = None
    if run_doctor is None:
        run_doctor = bool(cfg("learning.knowledge_doctor_enabled", True))
    if run_doctor:
        doctor = KnowledgeBaseDoctor(base_dir=str(loop.knowledge.base_dir))
        doctor_report = doctor.enforce(
            repair=bool(cfg("learning.knowledge_doctor_repair", True)) if doctor_repair is None else bool(doctor_repair),
            strict=bool(cfg("learning.knowledge_doctor_strict", False)) if doctor_strict is None else bool(doctor_strict),
        )
    return {
        "sessions": sessions,
        "metrics": metrics,
        "doctor": doctor_report,
    }


def _validation_snapshot(
    session: dict,
    *,
    hybrid: dict,
    features: dict,
    intelligence: dict,
    anomaly: dict,
    best_match: dict | None,
) -> dict:
    feature_keys = (
        "duration_ms",
        "time_to_failure_ms",
        "dia_failure_count",
        "charging_failed",
        "auth_failed_dia",
        "cross_protocol_hops",
        "timer_anomaly_count",
        "has_retransmission",
        "sip_4xx",
        "sip_5xx",
        "q850_network_fail",
        "protocol_count",
        "technology_count",
    )
    compact_features = {key: features.get(key, 0) for key in feature_keys}
    return {
        "session_id": session.get("session_id") or session.get("call_id"),
        "protocols": list(session.get("protocols", [])),
        "technologies": list(session.get("technologies", [])),
        "duration_ms": session.get("duration_ms", 0),
        "rca_label": hybrid.get("rca_label"),
        "confidence_pct": hybrid.get("confidence_pct", 0),
        "raw_confidence_pct": hybrid.get("raw_confidence_pct", hybrid.get("confidence_pct", 0)),
        "priority_score": hybrid.get("priority_score", session.get("priority_score", 0)),
        "priority_band": hybrid.get("priority_band", session.get("priority_band", "low")),
        "priority_reason": hybrid.get("priority_reason", session.get("priority_reason", "baseline inspection")),
        "pattern_match": {
            "root_cause": (best_match or {}).get("root_cause"),
            "similarity": (best_match or {}).get("similarity"),
            "historical_success": (best_match or {}).get("historical_success"),
        },
        "anomaly": {
            "score": anomaly.get("score", 0),
            "is_anomalous": anomaly.get("is_anomalous", False),
            "suggested_root_cause": anomaly.get("suggested_root_cause"),
            "dominant_signal": anomaly.get("dominant_signal"),
            "component_scores": anomaly.get("component_scores", {}),
        },
        "confidence_model": {
            "confidence_score": (hybrid.get("confidence_model") or {}).get("confidence_score"),
            "uncertainty": (hybrid.get("confidence_model") or {}).get("uncertainty"),
            "consensus": (hybrid.get("confidence_model") or {}).get("consensus"),
        },
        "features": compact_features,
        "trace_intelligence": {
            "sequence_length": intelligence.get("sequence_length", 0),
            "timer_anomaly_count": intelligence.get("timer_anomaly_count", 0),
            "cross_protocol_hops": intelligence.get("cross_protocol_hops", 0),
            "failure_signature": intelligence.get("failure_signature", ""),
        },
    }
