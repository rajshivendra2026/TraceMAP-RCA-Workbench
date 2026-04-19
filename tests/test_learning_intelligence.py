import json
import tempfile
import unittest
from pathlib import Path

from src.intelligence.knowledge_engine import KnowledgeEngine
from src.intelligence.learning_loop import LearningLoop
from src.intelligence.skill_exporter import SkillExporter
from src.ml.ranking import score_session_priority
from src.rules.rca_rules import blend_hybrid_rca


def sample_session():
    return {
        "session_id": "sess-1",
        "call_id": "call-1",
        "pcap_source": "roaming_attach_failure",
        "protocols": ["SIP", "DIAMETER", "TCP"],
        "technologies": ["IMS", "LTE/4G", "Transport"],
        "flow_summary": "INVITE → 100 → 487 → ACK",
        "flow": [
            {"protocol": "SIP", "message": "INVITE", "src": "UE\n10.0.0.1", "dst": "IMS\n10.0.0.2", "time": 1.0},
            {"protocol": "DIAMETER", "message": "272", "src": "IMS\n10.0.0.2", "dst": "OCS\n10.0.0.3", "time": 1.4},
            {"protocol": "SIP", "message": "487", "src": "IMS\n10.0.0.2", "dst": "UE\n10.0.0.1", "time": 4.2},
        ],
        "final_sip_code": "487",
        "invite_count": 2,
        "duration_ms": 3200,
        "time_to_failure_ms": 18000,
        "sip_msg_count": 3,
        "has_invite": True,
        "has_cancel": False,
        "has_bye": False,
        "has_180": False,
        "has_183": False,
        "has_200": False,
        "dia_msgs": [{"is_failure": True, "is_charging_failure": True, "cc_request_type": "1"}],
        "inap_msgs": [],
        "sip_msgs": [],
        "gtp_msgs": [],
        "generic_msgs": [],
        "rca": {
            "rca_label": "CHARGING_FAILURE",
            "rca_title": "Charging Failure",
            "rca_summary": "Charging path rejected the session.",
            "rca_detail": "CCR was rejected upstream.",
            "confidence_pct": 92,
            "severity": "HIGH",
            "evidence": ["Diameter charging failure"],
            "rule_id": "R0_CHARGING",
            "recommendations": ["Inspect OCS reachability"],
        },
    }


class LearningIntelligenceTests(unittest.TestCase):
    def test_hybrid_blend_prefers_high_similarity_pattern(self):
        hybrid = blend_hybrid_rca(
            rule_rca=sample_session()["rca"],
            pattern_match={
                "pattern_id": "p-1",
                "root_cause": "CHARGING_FAILURE",
                "scenario": "Roaming attach failure",
                "similarity": 0.98,
                "historical_success": 0.91,
            },
            anomaly_result={"score": 0.71, "is_anomalous": True, "suggested_root_cause": "CHARGING_FAILURE"},
        )
        self.assertEqual(hybrid["rca_label"], "CHARGING_FAILURE")
        self.assertGreaterEqual(hybrid["confidence_pct"], 50)
        self.assertTrue(any("historical pattern" in item for item in hybrid["evidence"]))

    def test_hybrid_blend_uses_winning_label_recommendations_only(self):
        rule_rca = {
            **sample_session()["rca"],
            "rca_label": "CHARGING_FAILURE",
            "recommendations": ["Check OCS latency"],
        }
        hybrid = blend_hybrid_rca(
            rule_rca=rule_rca,
            pattern_match={
                "pattern_id": "p-2",
                "root_cause": "POLICY_FAILURE",
                "scenario": "Policy reject",
                "similarity": 1.0,
                "historical_success": 1.0,
            },
            confidence_result={"final_label": "POLICY_FAILURE", "confidence_pct": 88, "confidence_score": 0.88},
        )
        self.assertEqual(hybrid["rca_label"], "POLICY_FAILURE")
        self.assertEqual(
            hybrid["recommendations"],
            [
                "Review PCRF/PCF logs for rejected transactions.",
                "Validate APN/DNN and policy binding configuration.",
                "Inspect subscription profile consistency across control-plane systems.",
            ],
        )

    def test_learning_loop_creates_and_reuses_patterns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            knowledge = KnowledgeEngine(base_dir=tmpdir)
            loop = LearningLoop(knowledge_engine=knowledge)
            session = sample_session()

            first = loop.process_sessions([session], compact=False, export_skills=False)
            self.assertEqual(first["candidate_patterns"], 1)
            self.assertTrue(session.get("hybrid_rca"))
            self.assertTrue(session.get("autonomous_rca"))
            self.assertEqual(len(knowledge.list_patterns()), 1)

            second_session = sample_session()
            second_session["session_id"] = "sess-2"
            second_session["call_id"] = "call-2"
            second = loop.process_sessions([second_session], compact=False, export_skills=False)
            self.assertGreaterEqual(second.get("reinforced_patterns", 0), 1)
            self.assertEqual(len(knowledge.list_patterns()), 1)

    def test_skill_exporter_writes_portable_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            knowledge = KnowledgeEngine(base_dir=tmpdir)
            knowledge.add_candidate_pattern(
                {
                    "pattern_id": "pat-validated",
                    "protocols": ["GTP", "DIAMETER"],
                    "scenario": "Attach Failure - Roaming",
                    "signature": ["GTP:CreateSessionRequest", "DIAMETER:272"],
                    "root_cause": "CORE_NETWORK_FAILURE",
                    "confidence": 0.91,
                    "evidence_template": "SGSN did not complete session setup",
                    "embedding_vector": [0.5, 0.5, 0.0, 0.0],
                    "validation_status": "validated",
                }
            )
            exporter = SkillExporter(knowledge_engine=knowledge, output_dir=Path(tmpdir) / "skills")
            target = exporter.export(min_confidence=0.75, top_n=10)
            payload = json.loads(Path(target).read_text(encoding="utf-8"))
            self.assertEqual(payload["pattern_count"], 1)
            self.assertEqual(payload["patterns"][0]["root_cause"], "CORE_NETWORK_FAILURE")

    def test_priority_ranking_favors_abnormal_uncertain_sessions(self):
        abnormal = sample_session()
        abnormal["autonomous_rca"] = {"agentic_analysis": {"is_conflicted": True}}
        abnormal["hybrid_rca"] = {
            **abnormal["rca"],
            "confidence_model": {"confidence_score": 0.52, "uncertainty": 0.44},
        }
        abnormal_features = {
            "dia_failure_count": 1,
            "timer_anomaly_count": 2,
            "has_retransmission": 1,
            "cross_protocol_hops": 3,
        }
        abnormal_score = score_session_priority(
            abnormal,
            features=abnormal_features,
            intelligence={},
            hybrid_rca=abnormal["hybrid_rca"],
            anomaly_result={"score": 0.72},
            confidence_model=abnormal["hybrid_rca"]["confidence_model"],
        )

        normal = sample_session()
        normal["rca"] = {
            **normal["rca"],
            "rca_label": "NORMAL_CALL",
            "rca_title": "Normal Session",
            "severity": "LOW",
            "confidence_pct": 78,
            "evidence": ["Normal attach flow"],
        }
        normal["hybrid_rca"] = {
            **normal["rca"],
            "confidence_model": {"confidence_score": 0.86, "uncertainty": 0.1},
        }
        normal_score = score_session_priority(
            normal,
            features={"dia_failure_count": 0, "timer_anomaly_count": 0, "has_retransmission": 0, "cross_protocol_hops": 1},
            intelligence={},
            hybrid_rca=normal["hybrid_rca"],
            anomaly_result={"score": 0.08},
            confidence_model=normal["hybrid_rca"]["confidence_model"],
        )

        self.assertGreater(abnormal_score["priority_score"], normal_score["priority_score"])
        self.assertEqual(abnormal_score["priority_band"], "critical")
        self.assertIn("Charging Failure".split()[0], abnormal_score["priority_reason"])


if __name__ == "__main__":
    unittest.main()
