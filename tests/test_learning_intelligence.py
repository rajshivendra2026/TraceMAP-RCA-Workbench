import json
import tempfile
import unittest
from pathlib import Path

from src.intelligence.knowledge_engine import KnowledgeEngine
from src.intelligence.learning_loop import LearningLoop
from src.intelligence.skill_exporter import SkillExporter
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


if __name__ == "__main__":
    unittest.main()
