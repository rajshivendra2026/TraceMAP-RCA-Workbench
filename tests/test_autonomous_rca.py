import importlib
import tempfile
import unittest

from src.autonomous.engine import AutonomousRCAEngine
from src.intelligence.knowledge_engine import KnowledgeEngine


def sample_session():
    return {
        "session_id": "sess-rca-1",
        "call_id": "call-rca-1",
        "pcap_source": "roaming_auth_reject",
        "protocols": ["DIAMETER", "SCTP", "NAS_5GS"],
        "technologies": ["IMS", "5G", "Transport"],
        "flow": [
            {"protocol": "SCTP", "message": "DATA", "src": "AMF", "dst": "UDM", "time": 0.0},
            {"protocol": "DIAMETER", "message": "SAA 5003", "src": "AMF", "dst": "UDM", "time": 0.05, "failure": True},
            {"protocol": "NAS_5GS", "message": "Registration Reject", "src": "AMF", "dst": "UE", "time": 0.07, "failure": True},
        ],
        "dia_msgs": [
            {
                "is_failure": True,
                "is_auth_failure": True,
                "result_text": "AUTHORIZATION_REJECTED",
                "result_code": "5003",
            }
        ],
        "nas_5gs_msgs": [{"message": "Registration Reject", "is_failure": True}],
        "rca": {
            "rca_label": "SUBSCRIBER_BARRED",
            "rca_title": "Subscriber Barred",
            "rca_summary": "Rejected during auth.",
            "rca_detail": "Authorization rejected upstream.",
            "confidence_pct": 85,
            "severity": "HIGH",
            "evidence": ["Diameter authorization rejected"],
            "rule_id": "R_AUTH",
            "recommendations": ["Inspect UDM profile"],
        },
    }


class AutonomousRCATests(unittest.TestCase):
    def test_autonomous_engine_adds_agentic_and_causal_outputs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            knowledge = KnowledgeEngine(base_dir=tmpdir)
            engine = AutonomousRCAEngine(knowledge_engine=knowledge)
            result = engine.analyze_session(sample_session())
            self.assertEqual(result["rca_label"], "SUBSCRIBER_BARRED")
            self.assertTrue(result["agentic_analysis"]["top_hypothesis"])
            self.assertTrue(result["causal_analysis"]["causal_chain"])
            self.assertGreaterEqual(result["confidence_pct"], 1)
            self.assertGreaterEqual(result["knowledge_graph_summary"]["nodes"], 1)

    def test_learning_loop_import_remains_available_after_knowledge_engine_import(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            knowledge = KnowledgeEngine(base_dir=tmpdir)
            learning_loop = importlib.import_module("src.intelligence.learning_loop")
            loop = learning_loop.LearningLoop(knowledge_engine=knowledge)
            self.assertIs(loop.knowledge, knowledge)
            self.assertTrue(callable(learning_loop.run_learning_cycle))


if __name__ == "__main__":
    unittest.main()
