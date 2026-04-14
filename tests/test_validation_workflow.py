import tempfile
import unittest

from src.intelligence.knowledge_engine import KnowledgeEngine


class ValidationWorkflowTests(unittest.TestCase):
    def test_resolve_validation_approve_marks_pattern_validated(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            knowledge = KnowledgeEngine(base_dir=tmpdir)
            knowledge.add_candidate_pattern(
                {
                    "pattern_id": "pat-1",
                    "protocols": ["DIAMETER"],
                    "scenario": "Charging reject",
                    "signature": ["DIAMETER:CCA Failure"],
                    "root_cause": "CHARGING_FAILURE",
                    "confidence": 0.72,
                    "embedding_vector": [0.5, 0.5],
                }
            )
            knowledge.queue_validation(
                {
                    "pattern_id": "pat-1",
                    "session_id": "sess-1",
                    "hybrid_root_cause": "CHARGING_FAILURE",
                }
            )
            validation_id = knowledge.validation_queue[0]["validation_id"]
            result = knowledge.resolve_validation(validation_id, "approve", reviewer="test")
            self.assertEqual(result["validation_status"], "approved")
            self.assertEqual(knowledge.get_pattern("pat-1")["validation_status"], "validated")

    def test_resolve_validation_reject_marks_pattern_for_review(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            knowledge = KnowledgeEngine(base_dir=tmpdir)
            knowledge.add_candidate_pattern(
                {
                    "pattern_id": "pat-2",
                    "protocols": ["SIP"],
                    "scenario": "Timeout",
                    "signature": ["SIP:408"],
                    "root_cause": "SERVICE_TIMEOUT",
                    "confidence": 0.7,
                    "embedding_vector": [0.3, 0.7],
                }
            )
            knowledge.queue_validation(
                {
                    "pattern_id": "pat-2",
                    "session_id": "sess-2",
                    "hybrid_root_cause": "SERVICE_TIMEOUT",
                }
            )
            validation_id = knowledge.validation_queue[0]["validation_id"]
            knowledge.resolve_validation(validation_id, "reject", reviewer="test")
            self.assertEqual(knowledge.get_pattern("pat-2")["validation_status"], "needs_review")


if __name__ == "__main__":
    unittest.main()
