import json
import tempfile
import unittest
from pathlib import Path

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

    def test_queue_validation_dedupes_pending_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            knowledge = KnowledgeEngine(base_dir=tmpdir)
            payload = {
                "session_id": "sess-3",
                "pattern_id": "pat-3",
                "hybrid_root_cause": "NORMAL_CALL",
            }
            knowledge.queue_validation(payload)
            knowledge.queue_validation({**payload, "similarity": 0.97})

            self.assertEqual(len(knowledge.validation_queue), 1)
            self.assertEqual(knowledge.metrics["validation_queue_size"], 1)
            self.assertEqual(knowledge.validation_queue[0]["similarity"], 0.97)

    def test_engine_reconciles_metrics_vectors_and_existing_duplicate_queue_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "patterns.json").write_text(
                json.dumps(
                    [
                        {
                            "pattern_id": "pat-1",
                            "protocols": ["DIAMETER"],
                            "scenario": "Charging reject",
                            "signature": ["DIAMETER:CCA Failure"],
                            "root_cause": "CHARGING_FAILURE",
                            "confidence": 0.72,
                            "embedding_vector": [1.0, 0.0],
                            "validation_status": "candidate",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (base / "validation_queue.json").write_text(
                json.dumps(
                    [
                        {
                            "validation_id": "val-1",
                            "session_id": "sess-1",
                            "pattern_id": "pat-1",
                            "hybrid_root_cause": "CHARGING_FAILURE",
                            "validation_status": "pending_review",
                        },
                        {
                            "validation_id": "val-2",
                            "session_id": "sess-1",
                            "pattern_id": "pat-1",
                            "hybrid_root_cause": "CHARGING_FAILURE",
                            "validation_status": "pending_review",
                            "similarity": 0.91,
                        },
                        {
                            "validation_id": "val-3",
                            "session_id": "sess-2",
                            "pattern_id": "pat-1",
                            "hybrid_root_cause": "CHARGING_FAILURE",
                            "validation_status": "approved",
                        },
                    ]
                ),
                encoding="utf-8",
            )
            (base / "metrics.json").write_text(
                json.dumps({"pattern_count": 99, "candidate_pattern_count": 88, "validation_queue_size": 77}),
                encoding="utf-8",
            )
            (base / "vectors.json").write_text(
                json.dumps(
                    [
                        {"id": "pat-1", "vector": [1.0, 0.0], "metadata": {"root_cause": "CHARGING_FAILURE"}},
                        {"id": "pat-orphan", "vector": [0.0, 1.0], "metadata": {"root_cause": "UNKNOWN"}},
                    ]
                ),
                encoding="utf-8",
            )

            knowledge = KnowledgeEngine(base_dir=tmpdir)

            self.assertEqual([row["id"] for row in knowledge.vector_store.items()], ["pat-1"])
            self.assertEqual(len(knowledge.validation_queue), 2)
            self.assertEqual(knowledge.validation_queue[0]["similarity"], 0.91)
            self.assertEqual(knowledge.metrics["pattern_count"], 1)
            self.assertEqual(knowledge.metrics["candidate_pattern_count"], 1)
            self.assertEqual(knowledge.metrics["validation_queue_size"], 1)
            self.assertEqual(knowledge.metrics["validated_count"], 1)


if __name__ == "__main__":
    unittest.main()
