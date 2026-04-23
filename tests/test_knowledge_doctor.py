import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.intelligence.knowledge_doctor import KnowledgeBaseDoctor
from src.intelligence.knowledge_engine import KnowledgeEngine
from src.intelligence.learning_loop import run_learning_cycle


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class KnowledgeDoctorTests(unittest.TestCase):
    def test_doctor_repairs_safe_derivations_and_flags_stale_runtime_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir) / "knowledge"
            raw = Path(tmpdir) / "raw_pcaps"
            raw.mkdir(parents=True)

            _write_json(
                base / "patterns.json",
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
                ],
            )
            _write_json(
                base / "vectors.json",
                [
                    {"id": "pat-1", "vector": [1.0, 0.0], "metadata": {"root_cause": "CHARGING_FAILURE"}},
                    {"id": "pat-orphan", "vector": [0.0, 1.0], "metadata": {"root_cause": "UNKNOWN"}},
                ],
            )
            _write_json(
                base / "metrics.json",
                {"pattern_count": 99, "candidate_pattern_count": 88, "validation_queue_size": 77},
            )
            _write_json(
                base / "validation_queue.json",
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
                        "similarity": 0.93,
                    },
                ],
            )
            _write_json(base / "learning_settings.json", {"learn_path": str(base / "missing-temp-path")})
            _write_json(
                base / "knowledge_graph.json",
                {
                    "nodes": {
                        "protocol:diameter": {
                            "id": "protocol:diameter",
                            "type": "protocol",
                            "name": "DIAMETER",
                            "occurrence_count": 4,
                        }
                    },
                    "edges": {},
                    "metrics": {"node_count": 0, "edge_count": 0, "protocol_count": {"DIAMETER": 1}},
                },
            )
            _write_json(
                base / "timeseries_intelligence.json",
                {
                    "events": [
                        {"timestamp": "2026-04-20T00:00:00+00:00", "root_cause": "CORE_NETWORK_FAILURE", "signature": "sig-a"},
                        {"timestamp": "2026-04-20T00:01:00+00:00", "root_cause": "CORE_NETWORK_FAILURE", "signature": "sig-a"},
                        {"timestamp": "2026-04-20T00:02:00+00:00", "root_cause": "CORE_NETWORK_FAILURE", "signature": "sig-a"},
                    ],
                    "last_updated": None,
                    "recurring_summary": {},
                },
            )
            _write_json(
                base / "run_reports" / "cycle-1.json",
                {"status": "accepted", "started_at": "2026-04-20T00:00:00+00:00", "finished_at": None},
            )

            doctor = KnowledgeBaseDoctor(base_dir=str(base))
            initial = doctor.audit()
            initial_codes = {issue["code"] for issue in initial["issues"]}
            self.assertIn("orphan_vectors", initial_codes)
            self.assertIn("metrics_out_of_sync", initial_codes)
            self.assertIn("duplicate_pending_validation", initial_codes)
            self.assertIn("knowledge_graph_metrics_out_of_sync", initial_codes)
            self.assertIn("timeseries_summary_out_of_sync", initial_codes)
            self.assertIn("stale_learning_path", initial_codes)
            self.assertIn("stale_run_reports", initial_codes)

            with patch("src.intelligence.knowledge_doctor.cfg_path", return_value=str(raw)):
                repaired = doctor.enforce(repair=True, strict=False)

            repaired_codes = {issue["code"] for issue in repaired["issues"]}
            self.assertNotIn("orphan_vectors", repaired_codes)
            self.assertNotIn("metrics_out_of_sync", repaired_codes)
            self.assertNotIn("duplicate_pending_validation", repaired_codes)
            self.assertNotIn("knowledge_graph_metrics_out_of_sync", repaired_codes)
            self.assertNotIn("timeseries_summary_out_of_sync", repaired_codes)
            self.assertNotIn("stale_learning_path", repaired_codes)
            self.assertIn("stale_run_reports", repaired_codes)
            self.assertTrue(repaired["repair_applied"])

            vectors = json.loads((base / "vectors.json").read_text(encoding="utf-8"))
            self.assertEqual([row["id"] for row in vectors], ["pat-1"])
            metrics = json.loads((base / "metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(metrics["pattern_count"], 1)
            self.assertEqual(metrics["candidate_pattern_count"], 1)
            self.assertEqual(metrics["validation_queue_size"], 1)
            validation = json.loads((base / "validation_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(len(validation), 1)
            self.assertEqual(validation[0]["similarity"], 0.93)
            settings = json.loads((base / "learning_settings.json").read_text(encoding="utf-8"))
            self.assertEqual(settings["learn_path"], str(raw.resolve()))
            graph = json.loads((base / "knowledge_graph.json").read_text(encoding="utf-8"))
            self.assertEqual(graph["metrics"]["protocol_count"]["DIAMETER"], 4)
            timeseries = json.loads((base / "timeseries_intelligence.json").read_text(encoding="utf-8"))
            self.assertEqual(timeseries["recurring_summary"]["recurring_failures"][0]["count"], 3)

    def test_doctor_strict_mode_raises_for_unrepairable_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir) / "knowledge"
            _write_json(
                base / "patterns.json",
                [
                    {"pattern_id": "pat-1", "embedding_vector": [1.0, 0.0]},
                    {"pattern_id": "pat-1", "embedding_vector": [1.0, 0.0]},
                ],
            )

            doctor = KnowledgeBaseDoctor(base_dir=str(base))
            with self.assertRaisesRegex(RuntimeError, "duplicate_pattern_ids"):
                doctor.enforce(repair=True, strict=True)

    def test_run_learning_cycle_invokes_knowledge_doctor_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            knowledge = KnowledgeEngine(base_dir=tmpdir)
            with patch("src.intelligence.learning_loop.LearningLoop.process_sessions", return_value={"candidate_patterns": 1}), patch(
                "src.intelligence.learning_loop.KnowledgeBaseDoctor"
            ) as mocked_doctor:
                mocked_doctor.return_value.enforce.return_value = {"ok": True, "error_count": 0, "warning_count": 0}
                result = run_learning_cycle(
                    [],
                    knowledge_engine=knowledge,
                    run_doctor=True,
                    doctor_repair=False,
                    doctor_strict=False,
                )

            mocked_doctor.assert_called_once_with(base_dir=str(knowledge.base_dir))
            mocked_doctor.return_value.enforce.assert_called_once_with(repair=False, strict=False)
            self.assertEqual(result["doctor"]["error_count"], 0)


if __name__ == "__main__":
    unittest.main()
