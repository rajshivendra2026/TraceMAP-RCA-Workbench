import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.autonomous.watcher import (
    AutonomousLearningWatcher,
    GitPublisher,
    SeedRefreshPolicy,
    snapshot_seed_state,
)


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class AutonomousWatcherTests(unittest.TestCase):
    def test_seed_refresh_policy_blocks_when_validation_queue_spikes(self):
        policy = SeedRefreshPolicy(max_unknown_ratio=0.4, max_validation_queue_growth=1, max_pattern_drop=0)
        before = {
            "files": {"patterns.json": {"sha1": "old"}},
            "pattern_count": 4,
            "pending_validation": 2,
        }
        after = {
            "files": {"patterns.json": {"sha1": "new"}},
            "pattern_count": 4,
            "pending_validation": 5,
        }
        cycle = {"session_count": 10, "label_counts": {"UNKNOWN": 1}}
        result = policy.evaluate(before, after, cycle)
        self.assertFalse(result["passed"])
        self.assertEqual(result["validation_queue_growth"], 3)

    def test_watcher_writes_report_and_updates_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            knowledge = base / "knowledge"
            input_dir = base / "raw"
            report_dir = knowledge / "run_reports"
            input_dir.mkdir(parents=True)
            _write_json(knowledge / "patterns.json", [])
            _write_json(knowledge / "metrics.json", {"validation_queue_size": 0})
            _write_json(knowledge / "vectors.json", [])
            _write_json(knowledge / "validation_queue.json", [])
            (input_dir / "trace-1.pcap").write_text("pcap", encoding="utf-8")

            sessions = [
                {"session_id": "sess-1", "rca": {"rca_label": "NORMAL_CALL"}},
                {"session_id": "sess-2", "rca": {"rca_label": "UNKNOWN"}},
            ]

            def fake_process_pcap(path: str, **kwargs):
                _write_json(
                    knowledge / "patterns.json",
                    [{"pattern_id": "pat-1", "root_cause": "NORMAL_CALL", "embedding_vector": [0.1, 0.2]}],
                )
                _write_json(knowledge / "vectors.json", [{"id": "pat-1"}])
                return list(sessions)

            with patch("src.autonomous.watcher.process_pcap", side_effect=fake_process_pcap), patch(
                "src.autonomous.watcher.report_dir", return_value=report_dir
            ), patch(
                "src.autonomous.watcher.cfg",
                side_effect=lambda key, default=None: False if key == "autonomous.auto_commit" else default,
            ):
                watcher = AutonomousLearningWatcher(
                    watch_paths=[str(input_dir)],
                    base_dir=knowledge,
                    manifest_path=knowledge / "processed_sources.json",
                    policy=SeedRefreshPolicy(
                        max_unknown_ratio=0.6,
                        max_validation_queue_growth=2,
                        max_pattern_drop=0,
                        benchmark_enabled=False,
                    ),
                )
                report = watcher.run_cycle()

            self.assertEqual(report["status"], "accepted")
            self.assertEqual(report["processed_trace_count"], 1)
            self.assertEqual(report["label_counts"]["UNKNOWN"], 1)
            self.assertTrue(Path(report["report_path"]).exists())
            written_report = json.loads(Path(report["report_path"]).read_text(encoding="utf-8"))
            self.assertEqual(written_report["finished_at"], report["finished_at"])
            self.assertEqual(written_report["git"], report["git"])
            manifest = json.loads((knowledge / "processed_sources.json").read_text(encoding="utf-8"))
            self.assertEqual(len(manifest), 1)

    def test_watcher_does_not_persist_manifest_when_publish_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            knowledge = base / "knowledge"
            input_dir = base / "raw"
            report_dir = knowledge / "run_reports"
            input_dir.mkdir(parents=True)
            _write_json(knowledge / "patterns.json", [])
            _write_json(knowledge / "metrics.json", {"validation_queue_size": 0})
            _write_json(knowledge / "vectors.json", [])
            _write_json(knowledge / "validation_queue.json", [])
            (input_dir / "trace-1.pcap").write_text("pcap", encoding="utf-8")

            def fake_process_pcap(path: str, **kwargs):
                _write_json(
                    knowledge / "patterns.json",
                    [{"pattern_id": "pat-1", "root_cause": "NORMAL_CALL", "embedding_vector": [0.1, 0.2]}],
                )
                _write_json(knowledge / "vectors.json", [{"id": "pat-1"}])
                return [{"session_id": "sess-1", "rca": {"rca_label": "NORMAL_CALL"}}]

            class RaisingPublisher:
                def publish(self, paths, message, push=False, branch=None):
                    raise RuntimeError("git publish failed")

            with patch("src.autonomous.watcher.process_pcap", side_effect=fake_process_pcap), patch(
                "src.autonomous.watcher.report_dir", return_value=report_dir
            ), patch("src.autonomous.watcher.cfg", side_effect=lambda key, default=None: True if key == "autonomous.auto_commit" else default):
                watcher = AutonomousLearningWatcher(
                    watch_paths=[str(input_dir)],
                    base_dir=knowledge,
                    manifest_path=knowledge / "processed_sources.json",
                    policy=SeedRefreshPolicy(max_unknown_ratio=0.6, max_validation_queue_growth=2, max_pattern_drop=0),
                    git_publisher=RaisingPublisher(),
                )
                with self.assertRaisesRegex(RuntimeError, "git publish failed"):
                    watcher.run_cycle()

            self.assertFalse((knowledge / "processed_sources.json").exists())

    def test_watcher_does_not_persist_manifest_for_held_cycles(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            knowledge = base / "knowledge"
            input_dir = base / "raw"
            report_dir = knowledge / "run_reports"
            input_dir.mkdir(parents=True)
            _write_json(knowledge / "patterns.json", [])
            _write_json(knowledge / "metrics.json", {"validation_queue_size": 0})
            _write_json(knowledge / "vectors.json", [])
            _write_json(knowledge / "validation_queue.json", [])
            (input_dir / "trace-1.pcap").write_text("pcap", encoding="utf-8")

            def fake_process_pcap(path: str, **kwargs):
                _write_json(
                    knowledge / "patterns.json",
                    [{"pattern_id": "pat-1", "root_cause": "UNKNOWN", "embedding_vector": [0.1, 0.2]}],
                )
                _write_json(knowledge / "vectors.json", [{"id": "pat-1"}])
                return [{"session_id": "sess-1", "rca": {"rca_label": "UNKNOWN"}}]

            with patch("src.autonomous.watcher.process_pcap", side_effect=fake_process_pcap), patch(
                "src.autonomous.watcher.report_dir", return_value=report_dir
            ):
                watcher = AutonomousLearningWatcher(
                    watch_paths=[str(input_dir)],
                    base_dir=knowledge,
                    manifest_path=knowledge / "processed_sources.json",
                    policy=SeedRefreshPolicy(
                        max_unknown_ratio=0.0,
                        max_validation_queue_growth=2,
                        max_pattern_drop=0,
                        benchmark_enabled=False,
                    ),
                )
                report = watcher.run_cycle()

            self.assertEqual(report["status"], "held")
            self.assertFalse(report["manifest_persisted"])
            self.assertFalse((knowledge / "processed_sources.json").exists())
            written_report = json.loads(Path(report["report_path"]).read_text(encoding="utf-8"))
            self.assertEqual(written_report["status"], "held")
            self.assertTrue(written_report["finished_at"])

    def test_git_publisher_commits_only_changed_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
            subprocess.run(["git", "config", "user.email", "watcher@example.com"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Watcher"], cwd=repo, check=True)
            tracked = repo / "patterns.json"
            ignored = repo / "validation_queue.json"
            tracked.write_text("[]\n", encoding="utf-8")
            ignored.write_text("[]\n", encoding="utf-8")
            subprocess.run(["git", "add", "patterns.json", "validation_queue.json"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-m", "seed"], cwd=repo, check=True, capture_output=True, text=True)

            tracked.write_text('[{"pattern_id":"pat-1"}]\n', encoding="utf-8")
            ignored.write_text('[{"validation_id":"val-1"}]\n', encoding="utf-8")

            result = GitPublisher(repo_root=repo).publish(
                paths=[str(tracked)],
                message="Refresh autonomous seed learning from trace-1.pcap",
                push=False,
            )

            self.assertTrue(result["committed"])
            status = subprocess.run(
                ["git", "status", "--short"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn(" M validation_queue.json", status)
            self.assertNotIn("patterns.json", status)

    def test_git_publisher_pushes_to_review_branch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
            subprocess.run(["git", "config", "user.email", "watcher@example.com"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Watcher"], cwd=repo, check=True)
            tracked = repo / "patterns.json"
            tracked.write_text("[]\n", encoding="utf-8")
            subprocess.run(["git", "add", "patterns.json"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-m", "seed"], cwd=repo, check=True, capture_output=True, text=True)

            tracked.write_text('[{"pattern_id":"pat-1"}]\n', encoding="utf-8")

            publisher = GitPublisher(repo_root=repo)
            commands: list[list[str]] = []
            original_run = publisher._run

            def capture_run(cmd, check=True):
                commands.append(list(cmd))
                if cmd[:3] == ["git", "push", "origin"]:
                    return subprocess.CompletedProcess(cmd, 0, "", "")
                return original_run(cmd, check=check)

            with patch.object(publisher, "_run", side_effect=capture_run):
                result = publisher.publish(
                    paths=[str(tracked)],
                    message="Refresh autonomous seed learning from trace-1.pcap",
                    push=True,
                    branch="learning-updates",
                )

            self.assertTrue(result["committed"])
            self.assertTrue(result["pushed"])
            self.assertEqual(result["branch"], "learning-updates")
            self.assertIn(["git", "push", "origin", "HEAD:learning-updates"], commands)

    def test_snapshot_seed_state_counts_pending_validation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            _write_json(base / "patterns.json", [{"pattern_id": "pat-1"}])
            _write_json(base / "metrics.json", {"pattern_reuse_count": 1})
            _write_json(base / "vectors.json", [])
            _write_json(
                base / "validation_queue.json",
                [
                    {"validation_id": "val-1", "validation_status": "pending_review"},
                    {"validation_id": "val-2", "validation_status": "approved"},
                ],
            )
            snapshot = snapshot_seed_state(base)
            self.assertEqual(snapshot["pattern_count"], 1)
            self.assertEqual(snapshot["pending_validation"], 1)
            self.assertNotIn("validation_queue.json", snapshot["files"])

    def test_seed_refresh_policy_blocks_when_benchmark_gate_fails(self):
        policy = SeedRefreshPolicy(
            max_unknown_ratio=0.4,
            max_validation_queue_growth=1,
            max_pattern_drop=0,
            benchmark_enabled=True,
            min_benchmark_pass_rate=1.0,
        )
        before = {
            "files": {"patterns.json": {"sha1": "old"}},
            "pattern_count": 4,
            "pending_validation": 0,
        }
        after = {
            "files": {"patterns.json": {"sha1": "new"}},
            "pattern_count": 5,
            "pending_validation": 0,
        }
        cycle = {
            "session_count": 4,
            "label_counts": {"NORMAL_CALL": 4},
            "benchmark": {
                "executed": True,
                "pass_rate": 0.5,
                "missing_cases": 0,
            },
        }
        result = policy.evaluate(before, after, cycle)
        self.assertFalse(result["passed"])
        self.assertEqual(result["checks"][-1]["name"], "benchmark_suite_passed")

    def test_watcher_runs_benchmark_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            knowledge = base / "knowledge"
            input_dir = base / "raw"
            report_dir = knowledge / "run_reports"
            input_dir.mkdir(parents=True)
            _write_json(knowledge / "patterns.json", [])
            _write_json(knowledge / "metrics.json", {"validation_queue_size": 0})
            _write_json(knowledge / "vectors.json", [])
            _write_json(knowledge / "validation_queue.json", [])
            (input_dir / "trace-1.pcap").write_text("pcap", encoding="utf-8")

            with patch("src.autonomous.watcher.process_pcap", return_value=[{"rca": {"rca_label": "NORMAL_CALL"}}]), patch(
                "src.autonomous.watcher.run_benchmark_suite",
                return_value={
                    "executed": True,
                    "pass_rate": 1.0,
                    "passed_cases": 1,
                    "failed_cases": 0,
                    "missing_cases": 0,
                    "cases": [],
                },
            ), patch("src.autonomous.watcher.report_dir", return_value=report_dir), patch(
                "src.autonomous.watcher.cfg",
                side_effect=lambda key, default=None: (
                    True if key == "autonomous.benchmark_enabled" else default
                ),
            ):
                watcher = AutonomousLearningWatcher(
                    watch_paths=[str(input_dir)],
                    base_dir=knowledge,
                    manifest_path=knowledge / "processed_sources.json",
                    policy=SeedRefreshPolicy(
                        max_unknown_ratio=0.6,
                        max_validation_queue_growth=2,
                        max_pattern_drop=0,
                        benchmark_enabled=True,
                        min_benchmark_pass_rate=1.0,
                    ),
                )
                report = watcher.run_cycle()

            self.assertTrue(report["benchmark"]["executed"])
            self.assertEqual(report["benchmark"]["pass_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
