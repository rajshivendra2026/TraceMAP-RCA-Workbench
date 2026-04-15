import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from src.eval.benchmark_runner import load_expected_results, resolve_case_pcap, run_benchmark_suite
from src.eval.metrics import benchmark_case_passed, compute_session_metrics


class BenchmarkRunnerTests(unittest.TestCase):
    def test_compute_session_metrics_tracks_unknown_ratio(self):
        sessions = [
            {"rca": {"rca_label": "NORMAL_CALL"}, "priority_score": 12},
            {"rca": {"rca_label": "UNKNOWN"}, "priority_score": 55},
        ]
        metrics = compute_session_metrics(sessions)
        self.assertEqual(metrics["session_count"], 2)
        self.assertEqual(metrics["unknown_count"], 1)
        self.assertEqual(metrics["top_label"], "NORMAL_CALL")
        self.assertEqual(metrics["unknown_ratio"], 0.5)

    def test_benchmark_case_passed_checks_expected_constraints(self):
        metrics = {
            "session_count": 3,
            "unknown_count": 0,
            "unknown_ratio": 0.0,
            "label_counts": {"NORMAL_CALL": 2, "NETWORK_CONGESTION": 1},
            "top_label": "NORMAL_CALL",
        }
        passed, reasons = benchmark_case_passed(
            metrics,
            {
                "min_session_count": 2,
                "max_unknown": 0,
                "required_labels": {"NETWORK_CONGESTION": 1},
                "dominant_label": "NORMAL_CALL",
            },
        )
        self.assertTrue(passed)
        self.assertEqual(reasons, [])

    def test_run_benchmark_suite_reports_pass_fail_and_missing(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            golden = root / "golden"
            golden.mkdir()
            (golden / "ok.pcap").write_text("pcap", encoding="utf-8")
            (golden / "bad.pcap").write_text("pcap", encoding="utf-8")
            suite = root / "expected_results.json"
            suite.write_text(
                """
                {
                  "root_dir": "golden",
                  "cases": [
                    {"name": "ok", "pcap": "ok.pcap", "max_unknown": 0},
                    {"name": "bad", "pcap": "bad.pcap", "max_unknown": 0},
                    {"name": "missing", "pcap": "missing.pcap", "max_unknown": 0}
                  ]
                }
                """,
                encoding="utf-8",
            )

            def fake_process(path: str):
                if path.endswith("ok.pcap"):
                    return [{"rca": {"rca_label": "NORMAL_CALL"}}]
                return [{"rca": {"rca_label": "UNKNOWN"}}]

            report = run_benchmark_suite(suite_path=suite, process_fn=fake_process)
            self.assertEqual(report["passed_cases"], 1)
            self.assertEqual(report["failed_cases"], 1)
            self.assertEqual(report["missing_cases"], 1)

    def test_load_expected_results_accepts_list_payload(self):
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "suite.json"
            path.write_text('[{"name":"a","pcap":"a.pcap"}]', encoding="utf-8")
            payload = load_expected_results(path)
            self.assertEqual(len(payload["cases"]), 1)

    def test_resolve_case_pcap_uses_configured_roots_for_pcap_name(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            external = root / "external"
            external.mkdir()
            target = external / "trace.pcap"
            target.write_text("pcap", encoding="utf-8")
            suite = root / "expected_results.json"
            suite.write_text('{"cases":[]}', encoding="utf-8")

            with patch("src.eval.benchmark_runner.cfg", side_effect=lambda key, default=None: [str(external)] if key == "benchmarks.roots" else default):
                resolved = resolve_case_pcap({"pcap_name": "trace.pcap"}, suite, root)

            self.assertEqual(resolved, target.resolve())

    def test_run_benchmark_suite_supports_pcap_name_from_external_root(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            external = root / "external"
            external.mkdir()
            target = external / "trace.pcap"
            target.write_text("pcap", encoding="utf-8")
            suite = root / "expected_results.json"
            suite.write_text(
                """
                {
                  "root_dir": "golden",
                  "cases": [
                    {"name": "external", "pcap_name": "trace.pcap", "max_unknown": 0}
                  ]
                }
                """,
                encoding="utf-8",
            )

            with patch("src.eval.benchmark_runner.cfg", side_effect=lambda key, default=None: [str(external)] if key == "benchmarks.roots" else default):
                report = run_benchmark_suite(
                    suite_path=suite,
                    process_fn=lambda path: [{"rca": {"rca_label": "NORMAL_CALL"}}],
                )

            self.assertEqual(report["passed_cases"], 1)
            self.assertEqual(report["missing_cases"], 0)


if __name__ == "__main__":
    unittest.main()
