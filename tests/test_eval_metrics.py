import unittest


from src.eval.metrics import compute_session_metrics


class EvalMetricsTests(unittest.TestCase):
    def test_prefers_hybrid_rca_label_over_rule_rca_label(self):
        metrics = compute_session_metrics(
            [
                {
                    "rca": {"rca_label": "UNKNOWN"},
                    "hybrid_rca": {"rca_label": "NORMAL_CALL"},
                    "confidence": 82,
                    "priority_score": 15,
                }
            ]
        )

        self.assertEqual(metrics["top_label"], "NORMAL_CALL")
        self.assertEqual(metrics["unknown_count"], 0)


if __name__ == "__main__":
    unittest.main()
