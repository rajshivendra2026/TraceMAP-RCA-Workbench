import unittest

from src.features.feature_engineer import detect_session_anomaly
from src.ml.anomaly import build_anomaly_feature_row, score_session_anomaly


def _session(label: str, *, protocols=None, technologies=None, duration_ms=2500, time_to_failure_ms=0):
    return {
        "session_id": f"s-{label}",
        "protocols": protocols or ["DIAMETER", "GTP"],
        "technologies": technologies or ["IMS", "LTE/4G", "Transport"],
        "duration_ms": duration_ms,
        "time_to_failure_ms": time_to_failure_ms,
        "flow": [
            {"protocol": "DIAMETER", "message": "ULA", "time": 1.0},
            {"protocol": "GTP", "message": "Create Session Request", "time": 4.1},
            {"protocol": "GTP", "message": "Create Session Response", "time": 4.4},
        ],
        "rca": {
            "rca_label": label,
            "confidence_pct": 86 if label != "NORMAL_CALL" else 78,
            "severity": "HIGH" if label != "NORMAL_CALL" else "LOW",
        },
    }


class AnomalyEnsembleTests(unittest.TestCase):
    def test_feature_row_marks_mobility_and_transport_context(self):
        session = _session(
            "UNKNOWN",
            protocols=["S1AP", "NAS_EPS", "GTP", "SCTP"],
            technologies=["LTE/4G", "Transport"],
        )
        row = build_anomaly_feature_row(
            session,
            features={"cross_protocol_hops": 4, "timer_anomaly_count": 2},
            intelligence={"sequence_length": 9},
        )
        self.assertEqual(row["is_mobility_trace"], 1.0)
        self.assertEqual(row["is_transport_heavy"], 1.0)
        self.assertEqual(row["is_unknown"], 1.0)

    def test_charging_heavy_session_scores_as_anomalous(self):
        session = _session("CHARGING_FAILURE", time_to_failure_ms=18000)
        features = {
            "duration_ms": 4100,
            "time_to_failure_ms": 18000,
            "cross_protocol_hops": 4,
            "timer_anomaly_count": 3,
            "has_retransmission": 1,
            "dia_failure_count": 3,
            "charging_failed": 1,
            "auth_failed_dia": 0,
            "sip_4xx": 0,
            "sip_5xx": 0,
            "q850_network_fail": 0,
        }
        intelligence = {"sequence_length": 12, "timer_anomalies": ["service timeout pattern", "retransmission pattern"]}
        result = score_session_anomaly(session, features=features, intelligence=intelligence)
        self.assertTrue(result["is_anomalous"])
        self.assertGreaterEqual(result["score"], 0.55)
        self.assertEqual(result["suggested_root_cause"], "CHARGING_FAILURE")
        self.assertIn(result["dominant_signal"], {"charging", "transport"})
        self.assertIn("component_scores", result)

    def test_normal_session_stays_low(self):
        session = _session("NORMAL_CALL", protocols=["GTP"], technologies=["LTE/4G"], duration_ms=1200)
        features = {
            "duration_ms": 1200,
            "time_to_failure_ms": 0,
            "cross_protocol_hops": 1,
            "timer_anomaly_count": 0,
            "has_retransmission": 0,
            "dia_failure_count": 0,
            "charging_failed": 0,
            "auth_failed_dia": 0,
            "sip_4xx": 0,
            "sip_5xx": 0,
            "q850_network_fail": 0,
        }
        intelligence = {"sequence_length": 3, "timer_anomalies": []}
        result = detect_session_anomaly(session, features=features, intelligence=intelligence)
        self.assertFalse(result["is_anomalous"])
        self.assertLess(result["score"], 0.55)


if __name__ == "__main__":
    unittest.main()
