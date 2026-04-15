import sys
import types
import unittest


class _FakeFlaskApp:
    def __init__(self, *args, **kwargs):
        self.config = {}

    def errorhandler(self, *_args, **_kwargs):
        def decorator(fn):
            return fn
        return decorator

    def route(self, *_args, **_kwargs):
        def decorator(fn):
            return fn
        return decorator


class _FakePandasDataFrame:
    pass


class _FakePandasSeries:
    pass

try:
    import pandas as _real_pandas
except Exception:  # pragma: no cover - fallback for minimal envs
    _real_pandas = None

try:
    import numpy as _real_numpy
except Exception:  # pragma: no cover - fallback for minimal envs
    _real_numpy = None


sys.modules["loguru"] = types.SimpleNamespace(
    logger=types.SimpleNamespace(
        info=lambda *a, **k: None,
        warning=lambda *a, **k: None,
        success=lambda *a, **k: None,
        debug=lambda *a, **k: None,
        error=lambda *a, **k: None,
        remove=lambda *a, **k: None,
        add=lambda *a, **k: None,
        exception=lambda *a, **k: None,
    )
)
sys.modules["yaml"] = types.SimpleNamespace(safe_load=lambda _: {})
sys.modules["flask"] = types.SimpleNamespace(
    Flask=_FakeFlaskApp,
    jsonify=lambda x: x,
    request=types.SimpleNamespace(files={}, get_json=lambda silent=True: {}),
    send_from_directory=lambda *a, **k: None,
)
sys.modules["flask_cors"] = types.SimpleNamespace(CORS=lambda *a, **k: None)
sys.modules["werkzeug.exceptions"] = types.SimpleNamespace(RequestEntityTooLarge=Exception)
sys.modules["werkzeug.utils"] = types.SimpleNamespace(secure_filename=lambda x: x)
sys.modules["pandas"] = _real_pandas or types.SimpleNamespace(DataFrame=_FakePandasDataFrame, Series=_FakePandasSeries, read_csv=lambda *a, **k: None)
sys.modules["numpy"] = _real_numpy or types.SimpleNamespace(array=lambda data, dtype=float: data, dtype=object, __version__="1.0.0")

from main import build_capture_summary
from src.app.summary import session_summary


class TraceSummaryTests(unittest.TestCase):
    def test_map_trace_summary_mentions_map(self):
        parsed = {
            "map": [
                {
                    "protocol": "MAP",
                    "technology": "2G/3G",
                    "msisdn": "12345",
                    "src_ip": "12345",
                    "dst_ip": "98765",
                }
            ],
            "sip": [],
            "diameter": [],
            "inap": [],
            "gtp": [],
            "s1ap": [],
            "ngap": [],
            "ranap": [],
            "bssap": [],
            "http": [],
            "tcp": [],
            "udp": [],
            "pfcp": [],
        }

        summary = build_capture_summary(parsed, [])

        self.assertEqual(summary["kpis"]["radio_2g_3g"], 1)
        self.assertEqual(summary["kpis"]["top_protocol"], "MAP")
        self.assertIn("MAP", summary["details"]["headline"])
        self.assertEqual(summary["details"]["a_party"], "12345")

    def test_expert_findings_prioritize_abnormal_unknown_and_transport_signals(self):
        parsed = {
            "diameter": [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}],
            "s1ap": [{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}],
            "sctp": [{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"}],
            "tcp": [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.6", "is_failure": True} for _ in range(12)],
            "sip": [],
            "inap": [],
            "gtp": [],
            "ngap": [],
            "ranap": [],
            "bssap": [],
            "map": [],
            "http": [],
            "udp": [],
            "pfcp": [],
            "dns": [],
            "icmp": [],
            "nas_eps": [],
            "nas_5gs": [],
        }
        sessions = [
            {
                "duration_ms": 1200,
                "protocols": ["DIAMETER", "SCTP"],
                "technologies": ["IMS", "Transport"],
                "hybrid_rca": {
                    "rca_label": "SUBSCRIBER_BARRED",
                    "rca_title": "Subscriber Barred",
                    "confidence_pct": 94,
                    "raw_confidence_pct": 88,
                    "confidence_band": "high",
                    "calibration_source": "isotonic",
                    "evidence": ["Diameter ULA rejected", "Roaming not allowed"],
                },
            },
            {
                "duration_ms": 800,
                "protocols": ["S1AP", "SCTP"],
                "technologies": ["LTE/4G", "Transport"],
                "hybrid_rca": {
                    "rca_label": "UNKNOWN",
                    "rca_title": "Unknown",
                    "confidence_pct": 31,
                    "evidence": ["Sparse control-plane fragment"],
                },
            },
            {
                "duration_ms": 1500,
                "protocols": ["S1AP", "SCTP"],
                "technologies": ["LTE/4G", "Transport"],
                "hybrid_rca": {
                    "rca_label": "NORMAL_CALL",
                    "rca_title": "Normal Session",
                    "confidence_pct": 72,
                    "evidence": ["Successful attach markers"],
                },
            },
        ]

        summary = build_capture_summary(parsed, sessions)
        findings = summary["expert_findings"]
        titles = [item["title"] for item in findings]
        self.assertGreaterEqual(len(findings), 3)
        self.assertIn("Subscriber Barred is the dominant abnormal pattern", titles)
        self.assertIn("Lead investigation target: Subscriber Barred", titles)
        self.assertIn("Unknown or weakly stitched sessions remain", titles)
        session_payload = session_summary(sessions[0])
        self.assertEqual(session_payload["raw_confidence"], 88)
        self.assertEqual(session_payload["confidence_band"], "high")
        self.assertEqual(session_payload["calibration_source"], "isotonic")


if __name__ == "__main__":
    unittest.main()
