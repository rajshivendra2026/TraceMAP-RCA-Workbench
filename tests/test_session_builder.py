import sys
import types
import unittest


sys.modules.setdefault(
    "loguru",
    types.SimpleNamespace(
        logger=types.SimpleNamespace(
            info=lambda *a, **k: None,
            warning=lambda *a, **k: None,
            success=lambda *a, **k: None,
            debug=lambda *a, **k: None,
            error=lambda *a, **k: None,
        )
    ),
)
sys.modules.setdefault("yaml", types.SimpleNamespace(safe_load=lambda _: {}))

from src.correlation.session_builder import build_sessions


class SessionBuilderTests(unittest.TestCase):
    def test_build_sessions_populates_feature_inputs(self):
        parsed = {
            "sip": [
                {
                    "call_id": "call-1",
                    "method": "INVITE",
                    "timestamp": 1.0,
                    "from_uri": "sip:+12345@ims.example.com",
                    "to_uri": "sip:67890@ims.example.com",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                },
                {
                    "call_id": "call-1",
                    "status_code": "180",
                    "timestamp": 2.0,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.1",
                },
                {
                    "call_id": "call-1",
                    "status_code": "487",
                    "timestamp": 5.0,
                    "reason_header": 'Q.850;cause=18;text="no answer"',
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.1",
                },
            ],
            "diameter": [],
            "inap": [],
            "gtp": [],
        }

        sessions = build_sessions(parsed)

        self.assertEqual(len(sessions), 1)
        session = sessions[0]
        self.assertEqual(session["session_id"], "call-1")
        self.assertEqual(session["flow_summary"], "INVITE → 180 → 487")
        self.assertEqual(session["q850_cause"], 18)
        self.assertEqual(session["time_to_failure_ms"], 4000.0)
        self.assertTrue(session["has_invite"])
        self.assertTrue(session["has_180"])
        self.assertFalse(session["has_200"])


if __name__ == "__main__":
    unittest.main()
