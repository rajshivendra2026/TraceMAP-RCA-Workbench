import sys
import types
import unittest
from unittest.mock import patch


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

from src.correlation.session_builder import _build_non_sip_seed_sessions, _group_sip_dialog, build_sessions


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

    def test_group_sip_dialog_preserves_interleaved_non_sip_without_flushing(self):
        flow = [
            {"protocol": "SIP", "message": "INVITE", "time": 1.0},
            {"protocol": "DIAMETER", "message": "CCR", "time": 1.1},
            {"protocol": "SIP", "message": "180", "time": 1.2},
            {"protocol": "SIP", "message": "200", "time": 1.3},
        ]

        grouped = _group_sip_dialog(flow)

        self.assertEqual([item["protocol"] for item in grouped], ["SIP", "DIAMETER", "SIP", "SIP"])
        self.assertEqual(grouped[0].get("dialog_segment"), 1)
        self.assertEqual(grouped[2].get("dialog_segment"), 1)
        self.assertEqual(grouped[3].get("dialog_segment"), 1)

    def test_non_sip_seed_sessions_do_not_merge_nat_packets_without_identity(self):
        dia_pkts = [
            {
                "frame_number": 100,
                "timestamp": 1.0,
                "src_ip": "203.0.113.10",
                "dst_ip": "198.51.100.20",
                "src_port": 3868,
                "dst_port": 3868,
                "session_id": None,
                "imsi": None,
                "msisdn": None,
            },
            {
                "frame_number": 101,
                "timestamp": 1.1,
                "src_ip": "203.0.113.10",
                "dst_ip": "198.51.100.20",
                "src_port": 3868,
                "dst_port": 3868,
                "session_id": None,
                "imsi": None,
                "msisdn": None,
            },
        ]

        sessions = _build_non_sip_seed_sessions(dia_pkts=dia_pkts, inap_pkts=[], gtp_pkts=[], generic_pkts=[])
        self.assertEqual(len(sessions), 2)
        self.assertNotEqual(sessions[0]["session_id"], sessions[1]["session_id"])

    def test_build_sessions_skips_compaction_for_oversized_seed_sets(self):
        parsed = {
            "sip": [],
            "diameter": [
                {
                    "frame_number": index,
                    "timestamp": float(index),
                    "src_ip": "203.0.113.10",
                    "dst_ip": "198.51.100.20",
                    "src_port": 3868,
                    "dst_port": 3868,
                    "session_id": None,
                    "imsi": None,
                    "msisdn": None,
                    "command_name": "CCR",
                }
                for index in range(1, 7)
            ],
            "inap": [],
            "gtp": [],
        }

        def fake_cfg(key, default=None):
            if key == "correlation.max_compaction_sessions":
                return 5
            return default

        with patch("src.correlation.session_builder.cfg", side_effect=fake_cfg):
            with patch("src.correlation.session_builder._compact_correlated_sessions") as compact:
                sessions = build_sessions(parsed)

        compact.assert_not_called()
        self.assertEqual(len(sessions), 6)


if __name__ == "__main__":
    unittest.main()
