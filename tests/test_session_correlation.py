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


class SessionCorrelationTests(unittest.TestCase):
    def test_transport_only_fragment_is_absorbed_by_lte_control_session(self):
        parsed = {
            "sip": [],
            "diameter": [],
            "inap": [],
            "gtp": [
                {
                    "frame_number": 1,
                    "timestamp": 10.0,
                    "src_ip": "1.1.1.1",
                    "dst_ip": "2.2.2.2",
                    "protocol": "GTP",
                    "technology": "LTE/4G",
                    "message": "Create Session Response (Request Accepted)",
                    "cause_code": "16",
                    "gtp.tid": "tid-1",
                }
            ],
            "s1ap": [],
            "http": [],
            "tcp": [],
            "dns": [],
            "icmp": [],
            "nas_eps": [],
            "nas_5gs": [],
            "udp": [
                {
                    "frame_number": 2,
                    "protocol": "UDP",
                    "technology": "Transport",
                    "timestamp": 10.2,
                    "src_ip": "1.1.1.1",
                    "dst_ip": "2.2.2.2",
                    "message": "UDP",
                    "stream_id": "9",
                    "src_port": 2123,
                    "dst_port": 2123,
                }
            ],
            "sctp": [],
            "ngap": [],
            "ranap": [],
            "bssap": [],
            "map": [],
            "pfcp": [],
        }

        sessions = build_sessions(parsed)

        self.assertEqual(len(sessions), 1)
        self.assertIn("gtp", sessions[0]["protocols"])
        self.assertIn("udp", sessions[0]["protocols"])

    def test_repeated_lte_procedures_are_split_into_separate_generic_sessions(self):
        parsed = {
            "sip": [],
            "diameter": [],
            "inap": [],
            "gtp": [],
            "s1ap": [],
            "http": [],
            "tcp": [],
            "dns": [],
            "icmp": [],
            "nas_eps": [
                {
                    "frame_number": 1,
                    "protocol": "NAS_EPS",
                    "technology": "LTE/4G",
                    "timestamp": 1.0,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "message": "NAS_EPS Tracking Area Update Request",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 2,
                    "protocol": "NAS_EPS",
                    "technology": "LTE/4G",
                    "timestamp": 1.1,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.1",
                    "message": "NAS_EPS Tracking Area Update Accept",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 3,
                    "protocol": "NAS_EPS",
                    "technology": "LTE/4G",
                    "timestamp": 1.2,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "message": "NAS_EPS Tracking Area Update Complete",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 4,
                    "protocol": "NAS_EPS",
                    "technology": "LTE/4G",
                    "timestamp": 4.0,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "message": "NAS_EPS Tracking Area Update Request",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 5,
                    "protocol": "NAS_EPS",
                    "technology": "LTE/4G",
                    "timestamp": 4.1,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.1",
                    "message": "NAS_EPS Tracking Area Update Reject cause=15",
                    "transaction_id": "ue-1",
                    "is_failure": True,
                },
                {
                    "frame_number": 6,
                    "protocol": "S1AP",
                    "technology": "LTE/4G",
                    "timestamp": 4.2,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.1",
                    "message": "UE Context Release",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 7,
                    "protocol": "SCTP",
                    "technology": "Transport",
                    "timestamp": 4.21,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.1",
                    "message": "DATA",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 8,
                    "protocol": "NAS_EPS",
                    "technology": "LTE/4G",
                    "timestamp": 20.0,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "message": "NAS_EPS Tracking Area Update Request",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 9,
                    "protocol": "NAS_EPS",
                    "technology": "LTE/4G",
                    "timestamp": 20.1,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.1",
                    "message": "NAS_EPS Tracking Area Update Accept",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 10,
                    "protocol": "NAS_EPS",
                    "technology": "LTE/4G",
                    "timestamp": 20.2,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "message": "NAS_EPS Tracking Area Update Complete",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 11,
                    "protocol": "S1AP",
                    "technology": "LTE/4G",
                    "timestamp": 20.3,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.1",
                    "message": "UE Context Release",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 12,
                    "protocol": "SCTP",
                    "technology": "Transport",
                    "timestamp": 20.31,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.1",
                    "message": "DATA",
                    "transaction_id": "ue-1",
                },
            ],
            "nas_5gs": [],
            "udp": [],
            "sctp": [],
            "ngap": [],
            "ranap": [],
            "bssap": [],
            "map": [],
            "pfcp": [],
        }

        sessions = build_sessions(parsed)

        self.assertEqual(len(sessions), 3)
        summaries = [session["flow_summary"] for session in sessions]
        self.assertTrue(any("Complete" in summary for summary in summaries))
        self.assertTrue(any("Reject" in summary for summary in summaries))

    def test_map_sessions_merge_on_subscriber_identity(self):
        sessions = build_sessions(
            {
                "sip": [],
                "diameter": [],
                "inap": [],
                "gtp": [],
                "s1ap": [],
                "ngap": [],
                "ranap": [],
                "bssap": [],
                "map": [
                    {
                        "frame_number": 1,
                        "timestamp": 100.0,
                        "src_ip": "10.1.1.1",
                        "dst_ip": "10.1.1.2",
                        "protocol": "MAP",
                        "technology": "2G/3G",
                        "transaction_id": "tid-1",
                        "message": "MAP sendAuthenticationInfo",
                        "imsi": "204049000003991",
                        "msisdn": "316540967050",
                        "is_failure": False,
                    },
                    {
                        "frame_number": 2,
                        "timestamp": 100.7,
                        "src_ip": "10.1.1.3",
                        "dst_ip": "10.1.1.4",
                        "protocol": "MAP",
                        "technology": "2G/3G",
                        "transaction_id": "tid-2",
                        "message": "MAP result sendAuthenticationInfo",
                        "imsi": "204049000003991",
                        "msisdn": "316540967050",
                        "is_failure": False,
                    },
                ],
                "http": [],
                "dns": [],
                "icmp": [],
                "nas_eps": [],
                "nas_5gs": [],
                "tcp": [],
                "udp": [],
                "pfcp": [],
                "sctp": [],
            }
        )

        self.assertEqual(len(sessions), 1)

    def test_iterative_compaction_merges_related_inap_and_map_fragments(self):
        sessions = build_sessions(
            {
                "sip": [],
                "diameter": [],
                "inap": [
                    {
                        "frame_number": 1,
                        "timestamp": 10.0,
                        "src_ip": "10.40.255.176",
                        "dst_ip": "10.8.216.30",
                        "protocol": "INAP",
                        "technology": "IMS",
                        "tcap_tid": "tid-a",
                        "message": "UNKNOWN",
                    },
                    {
                        "frame_number": 2,
                        "timestamp": 10.1,
                        "src_ip": "10.8.216.30",
                        "dst_ip": "10.40.255.176",
                        "protocol": "INAP",
                        "technology": "IMS",
                        "tcap_tid": "tid-a",
                        "message": "UNKNOWN",
                    },
                ],
                "gtp": [],
                "s1ap": [],
                "ngap": [],
                "ranap": [],
                "bssap": [],
                "map": [
                    {
                        "frame_number": 3,
                        "timestamp": 10.0,
                        "src_ip": "10.40.255.176",
                        "dst_ip": "10.8.216.30",
                        "protocol": "MAP",
                        "technology": "2G/3G",
                        "transaction_id": "tid-b",
                        "message": "MAP sendAuthenticationInfo",
                    },
                    {
                        "frame_number": 4,
                        "timestamp": 10.1,
                        "src_ip": "10.8.216.30",
                        "dst_ip": "10.40.255.176",
                        "protocol": "MAP",
                        "technology": "2G/3G",
                        "transaction_id": "tid-b",
                        "message": "MAP result sendAuthenticationInfo",
                    },
                ],
                "http": [],
                "dns": [],
                "icmp": [],
                "nas_eps": [],
                "nas_5gs": [],
                "tcp": [],
                "udp": [],
                "pfcp": [],
                "sctp": [
                    {
                        "frame_number": 5,
                        "protocol": "SCTP",
                        "technology": "Transport",
                        "timestamp": 10.0,
                        "src_ip": "10.40.255.176",
                        "dst_ip": "10.8.216.30",
                        "message": "DATA",
                    }
                ],
            }
        )

        self.assertEqual(len(sessions), 1)
        self.assertIn("inap", sessions[0]["protocols"])
        self.assertIn("map", sessions[0]["protocols"])


    def test_mixed_irat_session_summary_hides_transport_chatter(self):
        parsed = {
            "sip": [],
            "diameter": [],
            "inap": [],
            "gtp": [
                {
                    "frame_number": 1,
                    "timestamp": 1.0,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "protocol": "GTP",
                    "technology": "LTE/4G",
                    "message": "Modify Bearer Response (Request Accepted)",
                    "cause_code": "16",
                    "gtp.tid": "irat-1",
                }
            ],
            "s1ap": [],
            "ngap": [
                {
                    "frame_number": 2,
                    "timestamp": 1.1,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.3",
                    "protocol": "NGAP",
                    "technology": "5G",
                    "message": "NGAP procedure 15",
                    "transaction_id": "ue-1",
                }
            ],
            "ranap": [],
            "bssap": [],
            "map": [],
            "http": [],
            "dns": [],
            "icmp": [],
            "nas_eps": [],
            "nas_5gs": [
                {
                    "frame_number": 3,
                    "timestamp": 1.2,
                    "src_ip": "10.0.0.3",
                    "dst_ip": "10.0.0.2",
                    "protocol": "NAS_5GS",
                    "technology": "5G",
                    "message": "NAS_5GS Security Mode Complete",
                    "transaction_id": "ue-1",
                }
            ],
            "tcp": [],
            "udp": [],
            "sctp": [
                {
                    "frame_number": 4,
                    "timestamp": 1.21,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.3",
                    "protocol": "SCTP",
                    "technology": "Transport",
                    "message": "HEARTBEAT",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 5,
                    "timestamp": 1.22,
                    "src_ip": "10.0.0.3",
                    "dst_ip": "10.0.0.2",
                    "protocol": "SCTP",
                    "technology": "Transport",
                    "message": "HEARTBEAT_ACK",
                    "transaction_id": "ue-1",
                },
                {
                    "frame_number": 6,
                    "timestamp": 1.23,
                    "src_ip": "10.0.0.3",
                    "dst_ip": "10.0.0.2",
                    "protocol": "SCTP",
                    "technology": "Transport",
                    "message": "SACK",
                    "transaction_id": "ue-1",
                },
            ],
            "pfcp": [],
        }

        sessions = build_sessions(parsed)

        self.assertEqual(len(sessions), 2)
        joined_summary = " | ".join(session["flow_summary"] for session in sessions)
        self.assertIn("Modify Bearer Response", joined_summary)
        self.assertIn("Security Mode Complete", joined_summary)
        self.assertNotIn("HEARTBEAT", joined_summary)
        self.assertNotIn("SACK", joined_summary)

    def test_benign_transport_noise_sessions_are_suppressed(self):
        sessions = build_sessions(
            {
                "sip": [],
                "diameter": [],
                "inap": [],
                "gtp": [],
                "s1ap": [],
                "ngap": [],
                "ranap": [],
                "bssap": [],
                "map": [],
                "http": [],
                "dns": [],
                "icmp": [],
                "nas_eps": [],
                "nas_5gs": [],
                "tcp": [
                    {
                        "frame_number": 1,
                        "protocol": "TCP",
                        "technology": "Transport",
                        "timestamp": 1.0,
                        "src_ip": "1.1.1.1",
                        "dst_ip": "2.2.2.2",
                        "message": "TCP",
                        "stream_id": "1",
                    }
                ],
                "udp": [],
                "pfcp": [],
                "sctp": [
                    {
                        "frame_number": 2,
                        "protocol": "SCTP",
                        "technology": "Transport",
                        "timestamp": 2.0,
                        "src_ip": "3.3.3.3",
                        "dst_ip": "4.4.4.4",
                        "message": "INIT",
                        "stream_id": "2",
                    },
                    {
                        "frame_number": 3,
                        "protocol": "SCTP",
                        "technology": "Transport",
                        "timestamp": 2.1,
                        "src_ip": "4.4.4.4",
                        "dst_ip": "3.3.3.3",
                        "message": "ABORT",
                        "stream_id": "2",
                    },
                ],
            }
        )

        self.assertEqual(sessions, [])

    def test_repetitive_transport_probe_noise_is_suppressed(self):
        sessions = build_sessions(
            {
                "sip": [],
                "diameter": [],
                "inap": [],
                "gtp": [],
                "s1ap": [],
                "ngap": [],
                "ranap": [],
                "bssap": [],
                "map": [],
                "http": [],
                "dns": [],
                "icmp": [],
                "nas_eps": [],
                "nas_5gs": [],
                "tcp": [
                    {
                        "frame_number": index,
                        "protocol": "TCP",
                        "technology": "Transport",
                        "timestamp": float(index),
                        "src_ip": "127.0.0.1",
                        "dst_ip": "127.0.0.1",
                        "message": "TCP",
                        "stream_id": "9" if index % 2 else "10",
                        "reset": True,
                    }
                    for index in range(1, 7)
                ],
                "udp": [],
                "pfcp": [],
                "sctp": [
                    {
                        "frame_number": 100 + index,
                        "protocol": "SCTP",
                        "technology": "Transport",
                        "timestamp": 10.0 + index,
                        "src_ip": "192.168.10.30" if index % 2 else "192.168.10.35",
                        "dst_ip": "192.168.10.35" if index % 2 else "192.168.10.30",
                        "message": "INIT" if index % 2 else "ABORT",
                    }
                    for index in range(1, 7)
                ],
            }
        )

        self.assertEqual(sessions, [])

    def test_sip_session_absorbs_related_transport_and_control_messages(self):
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
                    "contact_ip": "10.0.0.1",
                    "via_ip": "10.0.0.2",
                },
                {
                    "call_id": "call-1",
                    "status_code": "200",
                    "timestamp": 2.0,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.1",
                },
            ],
            "diameter": [
                {
                    "session_id": "dia-1",
                    "command_code": "272",
                    "cmd_code": "272",
                    "timestamp": 1.5,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.9",
                    "framed_ip": "10.0.0.1",
                    "imsi": "001010123456789",
                    "msisdn": "12345",
                }
            ],
            "inap": [],
            "gtp": [],
            "s1ap": [
                {
                    "frame_number": 101,
                    "protocol": "S1AP",
                    "technology": "LTE/4G",
                    "timestamp": 1.6,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "message": "InitialUEMessage",
                    "transaction_id": "ue-7",
                }
            ],
            "http": [
                {
                    "frame_number": 102,
                    "protocol": "HTTP",
                    "technology": "5G",
                    "timestamp": 1.7,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "message": "POST /nsmf-pdusession/v1/sm-contexts",
                    "stream_id": "22",
                }
            ],
            "tcp": [
                {
                    "frame_number": 102,
                    "protocol": "TCP",
                    "technology": "Transport",
                    "timestamp": 1.8,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "message": "TCP",
                    "stream_id": "22",
                }
            ],
            "dns": [],
            "icmp": [],
            "nas_eps": [],
            "nas_5gs": [
                {
                    "frame_number": 101,
                    "protocol": "NAS_5GS",
                    "technology": "5G",
                    "timestamp": 1.65,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "message": "RegistrationReject",
                    "transaction_id": "ue-7",
                    "imsi": "001010123456789",
                    "cause_code": "9",
                }
            ],
            "udp": [],
            "sctp": [
                {
                    "frame_number": 101,
                    "protocol": "SCTP",
                    "technology": "Transport",
                    "timestamp": 1.62,
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "message": "DATA",
                    "transaction_id": "ue-7",
                }
            ],
            "ngap": [],
            "ranap": [],
            "bssap": [],
            "map": [],
            "pfcp": [],
        }

        sessions = build_sessions(parsed)

        self.assertEqual(len(sessions), 1)
        session = sessions[0]
        self.assertIn("sip", session["protocols"])
        self.assertIn("diameter", session["protocols"])
        self.assertIn("s1ap", session["protocols"])
        self.assertIn("http", session["protocols"])
        self.assertIn("tcp", session["protocols"])
        self.assertIn("nas_5gs", session["protocols"])
        self.assertIn("sctp", session["protocols"])
        self.assertIn("IMS", session["technologies"])
        self.assertIn("LTE/4G", session["technologies"])
        self.assertIn("5G", session["technologies"])
        self.assertEqual(len(session["nas_5gs_msgs"]), 1)
        self.assertEqual(len(session["sctp_msgs"]), 1)
        self.assertEqual(len(session["generic_msgs"]), 5)
        self.assertGreaterEqual(len(session["flow"]), 7)

    def test_pfcp_packets_group_by_seid_and_bucket_messages(self):
        sessions = build_sessions(
            {
                "sip": [],
                "diameter": [],
                "inap": [],
                "gtp": [],
                "s1ap": [],
                "ngap": [],
                "ranap": [],
                "bssap": [],
                "map": [],
                "http": [],
                "dns": [],
                "icmp": [],
                "nas_eps": [],
                "nas_5gs": [],
                "tcp": [],
                "udp": [],
                "sctp": [],
                "pfcp": [
                    {
                        "frame_number": 1,
                        "timestamp": 100.0,
                        "src_ip": "10.9.0.1",
                        "dst_ip": "10.9.0.2",
                        "src_port": 8805,
                        "dst_port": 8805,
                        "protocol": "PFCP",
                        "technology": "5G",
                        "message": "Session Establishment Request",
                        "pfcp.seid": "seid-1",
                        "pfcp.seqno": "777",
                    },
                    {
                        "frame_number": 2,
                        "timestamp": 100.1,
                        "src_ip": "10.9.0.2",
                        "dst_ip": "10.9.0.1",
                        "src_port": 8805,
                        "dst_port": 8805,
                        "protocol": "PFCP",
                        "technology": "5G",
                        "message": "Session Establishment Response (Request Accepted)",
                        "cause_code": "1",
                        "pfcp.seid": "seid-1",
                        "pfcp.seqno": "777",
                    },
                ],
            }
        )

        self.assertEqual(len(sessions), 1)
        self.assertIn("pfcp", sessions[0]["protocols"])
        self.assertEqual(len(sessions[0]["pfcp_msgs"]), 2)

    def test_sctp_data_only_probe_noise_is_suppressed(self):
        sessions = build_sessions(
            {
                "sip": [],
                "diameter": [],
                "inap": [],
                "gtp": [],
                "s1ap": [],
                "ngap": [],
                "ranap": [],
                "bssap": [],
                "map": [],
                "http": [],
                "dns": [],
                "icmp": [],
                "nas_eps": [],
                "nas_5gs": [],
                "tcp": [],
                "udp": [],
                "pfcp": [],
                "sctp": [
                    {
                        "frame_number": 1,
                        "protocol": "SCTP",
                        "technology": "Transport",
                        "timestamp": 1.0,
                        "src_ip": "10.1.1.1",
                        "dst_ip": "10.1.1.2",
                        "message": "DATA",
                    },
                    {
                        "frame_number": 2,
                        "protocol": "SCTP",
                        "technology": "Transport",
                        "timestamp": 1.1,
                        "src_ip": "10.1.1.2",
                        "dst_ip": "10.1.1.1",
                        "message": "DATA",
                    },
                ],
            }
        )

        self.assertEqual(sessions, [])

    def test_sctp_heartbeat_noise_is_suppressed(self):
        sessions = build_sessions(
            {
                "sip": [],
                "diameter": [],
                "inap": [],
                "gtp": [],
                "s1ap": [],
                "ngap": [],
                "ranap": [],
                "bssap": [],
                "map": [],
                "http": [],
                "dns": [],
                "icmp": [],
                "nas_eps": [],
                "nas_5gs": [],
                "tcp": [],
                "udp": [],
                "pfcp": [],
                "sctp": [
                    {
                        "frame_number": 1,
                        "protocol": "SCTP",
                        "technology": "Transport",
                        "timestamp": 1.0,
                        "src_ip": "10.1.1.1",
                        "dst_ip": "10.1.1.2",
                        "message": "HEARTBEAT",
                    },
                    {
                        "frame_number": 2,
                        "protocol": "SCTP",
                        "technology": "Transport",
                        "timestamp": 1.1,
                        "src_ip": "10.1.1.2",
                        "dst_ip": "10.1.1.1",
                        "message": "HEARTBEAT_ACK",
                    },
                ],
            }
        )

        self.assertEqual(sessions, [])

    def test_sctp_data_ppid_noise_is_suppressed(self):
        sessions = build_sessions(
            {
                "sip": [],
                "diameter": [],
                "inap": [],
                "gtp": [],
                "s1ap": [],
                "ngap": [],
                "ranap": [],
                "bssap": [],
                "map": [],
                "http": [],
                "dns": [],
                "icmp": [],
                "nas_eps": [],
                "nas_5gs": [],
                "tcp": [],
                "udp": [],
                "pfcp": [],
                "sctp": [
                    {
                        "frame_number": 1,
                        "protocol": "SCTP",
                        "technology": "Transport",
                        "timestamp": 1.0,
                        "src_ip": "10.1.1.1",
                        "dst_ip": "10.1.1.2",
                        "message": "DATA ppid=18",
                    },
                    {
                        "frame_number": 2,
                        "protocol": "SCTP",
                        "technology": "Transport",
                        "timestamp": 1.1,
                        "src_ip": "10.1.1.2",
                        "dst_ip": "10.1.1.1",
                        "message": "DATA ppid=18",
                    },
                ],
            }
        )

        self.assertEqual(sessions, [])

    def test_access_aliases_merge_split_s1ap_fragments(self):
        sessions = build_sessions(
            {
                "sip": [],
                "diameter": [],
                "inap": [],
                "gtp": [],
                "s1ap": [
                    {
                        "frame_number": 1,
                        "protocol": "S1AP",
                        "technology": "LTE/4G",
                        "timestamp": 100.0,
                        "src_ip": "10.0.0.1",
                        "dst_ip": "10.0.0.2",
                        "transaction_id": "991",
                        "s1ap_mme_ue_id": "991",
                        "s1ap_enb_ue_id": "77",
                        "message": "Initial UE Message",
                    },
                    {
                        "frame_number": 2,
                        "protocol": "S1AP",
                        "technology": "LTE/4G",
                        "timestamp": 100.5,
                        "src_ip": "10.0.0.3",
                        "dst_ip": "10.0.0.4",
                        "transaction_id": "77",
                        "s1ap_enb_ue_id": "77",
                        "message": "Downlink NAS Transport",
                    },
                ],
                "ngap": [],
                "ranap": [],
                "bssap": [],
                "map": [],
                "http": [],
                "dns": [],
                "icmp": [],
                "nas_eps": [],
                "nas_5gs": [],
                "tcp": [],
                "udp": [],
                "pfcp": [],
                "sctp": [],
            }
        )

        self.assertEqual(len(sessions), 1)
        self.assertEqual(len(sessions[0]["s1ap_msgs"]), 2)

    def test_icmp_neighbor_discovery_noise_is_suppressed(self):
        sessions = build_sessions(
            {
                "sip": [],
                "diameter": [],
                "inap": [],
                "gtp": [],
                "s1ap": [],
                "ngap": [],
                "ranap": [],
                "bssap": [],
                "map": [],
                "http": [],
                "dns": [],
                "icmp": [
                    {
                        "frame_number": 1,
                        "protocol": "ICMP",
                        "technology": "Core",
                        "timestamp": 1.0,
                        "src_ip": "2401::1",
                        "dst_ip": "ff02::1",
                        "message": "ICMP type 134 code 0",
                        "icmp_type": "134",
                        "icmp_code": "0",
                    },
                    {
                        "frame_number": 2,
                        "protocol": "ICMP",
                        "technology": "Core",
                        "timestamp": 1.1,
                        "src_ip": "2401::2",
                        "dst_ip": "2401::1",
                        "message": "ICMP type 135 code 0",
                        "icmp_type": "135",
                        "icmp_code": "0",
                    },
                ],
                "nas_eps": [],
                "nas_5gs": [],
                "tcp": [],
                "udp": [
                    {
                        "frame_number": 3,
                        "protocol": "UDP",
                        "technology": "Transport",
                        "timestamp": 1.2,
                        "src_ip": "2401::1",
                        "dst_ip": "2401::2",
                        "message": "UDP",
                    }
                ],
                "pfcp": [],
                "sctp": [],
            }
        )

        self.assertEqual(sessions, [])

    def test_low_information_gtp_probe_noise_is_suppressed(self):
        sessions = build_sessions(
            {
                "sip": [],
                "diameter": [],
                "inap": [],
                "gtp": [
                    {
                        "frame_number": index,
                        "protocol": "GTP",
                        "technology": "LTE/4G",
                        "timestamp": float(index),
                        "src_ip": None,
                        "dst_ip": None,
                        "message": "GTP",
                        "gtp.tid": None,
                        "cause_code": None,
                    }
                    for index in range(1, 7)
                ],
                "s1ap": [],
                "ngap": [],
                "ranap": [],
                "bssap": [],
                "map": [],
                "http": [],
                "dns": [],
                "icmp": [],
                "nas_eps": [],
                "nas_5gs": [],
                "tcp": [],
                "udp": [],
                "pfcp": [],
                "sctp": [],
            }
        )

        self.assertEqual(sessions, [])


if __name__ == "__main__":
    unittest.main()
