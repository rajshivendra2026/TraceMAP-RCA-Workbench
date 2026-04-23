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

    def before_request(self, fn):
        return fn

    def after_request(self, fn):
        return fn


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
from src.app.summary import build_session_details_summary, session_summary


class TraceSummaryTests(unittest.TestCase):
    def test_session_details_summary_prefers_msisdn_over_calling_ip(self):
        details = build_session_details_summary(
            {
                "calling": "10.48.38.112",
                "called": "10.3.160.10",
                "msisdn": "14105331485",
                "protocols": ["diameter", "sctp"],
                "technologies": ["IMS", "Transport"],
            }
        )

        self.assertEqual(details["a_party"], "14105331485")
        self.assertEqual(details["b_party"], "10.3.160.10")

    def test_session_details_summary_exposes_selected_sip_filter(self):
        details = build_session_details_summary(
            {
                "session_id": "call-abc",
                "call_id": "call-abc",
                "protocols": ["sip", "tcp"],
                "technologies": ["IMS", "Transport"],
                "sip_msgs": [{"call_id": "call-abc", "method": "INVITE"}],
            }
        )

        self.assertEqual(details["selected_filter"]["label"], "Call-ID")
        self.assertEqual(details["selected_filter"]["value"], "call-abc")
        self.assertIn("Selected filter: Call-ID = call-abc", details["summary_lines"])
        self.assertTrue(any(anchor["label"] == "Call-ID" for anchor in details["correlation_anchors"]))

    def test_session_details_summary_exposes_selected_gtp_tunnel_filter(self):
        details = build_session_details_summary(
            {
                "session_id": "gtp-1001",
                "call_id": "gtp-1001",
                "protocols": ["gtp"],
                "technologies": ["LTE/4G"],
                "subscriber_ip": "10.23.45.67",
                "gtp_msgs": [
                    {
                        "gtp.teid": "1001",
                        "gtp.f_teid": "2002",
                        "gtp.subscriber_ip": "10.23.45.67",
                        "gtpv2.imsi": "001010123456789",
                    }
                ],
            }
        )

        self.assertEqual(details["selected_filter"]["label"], "Tunnel ID (TEID)")
        self.assertEqual(details["selected_filter"]["value"], "1001")
        anchor_map = {anchor["label"]: anchor["value"] for anchor in details["correlation_anchors"]}
        self.assertEqual(anchor_map["Tunnel ID (TEID)"], "1001")
        self.assertEqual(anchor_map["Subscriber IP"], "10.23.45.67")

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

    def test_capture_summary_includes_subscriber_identity_and_node_inventory(self):
        parsed = {
            "sip": [
                {
                    "from_uri": "sip:+4915167536469@ims.example.net",
                    "to_uri": "sip:+491706543966@ims.example.net",
                    "src_ip": "62.156.115.252",
                    "dst_ip": "62.156.113.12",
                    "frame_number": 1,
                }
            ],
            "diameter": [
                {
                    "imsi": "262011905251670",
                    "msisdn": "+4915167536469",
                    "src_ip": "10.114.0.6",
                    "dst_ip": "10.114.1.10",
                    "frame_number": 2,
                }
            ],
            "ngap": [{"src_ip": "10.69.230.79", "dst_ip": "10.114.0.6", "frame_number": 3}],
            "s1ap": [{"src_ip": "10.69.230.80", "dst_ip": "10.114.0.6", "frame_number": 4}],
            "gtp": [
                {"src_ip": "10.114.5.143", "dst_ip": "10.112.189.225", "frame_number": 5},
                {"src_ip": "10.100.196.40", "dst_ip": "10.100.196.153", "gtpv2.message_type": "32", "frame_number": 6},
            ],
            "pfcp": [{"src_ip": "10.100.196.40", "dst_ip": "10.100.196.153", "frame_number": 7}],
            "map": [],
            "inap": [],
            "ranap": [],
            "bssap": [],
            "http": [],
            "tcp": [],
            "udp": [],
            "sctp": [],
            "dns": [],
            "icmp": [],
            "nas_eps": [{"imsi": "262011905251670", "frame_number": 8}],
            "nas_5gs": [],
        }

        summary = build_capture_summary(parsed, [])
        identities = {item["label"]: item for item in summary["details"]["party_identities"]}
        self.assertEqual(identities["A-party"]["msisdn"], "+4915167536469")
        self.assertEqual(identities["A-party"]["imsi"], "262011905251670")
        self.assertIn("Deutsche Telekom Germany", identities["A-party"]["network"])
        self.assertEqual(identities["B-party"]["msisdn"], "+491706543966")
        self.assertEqual(identities["B-party"]["imsi"], "Not observed")

        roles = {item["role"] for item in summary["details"]["node_inventory"]}
        self.assertIn("MME", roles)
        self.assertIn("UPF/SGW", roles)
        self.assertIn("SMF/PGW-C", roles)
        self.assertIn("P-CSCF", roles)

    def test_capture_summary_prefers_diameter_msisdn_for_diameter_only_trace(self):
        parsed = {
            "sip": [],
            "diameter": [
                {
                    "msisdn": "14105331485",
                    "src_ip": "10.48.38.112",
                    "dst_ip": "10.3.160.10",
                    "destination_host": "phxvhssa1.epc.mnc016.mcc901.3gppnetwork.org",
                    "frame_number": 1,
                }
            ],
            "inap": [],
            "gtp": [],
            "s1ap": [],
            "ngap": [],
            "ranap": [],
            "bssap": [],
            "map": [],
            "http": [],
            "tcp": [],
            "udp": [],
            "pfcp": [],
            "dns": [],
            "icmp": [],
            "nas_eps": [],
            "nas_5gs": [],
            "sctp": [],
        }

        summary = build_capture_summary(parsed, [])
        identities = {item["label"]: item for item in summary["details"]["party_identities"]}
        self.assertEqual(summary["details"]["a_party"], "14105331485")
        self.assertEqual(identities["A-party"]["msisdn"], "14105331485")
        self.assertEqual(identities["A-party"]["imsi"], "Not observed")

    def test_capture_summary_builds_error_analysis_report(self):
        parsed = {
            "sip": [
                {"status_code": "401", "message": "401 Unauthorized", "frame_number": 10, "timestamp": 1.0, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
                {"status_code": "200", "message": "200 OK", "frame_number": 11, "timestamp": 2.0, "src_ip": "2.2.2.2", "dst_ip": "1.1.1.1"},
            ],
            "tcp": [
                {"retransmission": "1", "frame_number": 20, "timestamp": 3.0, "src_ip": "3.3.3.3", "dst_ip": "4.4.4.4", "message": "TCP"},
                {"duplicate_ack": "1", "frame_number": 21, "timestamp": 3.5, "src_ip": "3.3.3.3", "dst_ip": "4.4.4.4", "message": "TCP"},
            ],
            "gtp": [
                {"cause_code": "64", "message": "Delete Bearer Response (Context Not Found)", "frame_number": 30, "timestamp": 4.0, "src_ip": "5.5.5.5", "dst_ip": "6.6.6.6"},
            ],
            "ngap": [{"message": "UE Context Release", "procedure": "41", "frame_number": 40, "timestamp": 5.0, "src_ip": "7.7.7.7", "dst_ip": "8.8.8.8"}],
            "s1ap": [{"message": "UE Context Release Request", "procedure": "18", "frame_number": 50, "timestamp": 6.0, "src_ip": "9.9.9.9", "dst_ip": "10.10.10.10"}],
            "diameter": [],
            "map": [],
            "inap": [],
            "ranap": [],
            "bssap": [],
            "http": [],
            "udp": [],
            "pfcp": [],
            "dns": [],
            "icmp": [],
            "nas_eps": [],
            "nas_5gs": [],
        }

        summary = build_capture_summary(parsed, [])
        report = summary["error_analysis"]
        categories = {item["category"]: item for item in report["categories"]}
        self.assertEqual(categories["SIP 401 Unauthorized"]["count"], 1)
        self.assertEqual(categories["SIP 401 Unauthorized"]["severity"], "none")
        self.assertEqual(categories["TCP Transport Issues"]["count"], 2)
        self.assertEqual(categories["GTPv2 Context Not Found"]["count"], 1)
        self.assertEqual(categories["GTPv2 Context Not Found"]["severity"], "medium")
        titles = [section["title"] for section in report["sections"]]
        self.assertIn("SIP — 401 Unauthorized", titles)
        self.assertIn("TCP Transport Issues", titles)
        self.assertIn("GTPv2 — Context Not Found", titles)

    def test_session_summary_emits_failure_topology_with_inferred_roles(self):
        session = {
            "session_id": "call-1",
            "call_id": "call-1",
            "calling": "+4915167536469",
            "called": "+491706543966",
            "subscriber_ip": "10.23.45.67",
            "protocols": ["sip", "diameter", "gtp"],
            "technologies": ["IMS", "LTE/4G"],
            "sip_msgs": [
                {
                    "call_id": "call-1",
                    "method": "INVITE",
                    "timestamp": 1.0,
                    "src_ip": "62.156.115.252",
                    "dst_ip": "62.156.113.12",
                    "from_uri": "sip:+4915167536469@ims.example.net",
                    "to_uri": "sip:+491706543966@ims.example.net",
                    "frame_number": 1,
                },
                {
                    "call_id": "call-1",
                    "status_code": "408",
                    "message": "408 Request Timeout",
                    "timestamp": 2.4,
                    "src_ip": "62.156.113.12",
                    "dst_ip": "62.156.115.252",
                    "frame_number": 2,
                },
            ],
            "dia_msgs": [
                {
                    "session_id": "dia-1",
                    "command_name": "LIR",
                    "command_code": "302",
                    "timestamp": 1.2,
                    "src_ip": "10.114.0.6",
                    "dst_ip": "10.114.1.10",
                    "result_code": "5001",
                    "is_failure": True,
                    "frame_number": 3,
                }
            ],
            "gtp_msgs": [
                {
                    "timestamp": 1.4,
                    "src_ip": "10.100.196.40",
                    "dst_ip": "10.100.196.153",
                    "message": "Create Session Request",
                    "gtp.teid": "1001",
                    "gtp.subscriber_ip": "10.23.45.67",
                    "frame_number": 4,
                }
            ],
            "flow": [
                {"protocol": "SIP", "message": "INVITE", "src": "EXT\n62.156.115.252", "dst": "EXT\n62.156.113.12", "time": 1.0},
                {"protocol": "DIAMETER", "message": "LIR 5001", "short_label": "LIR 5001", "failure": True, "src": "CORE\n10.114.0.6", "dst": "CORE\n10.114.1.10", "time": 1.2, "details": {"result_code": "5001"}},
                {"protocol": "GTP", "message": "Create Session Request", "src": "CORE\n10.100.196.40", "dst": "CORE\n10.100.196.153", "time": 1.4},
                {"protocol": "SIP", "message": "408 Request Timeout", "src": "EXT\n62.156.113.12", "dst": "EXT\n62.156.115.252", "time": 2.4},
            ],
            "flow_summary": "INVITE -> LIR 5001 -> 408",
            "correlation_methods": ["identity:sip:call_id", "identity:diameter:session_id"],
            "hybrid_rca": {
                "rca_label": "SUBSCRIBER_UNREACHABLE",
                "rca_title": "Subscriber Unreachable",
                "rca_summary": "Subscriber lookup and call setup timed out.",
                "confidence_pct": 86,
            },
        }

        payload = session_summary(session)
        topology = payload["failure_topology"]
        node_labels = {item["label"] for item in topology["nodes"]}
        edge_targets = {item["target"] for item in topology["edges"]}

        self.assertEqual(topology["rca_label"], "SUBSCRIBER_UNREACHABLE")
        self.assertIn("P-CSCF", node_labels)
        self.assertIn("HSS/PCRF", node_labels)
        self.assertIn("UE Failure", node_labels)
        self.assertIn("failure", edge_targets)
        self.assertTrue(any("Break marker:" in insight for insight in topology["insights"]))

    def test_capture_summary_includes_front_page_failure_topology(self):
        parsed = {
            "sip": [
                {
                    "call_id": "call-1",
                    "method": "INVITE",
                    "timestamp": 1.0,
                    "src_ip": "62.156.115.252",
                    "dst_ip": "62.156.113.12",
                    "from_uri": "sip:+4915167536469@ims.example.net",
                    "to_uri": "sip:+491706543966@ims.example.net",
                    "frame_number": 1,
                },
                {
                    "call_id": "call-1",
                    "status_code": "408",
                    "message": "408 Request Timeout",
                    "timestamp": 2.4,
                    "src_ip": "62.156.113.12",
                    "dst_ip": "62.156.115.252",
                    "frame_number": 2,
                },
            ],
            "diameter": [
                {
                    "session_id": "dia-1",
                    "command_name": "LIR",
                    "command_code": "302",
                    "timestamp": 1.2,
                    "src_ip": "10.114.0.6",
                    "dst_ip": "10.114.1.10",
                    "result_code": "5001",
                    "is_failure": True,
                    "frame_number": 3,
                }
            ],
            "gtp": [],
            "s1ap": [],
            "ngap": [],
            "inap": [],
            "ranap": [],
            "bssap": [],
            "map": [],
            "http": [],
            "tcp": [],
            "udp": [],
            "pfcp": [],
            "dns": [],
            "icmp": [],
            "nas_eps": [],
            "nas_5gs": [],
            "sctp": [],
        }

        session = {
            "session_id": "call-1",
            "call_id": "call-1",
            "protocols": ["sip", "diameter"],
            "technologies": ["IMS"],
            "priority_score": 90,
            "duration_ms": 2400,
            "sip_msgs": parsed["sip"],
            "dia_msgs": parsed["diameter"],
            "gtp_msgs": [],
            "inap_msgs": [],
            "generic_msgs": [],
            "flow": [
                {"protocol": "SIP", "message": "INVITE", "src": "EXT\n62.156.115.252", "dst": "EXT\n62.156.113.12", "time": 1.0},
                {"protocol": "DIAMETER", "message": "LIR 5001", "short_label": "LIR 5001", "failure": True, "src": "CORE\n10.114.0.6", "dst": "CORE\n10.114.1.10", "time": 1.2, "details": {"result_code": "5001"}},
                {"protocol": "SIP", "message": "408 Request Timeout", "src": "EXT\n62.156.113.12", "dst": "EXT\n62.156.115.252", "time": 2.4},
            ],
            "hybrid_rca": {
                "rca_label": "SUBSCRIBER_UNREACHABLE",
                "rca_title": "Subscriber Unreachable",
                "confidence_pct": 86,
            },
        }

        summary = build_capture_summary(parsed, [session])
        topology = summary["failure_topology"]
        self.assertEqual(topology["scope"], "capture-lead")
        self.assertEqual(topology["focus_session_id"], "call-1")
        self.assertTrue(topology["nodes"])
        self.assertTrue(topology["edges"])

    def test_normal_session_topology_does_not_emit_failure_sink(self):
        session = {
            "session_id": "normal-1",
            "call_id": "normal-1",
            "protocols": ["ngap", "nas_5gs"],
            "technologies": ["5G"],
            "ngap_msgs": [
                {"timestamp": 1.0, "src_ip": "172.17.0.5", "dst_ip": "192.168.123.10", "message": "Initial UE Message"},
                {"timestamp": 2.0, "src_ip": "192.168.123.10", "dst_ip": "172.17.0.5", "message": "UE Context Release"},
            ],
            "generic_msgs": [],
            "flow": [
                {"protocol": "NGAP", "message": "Initial UE Message", "src": "EXT\n172.17.0.5", "dst": "CORE\n192.168.123.10", "time": 1.0},
                {"protocol": "NGAP", "message": "UE Context Release", "src": "CORE\n192.168.123.10", "dst": "EXT\n172.17.0.5", "time": 2.0},
            ],
            "hybrid_rca": {
                "rca_label": "NORMAL_SESSION",
                "rca_title": "Normal Session",
                "rca_summary": "The trace shows a normal service establishment and clean teardown pattern.",
                "confidence_pct": 100,
            },
        }

        payload = session_summary(session)
        topology = payload["failure_topology"]

        self.assertFalse(topology["has_failure"])
        self.assertEqual(topology["title"], "Service Path Topology")
        self.assertNotIn("failure", {node["id"] for node in topology["nodes"]})
        self.assertFalse(any(edge["status"] in {"failure", "failure-path"} for edge in topology["edges"]))
        self.assertFalse(any("Break marker:" in insight for insight in topology["insights"]))

    def test_session_summary_builds_analyst_brief_from_known_diameter_semantics(self):
        session = {
            "protocols": ["DIAMETER", "SCTP"],
            "technologies": ["IMS", "Transport"],
            "dia_msgs": [
                {
                    "is_failure": True,
                    "experimental_result_code": "5550",
                    "effective_result_code": "5550",
                    "semantic_family": "subscriber_absent",
                    "semantic_label": "DIAMETER_ERROR_ABSENT_USER",
                    "command_name": "LIA",
                    "origin_host": "hss01.epc.mnc001.mcc262.3gppnetwork.org",
                    "destination_host": "icscf01.ims.mnc001.mcc262.3gppnetwork.org",
                    "protocol_intelligence": {
                        "name": "DIAMETER_ERROR_ABSENT_USER",
                        "code": "5550",
                        "semantic_family": "subscriber_absent",
                        "description": "The subscriber is absent, not currently registered, or not present in the queried service domain.",
                        "recommendations": [
                            "Check whether the subscriber is registered in IMS/HSS for the requested service.",
                            "Inspect subscriber reachability, service registration, and network attach state.",
                        ],
                    },
                }
            ],
            "hybrid_rca": {
                "rca_label": "SUBSCRIBER_UNREACHABLE",
                "rca_title": "Subscriber Unreachable",
                "rca_summary": "Diameter lookup failed",
                "rca_detail": "Generic detail",
                "recommendations": ["Generic check"],
            },
        }

        payload = session_summary(session)

        self.assertIn("DIAMETER_ERROR_ABSENT_USER (5550)", payload["analyst_brief"])
        self.assertIn("subscriber state / registration / HSS-IMS data", payload["analyst_brief"])
        self.assertEqual(
            payload["recommendations"][0],
            "Check whether the subscriber is registered in IMS/HSS for the requested service.",
        )

    def test_session_summary_builds_context_brief_for_unknown_diameter_code(self):
        session = {
            "protocols": ["DIAMETER", "SCTP"],
            "technologies": ["IMS", "Transport"],
            "dia_msgs": [
                {
                    "is_failure": True,
                    "experimental_result_code": "5555",
                    "effective_result_code": "5555",
                    "command_name": "8388646A",
                    "origin_host": "mmecFB.mmegiFF29.mme.epc.mnc410.mcc310.3gppnetwork.org",
                    "origin_realm": "epc.mnc410.mcc310.3gppnetwork.org",
                    "destination_host": "phxsmsc01.smsc.epc.mnc170.mcc310.3gppnetwork.org",
                    "destination_realm": "epc.mnc170.mcc310.3gppnetwork.org",
                }
            ],
            "hybrid_rca": {
                "rca_label": "UNKNOWN",
                "rca_title": "Unknown",
                "rca_summary": "Generic unknown",
                "rca_detail": "Generic detail",
                "recommendations": ["Generic check"],
            },
        }

        payload = session_summary(session)

        self.assertIn("Diameter non-success 5555", payload["analyst_brief"])
        self.assertIn("different EPC realms or PLMNs", payload["analyst_brief"])
        self.assertIn("Diameter routing / DSR / interconnect / subscriber lookup", payload["analyst_brief"])


if __name__ == "__main__":
    unittest.main()
