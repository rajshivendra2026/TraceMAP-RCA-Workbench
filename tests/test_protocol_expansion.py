import sys
import types
import unittest


sys.modules.setdefault(
    "loguru",
    types.SimpleNamespace(
        logger=types.SimpleNamespace(info=lambda *a, **k: None)
    ),
)

from src.parser.network_parser import parse_network_packet
from src.rules.rca_rules import classify_session


class ProtocolExpansionTests(unittest.TestCase):
    def test_parses_gtpv2_success_message(self):
        packet = parse_network_packet(
            {
                "frame.number": "1",
                "frame.time_epoch": "100.1",
                "ip.src": "1.1.1.1",
                "ip.dst": "2.2.2.2",
                "gtpv2.message_type": "33",
                "gtpv2.cause": "16",
                "gtp.tid": "abcd",
            },
            "GTP",
        )

        self.assertEqual(packet["protocol"], "GTP")
        self.assertIn("Create Session Response", packet["message"])
        self.assertFalse(packet["is_failure"])

    def test_parses_update_bearer_response_with_network_preference_as_success(self):
        packet = parse_network_packet(
            {
                "frame.number": "1",
                "frame.time_epoch": "100.2",
                "ip.src": "1.1.1.1",
                "ip.dst": "2.2.2.2",
                "gtpv2.message_type": "98",
                "gtpv2.cause": "18",
                "gtp.tid": "efgh",
            },
            "GTP",
        )

        self.assertIn("Update Bearer Response", packet["message"])
        self.assertIn("New PDN Type Due To Network Preference", packet["message"])
        self.assertFalse(packet["is_failure"])

    def test_parses_gtpv2_echo_request_with_human_readable_name(self):
        packet = parse_network_packet(
            {
                "frame.number": "11",
                "frame.time_epoch": "103.5",
                "ip.src": "3.3.3.3",
                "ip.dst": "4.4.4.4",
                "gtpv2.message_type": "1",
                "gtp.tid": "echo-1",
            },
            "GTP",
        )

        self.assertEqual(packet["message"], "Echo Request")

    def test_parses_5gs_security_mode_complete_with_human_readable_name(self):
        packet = parse_network_packet(
            {
                "frame.number": "12",
                "frame.time_epoch": "104.1",
                "ip.src": "10.1.2.1",
                "ip.dst": "10.1.2.2",
                "nas-5gs.mm.message_type": "0x5e",
            },
            "NAS_5GS",
        )

        self.assertIn("Security Mode Complete", packet["message"])

    def test_parses_5gs_authentication_request_with_human_readable_name(self):
        packet = parse_network_packet(
            {
                "frame.number": "13",
                "frame.time_epoch": "104.2",
                "ip.src": "10.1.2.2",
                "ip.dst": "10.1.2.1",
                "nas-5gs.mm.message_type": "0x56",
            },
            "NAS_5GS",
        )

        self.assertIn("Authentication Request", packet["message"])

    def test_parses_5gs_identity_request_with_human_readable_name(self):
        packet = parse_network_packet(
            {
                "frame.number": "15",
                "frame.time_epoch": "104.4",
                "ip.src": "10.1.3.2",
                "ip.dst": "10.1.3.1",
                "nas-5gs.mm.message_type": "0x5b",
            },
            "NAS_5GS",
        )

        self.assertIn("Identity Request", packet["message"])

    def test_prefers_ngap_ws_info_over_numeric_procedure(self):
        packet = parse_network_packet(
            {
                "frame.number": "14",
                "frame.time_epoch": "104.3",
                "ip.src": "10.1.3.1",
                "ip.dst": "10.1.3.2",
                "ngap.procedureCode": "41",
                "_ws.col.info": "SACK (Ack=6, Arwnd=2097152) , UEContextReleaseComplete",
            },
            "NGAP",
        )

        self.assertEqual(packet["message"], "UEContextReleaseComplete")

    def test_parses_nas_eps_tau_accept_message(self):
        packet = parse_network_packet(
            {
                "frame.number": "2",
                "frame.time_epoch": "101.1",
                "ip.src": "10.1.0.1",
                "ip.dst": "10.1.0.2",
                "nas-eps.nas_msg_emm_type": "0x49",
            },
            "NAS_EPS",
        )

        self.assertIn("Tracking Area Update Accept", packet["message"])
        self.assertFalse(packet["is_failure"])

    def test_parses_dns_failure_packet(self):
        packet = parse_network_packet(
            {
                "frame.number": "21",
                "frame.time_epoch": "200.1",
                "ip.src": "10.1.0.10",
                "ip.dst": "10.1.0.53",
                "udp.stream": "2",
                "udp.srcport": "54001",
                "udp.dstport": "53",
                "dns.id": "0x1111",
                "dns.qry.name": "amf.example.net",
                "dns.flags.rcode": "3",
            },
            "DNS",
        )

        self.assertEqual(packet["protocol"], "DNS")
        self.assertTrue(packet["is_failure"])
        self.assertIn("amf.example.net", packet["message"])

    def test_parses_standalone_nas_5gs_message(self):
        packet = parse_network_packet(
            {
                "frame.number": "22",
                "frame.time_epoch": "201.5",
                "ip.src": "10.1.1.10",
                "ip.dst": "10.1.1.20",
                "sctp.stream": "4",
                "e212.imsi": "310170123456789",
                "nas_5gs.mm.message_type": "RegistrationReject",
                "nas_5gs.mm.cause": "9",
            },
            "NAS_5GS",
        )

        self.assertEqual(packet["technology"], "5G")
        self.assertTrue(packet["is_failure"])
        self.assertIn("RegistrationReject", packet["message"])

    def test_parses_hyphenated_nas_5gs_fields(self):
        packet = parse_network_packet(
            {
                "frame.number": "23",
                "frame.time_epoch": "202.5",
                "ip.src": "10.1.2.10",
                "ip.dst": "10.1.2.20",
                "e212.imsi": "310170123456780",
                "nas-5gs.mm.message_type": "RegistrationReject",
                "nas-5gs.mm.5gmm_cause": "9",
            },
            "NAS_5GS",
        )

        self.assertEqual(packet["technology"], "5G")
        self.assertEqual(packet["cause_code"], "9")
        self.assertTrue(packet["is_failure"])
        self.assertIn("RegistrationReject", packet["message"])

    def test_classifies_dns_failure_session(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [{"is_failure": True, "dns_query": "pcf.example.net"}],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "DNS_FAILURE")

    def test_classifies_http_5xx_session_as_nf_failure(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [],
                "pfcp_msgs": [],
                "http_msgs": [{"status_code": "503", "message": "HTTP 503"}],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "radius_msgs": [],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NF_FAILURE")

    def test_classifies_nas_rejection_session(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [{"is_failure": True, "cause_code": "11", "message": "Attach Reject cause=11"}],
                "nas_5gs_msgs": [],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NAS_REJECTION")

    def test_classifies_gtp_success_session_as_normal(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [
                    {"message": "Create Session Response (Request Accepted)", "cause_code": "16"},
                    {"message": "Modify Bearer Response (Request Accepted)", "cause_code": "16"},
                ],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NORMAL_CALL")

    def test_classifies_radius_reject_session(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "radius_msgs": [
                    {
                        "radius_code": "3",
                        "message": "Access-Reject (subscriber barred)",
                        "radius_user_name": "alice@example.net",
                        "is_failure": True,
                    }
                ],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "SUBSCRIBER_BARRED")

    def test_classifies_radius_accept_session_as_normal(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "radius_msgs": [
                    {"radius_code": "11", "message": "Access-Challenge", "is_failure": False},
                    {"radius_code": "2", "message": "Access-Accept", "is_failure": False},
                ],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NORMAL_CALL")

    def test_classifies_successful_handover_sequence_as_normal(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [
                    {"message": "Forward Relocation Response (Request Accepted)", "cause_code": "16"},
                    {"message": "Modify Bearer Response (Request Accepted)", "cause_code": "16"},
                    {"message": "Delete Session Response (Request Accepted)", "cause_code": "16"},
                ],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [
                    {"message": "NAS_EPS Tracking Area Update Request", "is_failure": False},
                    {"message": "NAS_EPS Tracking Area Update Accept", "is_failure": False},
                    {"message": "NAS_EPS Tracking Area Update Complete", "is_failure": False},
                    {"message": "NAS_EPS Bearer Resource Failure Indication", "is_failure": False},
                ],
                "nas_5gs_msgs": [],
                "flow": [
                    {"message": "Handover Resource Allocation"},
                    {"message": "Handover Notification"},
                    {"message": "NAS_EPS Tracking Area Update Request"},
                    {"message": "NAS_EPS Tracking Area Update Accept"},
                    {"message": "NAS_EPS Tracking Area Update Complete"},
                    {"message": "UE Context Release"},
                ],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NORMAL_CALL")

    def test_classifies_inter_rat_handover_cleanup_slice_as_normal(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "s1ap_msgs": [],
                "ngap_msgs": [
                    {"message": "Handover Request", "is_failure": False},
                    {"message": "UE Context Release", "is_failure": False},
                ],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "protocols": ["ngap", "sctp"],
                "flow": [
                    {"message": "Handover Request"},
                    {"message": "UE Context Release"},
                ],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NORMAL_CALL")

    def test_classifies_successful_legacy_map_attach_as_normal(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "protocols": ["map", "sctp"],
                "flow": [
                    {"message": "MAP sendAuthenticationInfo"},
                    {"message": "MAP result sendAuthenticationInfo"},
                    {"message": "MAP updateGprsLocation"},
                    {"message": "MAP insertSubscriberData"},
                    {"message": "MAP result updateGprsLocation"},
                ],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NORMAL_CALL")

    def test_classifies_successful_ranap_attach_slice_as_normal(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "protocols": ["ranap", "sctp"],
                "flow": [
                    {"message": "InitialUE-Message (DTAP) (GMM) Attach Request"},
                    {"message": "DirectTransfer (DTAP) (GMM) Authentication and Ciphering Req"},
                    {"message": "DirectTransfer (DTAP) (GMM) Authentication and Ciphering Resp"},
                    {"message": "SecurityModeCommand"},
                    {"message": "SecurityModeComplete"},
                    {"message": "DirectTransfer (DTAP) (GMM) Attach Accept"},
                    {"message": "DirectTransfer (DTAP) (GMM) Attach Complete"},
                    {"message": "Iu-ReleaseCommand"},
                    {"message": "Iu-ReleaseComplete"},
                ],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NORMAL_CALL")

    def test_classifies_cancel_location_cleanup_as_normal(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [{"message": "UNKNOWN"}],
                "gtp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "protocols": ["inap", "map", "sctp"],
                "flow": [
                    {"message": "MAP sendAuthenticationInfo"},
                    {"message": "MAP result sendAuthenticationInfo"},
                    {"message": "MAP cancelLocation"},
                    {"message": "MAP result cancelLocation"},
                ],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NORMAL_CALL")

    def test_classifies_release_access_bearers_with_icmp_as_normal_cleanup(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [
                    {"message": "Create Bearer Response (Request Accepted)", "cause_code": "16"},
                    {"message": "Release Access Bearers Request", "cause_code": None},
                ],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [{"is_failure": True, "icmp_type": "3", "icmp_code": "3", "message": "ICMP type 3 code 3"}],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NORMAL_CALL")

    def test_classifies_healthy_pfcp_session_as_normal(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [],
                "inap_msgs": [],
                "gtp_msgs": [],
                "pfcp_msgs": [
                    {"protocol": "PFCP", "message": "Session Establishment Request"},
                    {"protocol": "PFCP", "message": "Session Establishment Response"},
                    {"protocol": "PFCP", "message": "Session Modification Request"},
                    {"protocol": "PFCP", "message": "Session Modification Response"},
                    {"protocol": "PFCP", "message": "Session Report Request"},
                    {"protocol": "PFCP", "message": "Session Report Response"},
                ],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NORMAL_CALL")

    def test_classifies_successful_diameter_sequence_as_normal(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [
                    {"command_code": "272", "result_code": "2001", "is_failure": False},
                    {"command_code": "258", "result_code": "2001", "is_failure": False},
                ],
                "inap_msgs": [],
                "gtp_msgs": [],
                "pfcp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "NORMAL_CALL")

    def test_parses_sctp_chunk_name(self):
        packet = parse_network_packet(
            {
                "frame.number": "24",
                "frame.time_epoch": "203.5",
                "ip.src": "10.1.3.10",
                "ip.dst": "10.1.3.20",
                "sctp.chunk_type": "0",
            },
            "SCTP",
        )

        self.assertEqual(packet["protocol"], "SCTP")
        self.assertEqual(packet["message"], "DATA")


if __name__ == "__main__":
    unittest.main()
