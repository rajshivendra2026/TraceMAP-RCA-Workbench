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


class NetworkParserTests(unittest.TestCase):
    def test_parses_5g_http2_packet(self):
        packet = parse_network_packet(
            {
                "frame.number": "10",
                "frame.time_epoch": "123.5",
                "ip.src": "10.1.1.1",
                "ip.dst": "10.2.2.2",
                "tcp.stream": "7",
                "http2.headers.method": "POST",
                "http2.headers.path": "/nudm-uecm/v1/registrations",
                "http2.headers.status": "201",
            },
            "HTTP",
        )

        self.assertEqual(packet["technology"], "5G")
        self.assertEqual(packet["sbi_service"], "nudm-uecm")
        self.assertEqual(packet["transport"], "TCP")
        self.assertEqual(packet["message"], "POST /nudm-uecm/v1/registrations")
        self.assertEqual(packet["stream_id"], "7")

    def test_parses_lte_s1ap_packet(self):
        packet = parse_network_packet(
            {
                "frame.number": "11",
                "frame.time_epoch": "124.0",
                "ip.src": "10.9.0.1",
                "ip.dst": "10.9.0.2",
                "sctp.stream": "4",
                "s1ap.procedureCode": "12",
                "s1ap.MME_UE_S1AP_ID": "991",
                "s1ap.ENB_UE_S1AP_ID": "77",
            },
            "S1AP",
        )

        self.assertEqual(packet["technology"], "LTE/4G")
        self.assertEqual(packet["transaction_id"], "991")
        self.assertEqual(packet["s1ap_mme_ue_id"], "991")
        self.assertEqual(packet["s1ap_enb_ue_id"], "77")
        self.assertEqual(packet["message"], "Initial UE Message")

    def test_parses_sctp_transport_packet(self):
        packet = parse_network_packet(
            {
                "frame.number": "12",
                "frame.time_epoch": "125.0",
                "ip.src": "10.20.0.1",
                "ip.dst": "10.20.0.2",
                "sctp.stream": "9",
                "sctp.srcport": "36412",
                "sctp.dstport": "36412",
                "sctp.ppid": "18",
            },
            "SCTP",
        )

        self.assertEqual(packet["technology"], "Transport")
        self.assertEqual(packet["transport"], "SCTP")
        self.assertEqual(packet["stream_id"], "9")
        self.assertEqual(packet["message"], "DATA ppid=18")

    def test_parses_map_info_fallback_message(self):
        packet = parse_network_packet(
            {
                "frame.number": "1",
                "frame.time_epoch": "100.0",
                "ip.src": "10.1.1.1",
                "ip.dst": "10.1.1.2",
                "tcap.tid": "69070000",
                "_ws.col.info": "invoke sendAuthenticationInfo",
                "gsm_map.imsi": "204049000003991",
                "gsm_map.msisdn": "316540967050",
            },
            "MAP",
        )

        self.assertEqual(packet["message"], "MAP sendAuthenticationInfo")
        self.assertEqual(packet["transaction_id"], "69070000")
        self.assertEqual(packet["imsi"], "204049000003991")
        self.assertEqual(packet["msisdn"], "316540967050")

    def test_parses_authentication_response_name(self):
        packet = parse_network_packet(
            {
                "frame.number": "13",
                "frame.time_epoch": "126.0",
                "ip.src": "10.9.0.1",
                "ip.dst": "10.9.0.2",
                "nas-eps.nas_msg_emm_type": "0x52",
            },
            "NAS_EPS",
        )

        self.assertEqual(packet["message"], "NAS_EPS Authentication Response")

    def test_parses_pfcp_session_establishment_response(self):
        packet = parse_network_packet(
            {
                "frame.number": "14",
                "frame.time_epoch": "127.0",
                "ip.src": "10.30.0.1",
                "ip.dst": "10.30.0.2",
                "udp.srcport": "8805",
                "udp.dstport": "8805",
                "pfcp.msg_type": "51",
                "pfcp.cause": "1",
                "pfcp.seqno": "9001",
                "pfcp.seid": "seid-44",
            },
            "PFCP",
        )

        self.assertEqual(packet["technology"], "5G")
        self.assertEqual(packet["transaction_id"], "seid-44")
        self.assertEqual(packet["pfcp.seqno"], "9001")
        self.assertIn("Session Establishment Response", packet["message"])
        self.assertFalse(packet["is_failure"])

    def test_parses_radius_access_reject_packet(self):
        packet = parse_network_packet(
            {
                "frame.number": "15",
                "frame.time_epoch": "128.0",
                "ip.src": "10.40.0.10",
                "ip.dst": "10.40.0.20",
                "udp.stream": "44",
                "udp.srcport": "1812",
                "udp.dstport": "1812",
                "radius.code": "3",
                "radius.id": "91",
                "radius.User_Name": "alice@example.net",
                "radius.Calling_Station_Id": "+491701234567",
                "radius.Acct_Session_Id": "acct-91",
                "radius.Reply_Message": "subscriber barred",
            },
            "RADIUS",
        )

        self.assertEqual(packet["technology"], "AAA")
        self.assertEqual(packet["transport"], "UDP")
        self.assertEqual(packet["transaction_id"], "acct-91")
        self.assertIn("Access-Reject", packet["message"])
        self.assertTrue(packet["is_failure"])

    def test_tcap_transaction_list_uses_first_value(self):
        packet = parse_network_packet(
            {
                "frame.number": "16",
                "frame.time_epoch": "129.0",
                "tcap.tid": ["69070000", "69070001"],
                "_ws.col.info": "invoke continue",
            },
            "MAP",
        )

        self.assertEqual(packet["transaction_id"], "69070000")


if __name__ == "__main__":
    unittest.main()
