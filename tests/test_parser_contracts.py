import unittest
import types
import sys

sys.modules.setdefault("loguru", types.SimpleNamespace(logger=types.SimpleNamespace(info=lambda *a, **k: None)))
from src.parser.diameter_parser import parse_diameter_packet
from src.parser.sip_parser import parse_sip_packet


class SipParserTests(unittest.TestCase):
    def test_prefers_ipv6_when_ipv4_absent(self):
        packet = parse_sip_packet(
            {
                "sip.Call-ID": "call-1",
                "sip.Method": "invite",
                "sip.From": "<sip:+12345@ims.example.com>",
                "sip.To": "<sip:67890@ims.example.com>",
                "ipv6.src": "2001:db8::10",
                "ipv6.dst": "2001:db8::20",
                "sip.Contact": "<sip:+12345@[2001:db8::30]>",
                "sip.Via": 'SIP/2.0/UDP [2001:db8::40]:5060',
            }
        )

        self.assertEqual(packet["src_ip"], "2001:db8::10")
        self.assertEqual(packet["dst_ip"], "2001:db8::20")
        self.assertEqual(packet["contact_ip"], "2001:db8::30")
        self.assertEqual(packet["via_ip"], "2001:db8::40")
        self.assertEqual(packet["method"], "INVITE")


class DiameterParserTests(unittest.TestCase):
    def test_produces_backward_compatible_keys(self):
        packet = parse_diameter_packet(
            {
                "diameter.Session-Id": "sess-1",
                "diameter.cmd.code": "272",
                "diameter.Result-Code": "5003",
                "diameter.CC-Request-Type": "1",
                "diameter.CC-Request-Number": "2",
                "diameter.Subscription-Id-Data": ["001010123456789", "+15551230000"],
                "diameter.Called-Station-Id": "internet",
                "diameter.Framed-IP-Address": "10.23.45.67",
            }
        )

        self.assertEqual(packet["command_code"], "272")
        self.assertEqual(packet["command_name"], "CCA")
        self.assertEqual(packet["command_long_name"], "Credit-Control")
        self.assertEqual(packet["cc_request_type_name"], "INITIAL")
        self.assertEqual(packet["result_text"], "AUTHORIZATION_REJECTED")
        self.assertEqual(packet["cc_request_type"], "1")
        self.assertEqual(packet["cc_request_number"], 2)
        self.assertTrue(packet["is_auth_failure"])
        self.assertTrue(packet["is_auth_reject"])
        self.assertTrue(packet["is_charging_failure"])
        self.assertEqual(packet["imsi"], "001010123456789")
        self.assertEqual(packet["msisdn"], "15551230000")

    def test_interprets_diameter_experimental_absent_user(self):
        packet = parse_diameter_packet(
            {
                "diameter.Session-Id": "sess-2",
                "diameter.cmd.code": "302",
                "diameter.Experimental-Result-Code": "5550",
                "diameter.flags.request": "False",
            }
        )

        self.assertEqual(packet["experimental_result_code"], "5550")
        self.assertEqual(packet["effective_result_code"], "5550")
        self.assertEqual(packet["semantic_label"], "DIAMETER_ERROR_ABSENT_USER")
        self.assertEqual(packet["semantic_family"], "subscriber_absent")
        self.assertEqual(packet["recommended_rca"], "SUBSCRIBER_UNREACHABLE")
        self.assertTrue(packet["is_subscriber_absent"])


if __name__ == "__main__":
    unittest.main()
