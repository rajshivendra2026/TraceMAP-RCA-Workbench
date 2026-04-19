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

from src.rules.rca_rules import classify_session


class DiameterRcaTests(unittest.TestCase):
    def test_auth_failure_is_not_misclassified_as_charging_failure(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [
                    {
                        "command_code": "301",
                        "command_name": "SAA",
                        "result_code": "5003",
                        "is_failure": True,
                        "is_auth_failure": True,
                        "is_auth_reject": True,
                        "is_charging_failure": False,
                        "is_policy_reject": False,
                    }
                ],
                "inap_msgs": [],
                "gtp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "SUBSCRIBER_BARRED")

    def test_roaming_not_allowed_is_subscriber_barred(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [
                    {
                        "command_code": "316",
                        "command_name": "ULA",
                        "result_code": "5004",
                        "result_text": "ROAMING_NOT_ALLOWED",
                        "is_failure": True,
                        "is_auth_failure": False,
                        "is_auth_reject": False,
                        "is_roaming_failure": True,
                        "is_charging_failure": False,
                        "is_policy_reject": False,
                    }
                ],
                "inap_msgs": [],
                "gtp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "SUBSCRIBER_BARRED")

    def test_cancel_location_housekeeping_is_normal_call(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [
                    {
                        "command_code": "317",
                        "command_name": "CLR",
                        "is_request": True,
                        "is_failure": False,
                        "is_auth_failure": False,
                        "is_auth_reject": False,
                        "is_roaming_failure": False,
                        "is_charging_failure": False,
                        "is_policy_reject": False,
                    }
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
                "protocols": ["diameter", "sctp"],
            }
        )

        self.assertEqual(result["rca_label"], "NORMAL_CALL")
        self.assertEqual(result["rule_id"], "R0AA_DIAMETER_HOUSEKEEPING")

    def test_absent_user_experimental_code_maps_to_subscriber_unreachable(self):
        result = classify_session(
            {
                "sip_msgs": [],
                "dia_msgs": [
                    {
                        "command_code": "302",
                        "command_name": "LIA",
                        "result_code": None,
                        "experimental_result_code": "5550",
                        "effective_result_code": "5550",
                        "result_text": "DIAMETER_ERROR_ABSENT_USER",
                        "is_failure": True,
                        "is_auth_failure": False,
                        "is_auth_reject": False,
                        "is_roaming_failure": False,
                        "is_charging_failure": False,
                        "is_policy_reject": False,
                        "is_subscriber_absent": True,
                        "semantic_family": "subscriber_absent",
                        "semantic_label": "DIAMETER_ERROR_ABSENT_USER",
                        "protocol_intelligence": {
                            "description": "The subscriber is absent, not currently registered, or not present in the queried service domain."
                        },
                    }
                ],
                "inap_msgs": [],
                "gtp_msgs": [],
                "http_msgs": [],
                "tcp_msgs": [],
                "dns_msgs": [],
                "icmp_msgs": [],
                "nas_eps_msgs": [],
                "nas_5gs_msgs": [],
                "final_sip_code": "",
            }
        )

        self.assertEqual(result["rca_label"], "SUBSCRIBER_UNREACHABLE")
        self.assertEqual(result["rule_id"], "R0_SUBSCRIBER_ABSENT")
        self.assertTrue(any("5550" in item for item in result["evidence"]))
        self.assertTrue(any("ABSENT_USER" in item for item in result["evidence"]))


if __name__ == "__main__":
    unittest.main()
