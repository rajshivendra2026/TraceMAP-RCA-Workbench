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


if __name__ == "__main__":
    unittest.main()
