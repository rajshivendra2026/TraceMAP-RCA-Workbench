import unittest
from unittest.mock import patch

from src.app.health import build_system_health


class SystemHealthTests(unittest.TestCase):
    def test_system_health_reports_release_and_isakmp_compatibility(self):
        supported = {
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "sip.Call-ID",
            "diameter.Session-Id",
            "gtp.teid",
            "gtpv2.teid",
            "isakmp",
            "isakmp.exchangetype",
            "isakmp.cfg.attr.internal_ip4_address",
        }

        class FakeTSharkRunner:
            binary = "/usr/bin/tshark"

            def version(self):
                return "TShark 4.2.0"

            @staticmethod
            def _supported_fields(_binary):
                return supported

        with patch("src.app.health.TSharkRunner", FakeTSharkRunner), patch(
            "src.app.health._is_path_writable", return_value=True
        ), patch(
            "src.app.health._git_output",
            side_effect=lambda *args: {
                ("rev-parse", "--short", "HEAD"): "abc1234",
                ("branch", "--show-current"): "main",
                ("status", "--short"): "",
            }.get(tuple(args)),
        ):
            health = build_system_health(model_status={"trained": False})

        self.assertIn(health["status"], {"ok", "warn"})
        self.assertEqual(health["release"]["commit"], "abc1234")
        self.assertTrue(health["tshark"]["isakmp_compat"])
        self.assertTrue(any(check["id"] == "ike_epdg_compatibility" for check in health["checks"]))


if __name__ == "__main__":
    unittest.main()
