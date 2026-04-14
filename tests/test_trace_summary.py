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
sys.modules["pandas"] = types.SimpleNamespace(DataFrame=object, read_csv=lambda *a, **k: None)
sys.modules["numpy"] = types.SimpleNamespace(array=lambda data, dtype=float: data)

from main import build_capture_summary


class TraceSummaryTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
