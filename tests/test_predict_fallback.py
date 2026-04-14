import sys
import types
import unittest


sys.modules.setdefault(
    "loguru",
    types.SimpleNamespace(
        logger=types.SimpleNamespace(
            info=lambda *a, **k: None,
            warning=lambda *a, **k: None,
            debug=lambda *a, **k: None,
            success=lambda *a, **k: None,
        )
    ),
)
sys.modules.setdefault("yaml", types.SimpleNamespace(safe_load=lambda _: {}))
sys.modules.setdefault("pandas", types.SimpleNamespace(DataFrame=object, read_csv=lambda *a, **k: None))
sys.modules.setdefault(
    "numpy",
    types.SimpleNamespace(
        array=lambda data, dtype=float: _FakeArray(data),
    ),
)


class _FakeArray(list):
    def reshape(self, *_shape):
        return self

from src.ml.predict import predict_session


class PredictFallbackTests(unittest.TestCase):
    def test_predict_session_uses_rule_fallback_without_model(self):
        session = {
            "call_id": "call-1",
            "flow_summary": "INVITE → 480",
            "duration_ms": 500.0,
            "protocols": ["sip"],
            "final_sip_code": "480",
            "rca": {
                "rca_label": "SUBSCRIBER_UNREACHABLE",
                "confidence_pct": 88,
                "evidence": ["480 Temporarily Unavailable"],
            },
        }

        result = predict_session(session, model=None, encoder=None)
        self.assertEqual(result["rca_label"], "SUBSCRIBER_UNREACHABLE")
        self.assertTrue(result["evidence"])
        self.assertEqual(result["call_id"], "call-1")


if __name__ == "__main__":
    unittest.main()
