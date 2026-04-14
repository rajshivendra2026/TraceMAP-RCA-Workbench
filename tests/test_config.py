import os
import sys
import types
import unittest


sys.modules.setdefault("yaml", types.SimpleNamespace(safe_load=lambda _: {"server": {"port": 5050}}))

from src.config import _coerce_env_value, cfg_path, project_root


class ConfigTests(unittest.TestCase):
    def test_cfg_path_resolves_from_project_root(self):
        path = cfg_path("missing.key", "data/models")
        self.assertTrue(path.startswith(project_root()))
        self.assertTrue(path.endswith("data/models"))

    def test_env_value_coercion(self):
        self.assertEqual(_coerce_env_value("42"), 42)
        self.assertEqual(_coerce_env_value("3.5"), 3.5)
        self.assertEqual(_coerce_env_value("true"), True)
        self.assertEqual(_coerce_env_value("a,b"), ["a", "b"])


if __name__ == "__main__":
    unittest.main()
