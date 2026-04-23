import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.app import learning


class LearningPathSettingsTests(unittest.TestCase):
    def test_save_and_load_default_learning_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir) / "knowledge"
            raw = Path(tmpdir) / "raw_pcaps"
            raw.mkdir(parents=True)

            with patch("src.app.learning.learning_base_dir", return_value=base), patch(
                "src.app.learning.cfg_path", return_value=str(raw)
            ):
                saved = learning.save_default_learning_path(str(raw))
                self.assertEqual(saved, str(raw.resolve()))
                self.assertEqual(learning.default_learning_path(), str(raw.resolve()))

                settings = json.loads((base / "learning_settings.json").read_text(encoding="utf-8"))
                self.assertEqual(settings["learn_path"], str(raw.resolve()))

    def test_load_learning_metrics_exposes_default_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir) / "knowledge"
            raw = Path(tmpdir) / "raw_pcaps"
            base.mkdir(parents=True)
            raw.mkdir(parents=True)
            (base / "metrics.json").write_text(json.dumps({"pattern_count": 3}), encoding="utf-8")

            with patch("src.app.learning.learning_base_dir", return_value=base), patch(
                "src.app.learning.default_learning_path", return_value=str(raw.resolve())
            ), patch("src.app.learning.load_learning_manifest", return_value={"x": {"name": "a.pcap"}}):
                metrics = learning.load_learning_metrics()
                self.assertEqual(metrics["pattern_count"], 3)
                self.assertEqual(metrics["learned_pcap_count"], 1)
                self.assertEqual(metrics["default_learning_path"], str(raw.resolve()))

    def test_default_learning_path_falls_back_when_saved_path_no_longer_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir) / "knowledge"
            raw = Path(tmpdir) / "raw_pcaps"
            base.mkdir(parents=True)
            raw.mkdir(parents=True)
            stale = Path(tmpdir) / "stale-temp-path"
            (base / "learning_settings.json").write_text(
                json.dumps({"learn_path": str(stale)}),
                encoding="utf-8",
            )

            with patch("src.app.learning.learning_base_dir", return_value=base), patch(
                "src.app.learning.cfg_path", return_value=str(raw)
            ):
                self.assertEqual(learning.default_learning_path(), str(raw.resolve()))


if __name__ == "__main__":
    unittest.main()
