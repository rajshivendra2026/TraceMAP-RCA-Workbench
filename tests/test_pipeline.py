import unittest
from unittest.mock import patch

from src.pipeline import process_pcap


class PipelineTests(unittest.TestCase):
    @patch("src.pipeline.load_pcap", side_effect=RuntimeError("boom"))
    def test_process_pcap_returns_empty_list_by_default(self, mocked_load):
        self.assertEqual(process_pcap("broken.pcap"), [])

    @patch("src.pipeline.load_pcap", side_effect=RuntimeError("boom"))
    def test_process_pcap_can_raise_for_strict_callers(self, mocked_load):
        with self.assertRaisesRegex(RuntimeError, "boom"):
            process_pcap("broken.pcap", raise_on_error=True)


if __name__ == "__main__":
    unittest.main()
