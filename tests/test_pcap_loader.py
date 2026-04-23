import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.parser.pcap_loader import load_pcap
from src.parser.tshark_runner import TSharkParseError


class PcapLoaderTests(unittest.TestCase):
    def test_optional_protocol_parse_error_does_not_fail_upload(self):
        class Runner:
            def __init__(self):
                self.filters = []

            def validate_pcap(self, _pcap_path):
                return True

            def version(self):
                return "mock tshark"

            def extract(self, _pcap_path, display_filter, _fields):
                self.filters.append(display_filter)
                if display_filter == "isakmp":
                    raise TSharkParseError(
                        'tshark: "isakmp" is not a valid protocol or protocol field.'
                    )
                return []

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap = Path(tmpdir) / "trace.pcap"
            pcap.write_text("pcap", encoding="utf-8")
            runner = Runner()

            with patch("src.parser.pcap_loader.cfg", return_value={}):
                result = load_pcap(str(pcap), runner=runner)

        self.assertIn("isakmp", runner.filters)
        self.assertEqual(result["ikev2"], [])


if __name__ == "__main__":
    unittest.main()
