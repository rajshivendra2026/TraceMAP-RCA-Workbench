import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.parser.tshark_runner import TSharkParseError, TSharkRunner


class TSharkRunnerTests(unittest.TestCase):
    def test_extract_raises_parse_error_on_exit_code_two_with_real_stderr(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap = Path(tmpdir) / "trace.pcap"
            pcap.write_text("pcap", encoding="utf-8")

            with patch("src.parser.tshark_runner.TSharkRunner._resolve_binary", return_value="/usr/bin/tshark"), patch(
                "src.parser.tshark_runner.TSharkRunner._supported_fields", return_value={"frame.number"}
            ), patch(
                "src.parser.tshark_runner.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    ["/usr/bin/tshark"],
                    2,
                    stdout="",
                    stderr="tshark: malformed display filter\n",
                ),
            ):
                runner = TSharkRunner()
                with self.assertRaisesRegex(TSharkParseError, "malformed display filter"):
                    runner.extract(str(pcap), "sip", ["frame.number"])


if __name__ == "__main__":
    unittest.main()
