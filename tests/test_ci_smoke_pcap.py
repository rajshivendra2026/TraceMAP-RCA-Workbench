import socket
import struct
import time
import unittest
from pathlib import Path

from src.parser.pcap_loader import load_pcap
from src.parser.tshark_runner import TSharkNotFoundError, TSharkRunner


class SamplePcapSmokeTests(unittest.TestCase):
    def test_generated_sip_pcap_decodes_through_real_tshark_path(self):
        try:
            runner = TSharkRunner()
        except TSharkNotFoundError as exc:
            self.skipTest(str(exc))

        pcap_path = Path("data/raw_pcaps/.ci-smoke-sip.pcap")
        pcap_path.parent.mkdir(parents=True, exist_ok=True)
        pcap_path.write_bytes(_build_sip_invite_pcap())
        self.addCleanup(lambda: pcap_path.exists() and pcap_path.unlink())

        parsed = load_pcap(str(pcap_path), runner=runner)

        self.assertGreaterEqual(len(parsed["sip"]), 1)
        self.assertEqual(parsed["sip"][0]["call_id"], "smoke-call-1@example.com")
        self.assertEqual(parsed["sip"][0]["method"], "INVITE")


def _build_sip_invite_pcap() -> bytes:
    payload = (
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-smoke\r\n"
        "From: <sip:alice@example.com>;tag=from1\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: smoke-call-1@example.com\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:alice@10.0.0.1>\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode("ascii")

    udp = _udp_packet("10.0.0.1", "10.0.0.2", 5060, 5060, payload)
    ethernet = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack("!H", 0x0800)
    frame = ethernet + udp
    now = int(time.time())
    pcap_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", now, 0, len(frame), len(frame))
    return pcap_header + packet_header + frame


def _udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    udp_length = 8 + len(payload)
    total_length = 20 + udp_length
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        17,
        0,
        src,
        dst,
    )
    checksum = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        17,
        checksum,
        src,
        dst,
    )
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    return ip_header + udp_header + payload


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


if __name__ == "__main__":
    unittest.main()
