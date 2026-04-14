# src/parser/tshark_runner.py

import shutil
import subprocess
import csv
from functools import lru_cache
from pathlib import Path
from typing import Optional, List, Dict

from loguru import logger
from src.config import cfg


# ── Exceptions ───────────────────────────────────────────────

class TSharkError(Exception):
    pass


class TSharkNotFoundError(TSharkError):
    pass


class TSharkTimeoutError(TSharkError):
    pass


class TSharkParseError(TSharkError):
    pass


# ── Windows fallback paths ───────────────────────────────────

_WINDOWS_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


# ── Runner ──────────────────────────────────────────────────

class TSharkRunner:

    def __init__(self, binary: Optional[str] = None):
        self.binary = binary or self._resolve_binary()
        self.timeout = cfg("tshark.timeout_sec", 120)
        self.extra = cfg("tshark.extra_flags", ["-n"])

        logger.debug(
            f"TSharkRunner: binary={self.binary} "
            f"timeout={self.timeout}s extra={self.extra}"
        )

    # ── Binary resolution ─────────────────────────────────────

    @staticmethod
    def _resolve_binary() -> str:
        configured = cfg("tshark.binary", "auto")

        if configured and configured != "auto":
            if Path(configured).exists():
                return configured
            raise TSharkNotFoundError(f"Invalid tshark path: {configured}")

        found = shutil.which("tshark")
        if found:
            return found

        for p in _WINDOWS_PATHS:
            if Path(p).exists():
                return p

        raise TSharkNotFoundError("tshark not found. Install Wireshark.")

    # ── CORE FIXED METHOD ─────────────────────────────────────

    def extract(
        self,
        pcap_path: str,
        display_filter: str,
        fields: List[str]
    ) -> List[Dict]:
        pcap = Path(pcap_path)
        if not pcap.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap}")

        if not fields:
            return []

        valid_fields = self._supported_extract_fields(fields)
        if not valid_fields:
            logger.warning(
                f"No supported tshark fields available for filter '{display_filter}'"
            )
            return []

        unsupported = [field for field in fields if field not in valid_fields]
        if unsupported:
            logger.debug(
                f"Skipping unsupported tshark fields for {display_filter}: {unsupported}"
            )

        # Build -e field args
        field_args = []
        for f in valid_fields:
            field_args += ["-e", f]

        # ✅ FIX: use -T fields (NOT json)
        cmd = (
            [self.binary,
             "-r", str(pcap_path),
             "-Y", display_filter,
             "-T", "fields",
             "-E", "separator=|",
             "-E", "quote=d",
             "-E", "occurrence=f"]
            + self.extra
            + field_args
        )

        logger.debug(
            f"tshark filter={display_filter} file={Path(pcap_path).name}"
        )

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError:
            raise TSharkNotFoundError(self.binary)
        except subprocess.TimeoutExpired:
            raise TSharkTimeoutError(f"Timeout: {display_filter}")

        # ── Handle errors ─────────────────────────────────────

        if result.returncode not in (0, 1, 2):
            logger.warning(f"tshark exit={result.returncode}")

        stdout = (result.stdout or "").strip()

        if not stdout:
            stderr = (result.stderr or "").strip()
            real_err = [
                l for l in stderr.splitlines()
                if "hosts" not in l.lower() and l.strip()
            ]

            if real_err:
                logger.warning(
                    f"tshark no output for '{display_filter}' "
                    f"stderr={real_err[0][:150]}"
                )
            return []

        # ── Parse FIELD output (FIXED) ─────────────────────────

        packets = []
        reader = csv.reader(stdout.splitlines(), delimiter="|", quotechar='"')

        for values in reader:
            pkt = {}

            for i, field in enumerate(valid_fields):
                if i < len(values):
                    val = values[i].strip()
                    if val:
                        pkt[field] = val

            if pkt:
                packets.append(pkt)

        logger.debug(
            f"filter={display_filter} → {len(packets)} packets"
        )

        return packets

    def _supported_extract_fields(self, fields: List[str]) -> List[str]:
        supported = self._supported_fields(self.binary)
        if not supported:
            return fields
        return [field for field in fields if field in supported]

    @staticmethod
    @lru_cache(maxsize=4)
    def _supported_fields(binary: str) -> set[str]:
        try:
            result = subprocess.run(
                [binary, "-G", "fields"],
                capture_output=True,
                text=True,
                timeout=20,
            )
        except Exception:
            return set()

        if result.returncode not in (0, 1):
            return set()

        supported = set()
        for line in (result.stdout or "").splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0] in {"F", "P"}:
                supported.add(parts[2].strip())
        return supported

    # ── Version ──────────────────────────────────────────────

    def version(self) -> str:
        try:
            r = subprocess.run(
                [self.binary, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return r.stdout.splitlines()[0]
        except Exception:
            return "unknown"

    # ── Validate PCAP ────────────────────────────────────────

    def validate_pcap(self, pcap_path: str) -> bool:
        try:
            r = subprocess.run(
                [self.binary, "-r", str(pcap_path), "-c", "1"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return r.returncode in (0, 1, 2)
        except Exception:
            return False
