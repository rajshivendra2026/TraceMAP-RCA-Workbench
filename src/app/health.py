import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from src.config import cfg, cfg_path, project_root
from src.parser.tshark_runner import TSharkRunner

from .learning import APP_VERSION


CORE_TSHARK_FIELDS = {
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "sip.Call-ID",
    "diameter.Session-Id",
    "gtp.teid",
    "gtpv2.teid",
}

OPTIONAL_TSHARK_FIELDS = {
    "pfcp.seid",
    "http2.headers.path",
    "isakmp.exchangetype",
    "isakmp.cfg.attr.internal_ip4_address",
}

RUNTIME_DIR_KEYS = {
    "raw_pcaps": ("data.raw_pcaps", "data/raw_pcaps"),
    "knowledge_base": ("data.knowledge_base", "data/knowledge_base"),
}


def build_system_health(model_status: dict | None = None) -> dict:
    release = build_release_info()
    checks = [
        _check_python(),
        _check_runtime_dirs(),
        _check_git_state(),
        _check_auth_mode(),
    ]
    tshark_status, tshark_checks = _check_tshark()
    checks.extend(tshark_checks)

    status = _overall_status(checks)
    return {
        "status": status,
        "score": _readiness_score(checks),
        "version": release["version"],
        "release": release,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "tshark": tshark_status,
        "model": model_status or {},
        "checks": checks,
        "actions": _recommended_actions(checks),
    }


def build_release_info() -> dict:
    commit = (
        os.getenv("TRACEMAP_GIT_COMMIT")
        or os.getenv("GITHUB_SHA")
        or _git_output("rev-parse", "--short", "HEAD")
        or "unknown"
    )
    if len(commit) > 12 and commit != "unknown":
        commit = commit[:12]

    branch = (
        os.getenv("TRACEMAP_GIT_BRANCH")
        or os.getenv("GITHUB_REF_NAME")
        or _git_output("branch", "--show-current")
        or "unknown"
    )
    return {
        "version": os.getenv("TRACEMAP_VERSION") or APP_VERSION,
        "commit": commit,
        "branch": branch,
        "build_time": os.getenv("TRACEMAP_BUILD_TIME") or "local-dev",
        "release_channel": "main" if branch == "main" else "development",
    }


def _check_python() -> dict:
    version = sys.version_info
    status = "ok" if version >= (3, 11) else "warn"
    return _check(
        "python",
        "Python runtime",
        status,
        f"Python {version.major}.{version.minor}.{version.micro}",
        "Recommended runtime is Python 3.11 or newer.",
    )


def _check_runtime_dirs() -> dict:
    results = {}
    failures = []
    for name, (key, default) in RUNTIME_DIR_KEYS.items():
        path = Path(cfg_path(key, default))
        writable = _is_path_writable(path)
        results[name] = {"path": str(path), "writable": writable}
        if not writable:
            failures.append(str(path))

    if failures:
        return _check(
            "runtime_dirs",
            "Runtime directories",
            "fail",
            "One or more runtime directories are not writable.",
            "; ".join(failures),
            {"directories": results},
        )
    return _check(
        "runtime_dirs",
        "Runtime directories",
        "ok",
        "Upload and knowledge-base directories are writable.",
        "The app can persist uploads, jobs, learning state, and analysis artifacts.",
        {"directories": results},
    )


def _check_git_state() -> dict:
    commit = _git_output("rev-parse", "--short", "HEAD")
    branch = _git_output("branch", "--show-current")
    status_lines = (_git_output("status", "--short") or "").splitlines()
    product_dirty = [
        line for line in status_lines
        if not _is_runtime_status_line(line)
    ]
    runtime_dirty = len(status_lines) - len(product_dirty)

    if not commit:
        return _check(
            "git_state",
            "Git release state",
            "warn",
            "Git metadata is unavailable.",
            "Set TRACEMAP_GIT_COMMIT and TRACEMAP_GIT_BRANCH in packaged deployments.",
        )

    if product_dirty:
        return _check(
            "git_state",
            "Git release state",
            "warn",
            f"{len(product_dirty)} product file(s) differ from the checked-out commit.",
            "Commit, stash, or discard local product changes before calling this a release.",
            {"commit": commit, "branch": branch, "dirty_product_files": product_dirty[:10]},
        )

    detail = "Working tree is clean for product files."
    if runtime_dirty:
        detail += f" {runtime_dirty} runtime/local state file(s) are intentionally ignored by this check."
    return _check(
        "git_state",
        "Git release state",
        "ok",
        f"{branch or 'detached'} @ {commit}",
        detail,
        {"commit": commit, "branch": branch, "runtime_dirty_count": runtime_dirty},
    )


def _check_auth_mode() -> dict:
    token = str(cfg("auth.token", "") or "").strip()
    if token:
        return _check(
            "auth",
            "API protection",
            "ok",
            "API token is configured.",
            "Protected routes require Authorization: Bearer or X-API-Key.",
        )
    return _check(
        "auth",
        "API protection",
        "warn",
        "API token is not configured.",
        "Acceptable for local demos; set TC_RCA__AUTH__TOKEN for shared or exposed deployments.",
    )


def _check_tshark() -> tuple[dict, list[dict]]:
    try:
        runner = TSharkRunner()
    except Exception as exc:
        return (
            {"available": False, "error": str(exc)},
            [
                _check(
                    "tshark_available",
                    "TShark availability",
                    "fail",
                    "tshark is not available.",
                    "Install Wireshark/tshark or set TC_RCA__TSHARK__BINARY.",
                )
            ],
        )

    supported = TSharkRunner._supported_fields(runner.binary)
    missing_core = sorted(field for field in CORE_TSHARK_FIELDS if supported and field not in supported)
    missing_optional = sorted(field for field in OPTIONAL_TSHARK_FIELDS if supported and field not in supported)
    has_isakmp = not supported or "isakmp" in supported or "isakmp.exchangetype" in supported
    has_ikev2 = not supported or "ikev2" in supported or "ikev2.exchange_type" in supported

    checks = [
        _check(
            "tshark_available",
            "TShark availability",
            "ok",
            runner.version(),
            f"Using binary: {runner.binary}",
        )
    ]

    if missing_core:
        checks.append(
            _check(
                "tshark_core_fields",
                "Core protocol field support",
                "fail",
                f"Missing {len(missing_core)} core field(s).",
                ", ".join(missing_core),
                {"missing": missing_core},
            )
        )
    else:
        checks.append(
            _check(
                "tshark_core_fields",
                "Core protocol field support",
                "ok",
                "Core SIP, Diameter, GTP, and frame fields are available.",
                "Unsupported optional fields are filtered automatically at extraction time.",
            )
        )

    ike_status = "ok" if has_isakmp or has_ikev2 else "warn"
    ike_summary = "IKE/ePDG compatible mode available." if ike_status == "ok" else "IKE/ePDG fields not detected."
    ike_detail = "This tshark exposes IKEv2 through ISAKMP fields." if has_isakmp and not has_ikev2 else "Native or compatible IKE fields are present."
    checks.append(
        _check(
            "ike_epdg_compatibility",
            "IKE/ePDG compatibility",
            ike_status,
            ike_summary,
            ike_detail,
            {
                "has_isakmp": has_isakmp,
                "has_ikev2": has_ikev2,
                "missing_optional_fields": missing_optional,
            },
        )
    )

    return (
        {
            "available": True,
            "version": runner.version(),
            "binary": runner.binary,
            "isakmp_compat": has_isakmp,
            "ikev2_native": has_ikev2,
        },
        checks,
    )


def _overall_status(checks: list[dict]) -> str:
    if any(check["status"] == "fail" for check in checks):
        return "fail"
    if any(check["status"] == "warn" for check in checks):
        return "warn"
    return "ok"


def _readiness_score(checks: list[dict]) -> int:
    score = 100
    for check in checks:
        if check["status"] == "fail":
            score -= 22
        elif check["status"] == "warn":
            score -= 7
    return max(0, min(100, score))


def _recommended_actions(checks: list[dict]) -> list[str]:
    actions = []
    for check in checks:
        if check["status"] == "ok":
            continue
        if check["id"] == "tshark_available":
            actions.append("Install Wireshark/tshark and rerun scripts/preflight.py.")
        elif check["id"] == "tshark_core_fields":
            actions.append("Upgrade Wireshark/tshark or validate the installed dissector set.")
        elif check["id"] == "runtime_dirs":
            actions.append("Fix permissions for data/raw_pcaps and data/knowledge_base.")
        elif check["id"] == "auth":
            actions.append("Set TC_RCA__AUTH__TOKEN before exposing the tool beyond localhost.")
        elif check["id"] == "git_state":
            actions.append("Release from a clean product working tree or a tagged commit.")
        elif check["id"] == "ike_epdg_compatibility":
            actions.append("Use a Wireshark build with ISAKMP/IKE dissector support for VoWiFi/ePDG traces.")
    return actions[:6]


def _check(
    check_id: str,
    label: str,
    status: str,
    summary: str,
    detail: str,
    meta: dict | None = None,
) -> dict:
    return {
        "id": check_id,
        "label": label,
        "status": status,
        "summary": summary,
        "detail": detail,
        "meta": meta or {},
    }


def _git_output(*args: str) -> str | None:
    git = os.getenv("GIT_BINARY") or "git"
    try:
        result = subprocess.run(
            [git, *args],
            cwd=project_root(),
            capture_output=True,
            text=True,
            timeout=3,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return (result.stdout or "").strip() or None


def _is_path_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, prefix=".tracemap-write-", delete=True):
            return True
    except Exception:
        return False


def _is_runtime_status_line(line: str) -> bool:
    path = line[3:].strip() if len(line) > 3 else line.strip()
    return (
        path.startswith("data/knowledge_base/")
        or path.startswith("data/raw_pcaps/")
        or path.startswith("data/parsed/")
        or path.startswith("logs/")
        or path.startswith(".cache/")
        or path.startswith("~$")
    )


__all__ = ["build_release_info", "build_system_health"]
