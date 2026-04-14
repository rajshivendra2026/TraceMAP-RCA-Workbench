"""
Central Configuration Loader (config.py)

PURPOSE
────────────────────────────────────────────
Loads config.yaml once and provides access via cfg().

KEY FEATURES
────────────────────────────────────────────
✔ Dot-notation access (cfg("tshark.timeout_sec"))
✔ Cached loading (fast)
✔ Absolute path resolution (fixes relative path issues)
✔ Safe defaults (no crashes if key missing)
✔ Production-ready logging support

WHY THIS MATTERS
────────────────────────────────────────────
This file ensures:
  - No hardcoded values in code
  - Easy environment portability
  - Clean separation of config vs logic
"""

import os
from pathlib import Path
from functools import lru_cache
from typing import Any

import yaml


# ============================================================
# CONFIG FILE LOCATION
# ============================================================

# config.yaml MUST be in project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_PATH = _PROJECT_ROOT / "config.yaml"


# ============================================================
# LOAD CONFIG (CACHED)
# ============================================================

@lru_cache(maxsize=1)
def _load() -> dict:
    """
    Load config.yaml once and cache it.

    Raises:
        FileNotFoundError if config missing
        ValueError if malformed
    """

    if not _CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"config.yaml not found at: {_CONFIG_PATH}"
        )

    with _CONFIG_PATH.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("config.yaml is empty or malformed")

    return data


# ============================================================
# CORE ACCESS FUNCTION
# ============================================================

def cfg(dotted_key: str, default: Any = None) -> Any:
    """
    Access config values using dot notation.

    Example:
        cfg("tshark.timeout_sec") → 120
        cfg("server.port") → 5050

    Returns:
        value or default if not found
    """

    env_key = "TC_RCA__" + dotted_key.replace(".", "__").upper()
    if env_key in os.environ:
        return _coerce_env_value(os.environ[env_key])

    try:
        data = _load()
    except Exception:
        return default

    keys = dotted_key.split(".")
    node = data

    for k in keys:
        if isinstance(node, dict) and k in node:
            node = node[k]
        else:
            return default

    return node


# ============================================================
# PATH RESOLUTION (🔥 IMPORTANT FIX)
# ============================================================

def cfg_path(dotted_key: str, default: str = None) -> str:
    """
    Return ABSOLUTE path from config.

    Fixes:
    - Relative path issues
    - Different working directory bugs
    - Docker / CI/CD inconsistencies

    Example:
        cfg_path("data.parsed") → /abs/path/data/parsed
    """

    rel_path = cfg(dotted_key, default)

    if not rel_path:
        return None

    path = Path(rel_path)
    if path.is_absolute():
        return str(path)
    return str((_PROJECT_ROOT / path).resolve())


# ============================================================
# FULL CONFIG (DEBUGGING)
# ============================================================

def cfg_all() -> dict:
    """
    Return full configuration.

    Useful for:
    - Debug logging
    - System introspection
    """
    try:
        return _load()
    except Exception:
        return {}


# ============================================================
# RELOAD CONFIG (TESTING)
# ============================================================

def reload_config():
    """
    Force reload of config.yaml.

    Useful in:
    - Unit tests
    - Dynamic config updates
    """
    _load.cache_clear()


def project_root() -> str:
    """Return the absolute project root directory."""
    return str(_PROJECT_ROOT)


# ============================================================
# LOGGING CONFIG HELPER (OPTIONAL)
# ============================================================

def get_log_config():
    """
    Return logging configuration safely.

    Example:
        level = get_log_config()["level"]
    """

    return {
        "level": cfg("logging.level", "INFO"),
        "log_to_file": cfg("logging.log_to_file", False),
        "log_file": cfg_path("logging.log_file", "logs/app.log"),
    }


def _coerce_env_value(value: str) -> Any:
    text = value.strip()
    if not text:
        return text

    lowered = text.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"

    for caster in (int, float):
        try:
            return caster(text)
        except ValueError:
            continue

    if "," in text:
        return [part.strip() for part in text.split(",") if part.strip()]

    return text
