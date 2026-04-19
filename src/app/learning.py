import hashlib
import json
import time
from collections import Counter
from pathlib import Path

from loguru import logger

from src.config import cfg_path

from .state import get_learning_status, update_job, update_learning_status


APP_VERSION = "v1.1.0"
VERSION_HISTORY_PATH = Path(cfg_path("docs.version_history", "docs/version_history.json"))


def learning_base_dir() -> Path:
    return Path(cfg_path("data.knowledge_base", "data/knowledge_base"))


def learning_manifest_path() -> Path:
    return learning_base_dir() / "processed_sources.json"


def learning_settings_path() -> Path:
    return learning_base_dir() / "learning_settings.json"


def load_learning_manifest() -> dict:
    path = learning_manifest_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_learning_manifest(payload: dict) -> None:
    path = learning_manifest_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_learning_settings() -> dict:
    path = learning_settings_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_learning_settings(payload: dict) -> None:
    path = learning_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def default_learning_path() -> str:
    settings = load_learning_settings()
    path = settings.get("learn_path") or cfg_path("data.raw_pcaps", "data/raw_pcaps")
    return str(Path(path).expanduser().resolve())


def save_default_learning_path(path_value: str) -> str:
    resolved = str(Path(path_value).expanduser().resolve())
    settings = load_learning_settings()
    settings["learn_path"] = resolved
    settings["updated_at"] = time.time()
    save_learning_settings(settings)
    return resolved


def discover_pcaps(root_path: str) -> list[dict]:
    base = Path(root_path)
    files = []
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
            continue
        stat = path.stat()
        signature = hashlib.sha1(
            f"{path.resolve()}::{stat.st_size}::{int(stat.st_mtime)}".encode("utf-8")
        ).hexdigest()
        files.append(
            {
                "path": str(path.resolve()),
                "name": path.name,
                "signature": signature,
                "size": stat.st_size,
                "mtime": int(stat.st_mtime),
            }
        )
    return files


def run_learning_job(learn_path: str, pending_files: list[dict], job_id: str | None = None) -> None:
    from src.pipeline import process_pcap

    manifest = load_learning_manifest()
    processed = 0
    total = len(pending_files)

    try:
        for item in pending_files:
            if job_id:
                update_job(
                    job_id,
                    status="running",
                    message=f"Learning in progress: {processed}/{total} PCAPs processed",
                    progress=round((processed / max(total, 1)) * 100, 1),
                    processed_pcaps=processed,
                    total_pcaps=total,
                    path=learn_path,
                )
            process_pcap(item["path"])
            manifest[item["signature"]] = {
                "path": item["path"],
                "name": item["name"],
                "size": item["size"],
                "mtime": item["mtime"],
                "learned_at": time.time(),
            }
            processed += 1
            save_learning_manifest(manifest)
            update_learning_status(
                running=True,
                message=f"Learning in progress: {processed}/{len(pending_files)} PCAPs processed",
                path=learn_path,
                processed_pcaps=processed,
                new_pcaps=len(pending_files),
            )

        result = {"processed_pcaps": processed, "path": learn_path}
        if job_id:
            update_job(
                job_id,
                status="completed",
                message=f"Learning complete. Processed {processed} new PCAP(s).",
                progress=100,
                processed_pcaps=processed,
                total_pcaps=total,
                path=learn_path,
                result=result,
            )
        update_learning_status(
            running=False,
            message=f"Learning complete. Processed {processed} new PCAP(s).",
            path=learn_path,
            finished_at=time.time(),
            processed_pcaps=processed,
            new_pcaps=len(pending_files),
            last_result=result,
            learning_job_id=job_id,
        )
    except Exception as exc:
        logger.exception(f"Learning job failed: {exc}")
        if job_id:
            update_job(
                job_id,
                status="failed",
                message=f"Learning failed: {exc}",
                error=str(exc),
                progress=round((processed / max(total, 1)) * 100, 1),
                processed_pcaps=processed,
                total_pcaps=total,
                path=learn_path,
            )
        update_learning_status(
            running=False,
            message=f"Learning failed: {exc}",
            path=learn_path,
            finished_at=time.time(),
            processed_pcaps=processed,
            new_pcaps=len(pending_files),
            learning_job_id=job_id,
        )


def load_learning_metrics() -> dict:
    path = learning_base_dir() / "metrics.json"
    data = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    data.setdefault("pattern_count", 0)
    data["learned_pcap_count"] = len(load_learning_manifest())
    data["default_learning_path"] = default_learning_path()
    return data


def load_validation_queue() -> dict:
    path = learning_base_dir() / "validation_queue.json"
    queue = []
    if path.exists():
        try:
            queue = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            queue = []
    pending = [item for item in queue if item.get("validation_status", "pending_review") == "pending_review"]
    pending = sorted(
        pending,
        key=lambda item: (
            float(item.get("confidence_score", 0.0)),
            float(item.get("similarity", 0.0)),
        ),
    )
    label_counts = Counter(
        item.get("hybrid_root_cause")
        or item.get("knowledge_root_cause")
        or item.get("rule_root_cause")
        or "UNKNOWN"
        for item in pending
    )
    return {
        "queue_size": len(queue),
        "pending_count": len(pending),
        "label_counts": dict(label_counts.most_common(8)),
        "items": pending[:8],
    }


def load_version_history() -> dict:
    history = []
    if VERSION_HISTORY_PATH.exists():
        try:
            history = json.loads(VERSION_HISTORY_PATH.read_text(encoding="utf-8"))
        except Exception:
            history = []
    return {"version": APP_VERSION, "history": history}


__all__ = [
    "APP_VERSION",
    "default_learning_path",
    "discover_pcaps",
    "get_learning_status",
    "learning_base_dir",
    "load_learning_manifest",
    "load_learning_metrics",
    "load_learning_settings",
    "load_validation_queue",
    "load_version_history",
    "run_learning_job",
    "save_default_learning_path",
    "save_learning_manifest",
    "save_learning_settings",
    "update_learning_status",
]
