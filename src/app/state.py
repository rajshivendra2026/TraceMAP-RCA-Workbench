import json
import sqlite3
import time
import uuid
from pathlib import Path
from threading import Lock, RLock

from src.config import cfg, cfg_path


_store: dict[str, dict] = {}
_lock = Lock()
_job_lock = Lock()
_learning_lock = RLock()
_learning_status = {
    "running": False,
    "message": "Idle",
    "path": None,
    "started_at": None,
    "finished_at": None,
    "new_pcaps": 0,
    "processed_pcaps": 0,
    "last_result": None,
    "last_retraining": None,
    "last_retraining_at": None,
    "retraining_running": False,
    "retraining_message": "Idle",
    "retraining_job_id": None,
    "learning_job_id": None,
}


def store_sessions(sessions: list) -> str:
    token = str(uuid.uuid4())
    max_cached = int(cfg("server.max_cached_uploads", 20))
    with _lock:
        purge_expired_sessions(locked=True)
        _store[token] = {"sessions": sessions, "ts": time.monotonic()}
        while len(_store) > max_cached:
            oldest = min(_store.items(), key=lambda item: item[1]["ts"])[0]
            _store.pop(oldest, None)
    return token


def find_session(call_id: str, token: str | None = None):
    purge_expired_sessions()
    with _lock:
        if token and token in _store:
            for session in _store[token]["sessions"]:
                if session.get("call_id") == call_id:
                    return session

        for entry in _store.values():
            for session in entry["sessions"]:
                if session.get("call_id") == call_id:
                    return session
    return None


def purge_expired_sessions(locked: bool = False) -> None:
    ttl_sec = int(cfg("server.session_ttl_sec", 3600))
    now = time.monotonic()

    def purge() -> None:
        expired = [token for token, entry in _store.items() if now - entry["ts"] > ttl_sec]
        for token in expired:
            _store.pop(token, None)

    if locked:
        purge()
        return

    with _lock:
        purge()


def cache_stats() -> dict:
    return {
        "entries": len(_store),
        "jobs": _job_count(),
        "ttl_sec": int(cfg("server.session_ttl_sec", 3600)),
    }


def create_job(kind: str, **values) -> dict:
    job_id = str(uuid.uuid4())
    now = time.time()
    payload = {
        "job_id": job_id,
        "kind": kind,
        "status": "queued",
        "message": "Queued",
        "created_at": now,
        "updated_at": now,
    }
    payload.update(values)
    with _job_lock:
        _init_job_store()
        purge_expired_jobs(locked=True)
        with _job_conn() as conn:
            conn.execute(
                """
                INSERT INTO jobs (job_id, kind, status, created_at, updated_at, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    kind,
                    payload["status"],
                    payload["created_at"],
                    payload["updated_at"],
                    json.dumps(payload),
                ),
            )
            conn.commit()
        _trim_jobs_locked()
    return dict(payload)


def update_job(job_id: str, **values) -> dict | None:
    with _job_lock:
        _init_job_store()
        entry = _fetch_job_locked(job_id)
        if not entry:
            return None
        entry.update(values)
        entry["updated_at"] = time.time()
        with _job_conn() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = ?, updated_at = ?, payload = ?
                WHERE job_id = ?
                """,
                (
                    entry.get("status", "queued"),
                    entry["updated_at"],
                    json.dumps(entry),
                    job_id,
                ),
            )
            conn.commit()
        return dict(entry)


def get_job(job_id: str) -> dict | None:
    purge_expired_jobs()
    with _job_lock:
        _init_job_store()
        entry = _fetch_job_locked(job_id)
        return dict(entry) if entry else None


def fail_incomplete_jobs(reason: str = "Job interrupted by app restart") -> int:
    with _job_lock:
        _init_job_store()
        with _job_conn() as conn:
            rows = conn.execute(
                "SELECT job_id, payload FROM jobs WHERE status IN ('queued', 'running')"
            ).fetchall()
            updated = 0
            now = time.time()
            for row in rows:
                try:
                    entry = json.loads(row["payload"])
                except Exception:
                    continue
                entry.update(
                    {
                        "status": "failed",
                        "message": reason,
                        "error": reason,
                        "updated_at": now,
                    }
                )
                conn.execute(
                    """
                    UPDATE jobs
                    SET status = ?, updated_at = ?, payload = ?
                    WHERE job_id = ?
                    """,
                    ("failed", now, json.dumps(entry), row["job_id"]),
                )
                updated += 1
            conn.commit()
        return updated


def purge_expired_jobs(locked: bool = False) -> None:
    ttl_sec = int(cfg("server.session_ttl_sec", 3600))
    now = time.time()

    def purge() -> None:
        _init_job_store()
        cutoff = now - ttl_sec
        with _job_conn() as conn:
            conn.execute("DELETE FROM jobs WHERE updated_at < ?", (cutoff,))
            conn.commit()

    if locked:
        purge()
        return

    with _job_lock:
        purge()


def update_learning_status(**values) -> None:
    with _learning_lock:
        _learning_status.update(values)


def get_learning_status() -> dict:
    with _learning_lock:
        return dict(_learning_status)


def _job_store_path() -> Path:
    return Path(cfg_path("data.jobs_db", "data/knowledge_base/jobs.sqlite"))


def _job_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_job_store_path(), timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def _init_job_store() -> None:
    path = _job_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _job_conn() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        conn.commit()


def _fetch_job_locked(job_id: str) -> dict | None:
    with _job_conn() as conn:
        row = conn.execute("SELECT payload FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["payload"])
    except Exception:
        return None


def _job_count() -> int:
    with _job_lock:
        _init_job_store()
        with _job_conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM jobs").fetchone()
        return int(row["count"] if row else 0)


def _trim_jobs_locked() -> None:
    max_jobs = int(cfg("server.max_cached_uploads", 20)) * 4
    with _job_conn() as conn:
        row = conn.execute("SELECT COUNT(*) AS count FROM jobs").fetchone()
        count = int(row["count"] if row else 0)
        if count <= max_jobs:
            return
        excess = count - max_jobs
        conn.execute(
            """
            DELETE FROM jobs
            WHERE job_id IN (
                SELECT job_id
                FROM jobs
                ORDER BY updated_at ASC
                LIMIT ?
            )
            """,
            (excess,),
        )
        conn.commit()
