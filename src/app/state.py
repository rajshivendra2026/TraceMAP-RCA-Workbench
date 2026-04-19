import time
import uuid
from threading import Lock, RLock

from src.config import cfg


_store: dict[str, dict] = {}
_lock = Lock()
_job_store: dict[str, dict] = {}
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
        "jobs": len(_job_store),
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
    ttl_sec = int(cfg("server.session_ttl_sec", 3600))
    with _job_lock:
        purge_expired_jobs(locked=True)
        _job_store[job_id] = payload
        while len(_job_store) > int(cfg("server.max_cached_uploads", 20)) * 4:
            oldest = min(_job_store.items(), key=lambda item: item[1]["updated_at"])[0]
            _job_store.pop(oldest, None)
    return dict(payload)


def update_job(job_id: str, **values) -> dict | None:
    with _job_lock:
        entry = _job_store.get(job_id)
        if not entry:
            return None
        entry.update(values)
        entry["updated_at"] = time.time()
        return dict(entry)


def get_job(job_id: str) -> dict | None:
    purge_expired_jobs()
    with _job_lock:
        entry = _job_store.get(job_id)
        return dict(entry) if entry else None


def purge_expired_jobs(locked: bool = False) -> None:
    ttl_sec = int(cfg("server.session_ttl_sec", 3600))
    now = time.time()

    def purge() -> None:
        expired = [job_id for job_id, entry in _job_store.items() if now - float(entry.get("updated_at", now)) > ttl_sec]
        for job_id in expired:
            _job_store.pop(job_id, None)

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
