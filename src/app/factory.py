import sys
import time
import uuid
from pathlib import Path
from threading import Thread

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from loguru import logger
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from src.config import cfg, cfg_path, get_log_config, project_root
from src.correlation.cause_mapper import apply_correlation
from src.correlation.session_builder import build_sessions
from src.features.feature_engineer import extract_features
from src.intelligence.knowledge_engine import KnowledgeEngine
from src.intelligence.learning_loop import run_learning_cycle
from src.ml.retrain import retrain_from_feedback
from src.ml.predict import predict_session
from src.parser.pcap_loader import load_pcap
from src.parser.tshark_runner import TSharkRunner
from src.rules.rca_rules import apply_rca

from .learning import (
    APP_VERSION,
    default_learning_path,
    discover_pcaps,
    get_learning_status,
    load_learning_manifest,
    load_learning_metrics,
    load_learning_settings,
    load_validation_queue,
    load_version_history,
    run_learning_job,
    save_default_learning_path,
    update_learning_status,
)
from .state import (
    cache_stats,
    create_job,
    fail_incomplete_jobs,
    find_session,
    get_job,
    purge_expired_jobs,
    purge_expired_sessions,
    store_sessions,
    update_job,
)
from .summary import build_capture_graph, build_capture_summary, session_summary


BASE_DIR = Path(project_root())
_logger_configured = False


def configure_logging() -> None:
    global _logger_configured
    if _logger_configured:
        return

    log_cfg = get_log_config()
    logger.remove()
    logger.add(
        sys.stdout,
        level=log_cfg["level"],
        format=cfg(
            "logging.format",
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level:5}</level> | {message}",
        ),
        colorize=True,
    )

    if log_cfg["log_to_file"] and log_cfg["log_file"]:
        log_path = Path(log_cfg["log_file"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            str(log_path),
            level=log_cfg["level"],
            rotation=cfg("logging.rotation", "10 MB"),
            retention=cfg("logging.retention", "14 days"),
            enqueue=True,
        )

    _logger_configured = True


def create_app() -> Flask:
    configure_logging()
    recovered_jobs = fail_incomplete_jobs()
    if recovered_jobs:
        logger.warning(f"Marked {recovered_jobs} interrupted background job(s) as failed on startup")

    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = int(
        cfg("server.max_upload_mb", 500) * 1024 * 1024
    )

    cors_origins = cfg("server.cors_origins", ["http://localhost:5050", "http://127.0.0.1:5050"])
    CORS(app, resources={r"/api/*": {"origins": cors_origins}, r"/upload": {"origins": cors_origins}})

    @app.before_request
    def require_api_auth():
        if request.method == "OPTIONS":
            return None
        if request.path in {"/", "/health"} or request.path.startswith("/css/") or request.path.startswith("/js/"):
            return None
        if not (request.path.startswith("/api/") or request.path == "/upload"):
            return None

        token = str(cfg("auth.token", "") or "").strip()
        if not token:
            return None

        provided = _request_auth_token()
        if provided == token:
            return None

        return jsonify({"error": "Unauthorized"}), 401

    @app.errorhandler(RequestEntityTooLarge)
    def handle_upload_too_large(_exc):
        return jsonify({"error": "Uploaded file exceeds configured size limit"}), 413

    @app.errorhandler(404)
    def handle_not_found(_exc):
        return jsonify({"error": "Not found"}), 404

    @app.route("/")
    def serve_index():
        return send_from_directory(BASE_DIR, "index.html")

    @app.route("/css/<path:filename>")
    def serve_css(filename):
        response = send_from_directory(BASE_DIR / "css", filename)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    @app.route("/js/<path:filename>")
    def serve_js(filename):
        response = send_from_directory(BASE_DIR / "js", filename)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    @app.route("/health")
    def health():
        status = system_status()
        return jsonify(
            {
                "status": "ok",
                "version": "production-hardened",
                "tshark": status["tshark"],
                "model": status["model"],
                "cache": cache_stats(),
            }
        )

    @app.route("/api/model-status")
    def model_status():
        return jsonify(load_model_status())

    @app.route("/api/version-history")
    def version_history():
        return jsonify(load_version_history())

    @app.route("/api/debug/frontend", methods=["POST"])
    def frontend_debug():
        payload = request.get_json(silent=True) or {}
        logger.debug(f"Frontend debug: {payload}")
        return jsonify({"ok": True})

    @app.route("/api/learning/status")
    def learning_status():
        return jsonify(
            {
                "version": APP_VERSION,
                "status": get_learning_status(),
                "knowledge": load_learning_metrics(),
                "settings": load_learning_settings(),
            }
        )

    @app.route("/api/learning/path", methods=["POST"])
    def learning_path_update():
        payload = request.get_json(silent=True) or {}
        raw_path = payload.get("path")
        if not raw_path:
            return jsonify({"error": "path is required"}), 400

        resolved = str(Path(raw_path).expanduser().resolve())
        if not Path(resolved).exists():
            return jsonify({"error": f"Learning path not found: {resolved}"}), 404

        saved_path = save_default_learning_path(resolved)
        update_learning_status(path=saved_path)
        return jsonify(
            {
                "saved": True,
                "path": saved_path,
                "status": get_learning_status(),
                "knowledge": load_learning_metrics(),
                "settings": load_learning_settings(),
            }
        )

    @app.route("/api/learning/validation")
    def learning_validation():
        return jsonify(load_validation_queue())

    @app.route("/api/learning/validation/action", methods=["POST"])
    def learning_validation_action():
        payload = request.get_json(silent=True) or {}
        validation_id = payload.get("validation_id")
        action = payload.get("action")
        note = payload.get("note")
        reviewer = payload.get("reviewer", "analyst")

        if not validation_id or not action:
            return jsonify({"error": "validation_id and action are required"}), 400

        try:
            knowledge = KnowledgeEngine()
            result = knowledge.resolve_validation(validation_id, action, reviewer=reviewer, note=note)
            if not result:
                return jsonify({"error": "Validation item not found"}), 404
            retraining = None
            retraining_started = False
            if bool(cfg("learning.feedback_retrain_enabled", True)):
                retraining = _start_feedback_retraining(knowledge)
                retraining_started = bool(retraining)
            return jsonify(
                {
                    "updated": result,
                    "queue": load_validation_queue(),
                    "knowledge": load_learning_metrics(),
                    "status": get_learning_status(),
                    "retraining": retraining,
                    "retraining_started": retraining_started,
                }
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/learning/start", methods=["POST"])
    def learning_start():
        payload = request.get_json(silent=True) or {}
        learn_path = payload.get("path") or default_learning_path()
        learn_path = str(Path(learn_path).expanduser().resolve())

        if not Path(learn_path).exists():
            return jsonify({"error": f"Learning path not found: {learn_path}"}), 404

        save_default_learning_path(learn_path)

        manifest = load_learning_manifest()
        files = discover_pcaps(learn_path)
        pending = [item for item in files if item["signature"] not in manifest]

        if not pending:
            update_learning_status(
                running=False,
                message="System learning is up to date. No new PCAPs found.",
                path=learn_path,
                started_at=None,
                finished_at=time.time(),
                new_pcaps=0,
                processed_pcaps=0,
                last_result={"processed_pcaps": 0},
                learning_job_id=None,
            )
            return jsonify(
                {
                    "started": False,
                    "status": get_learning_status(),
                    "knowledge": load_learning_metrics(),
                }
            )

        if get_learning_status()["running"]:
            return jsonify({"error": "Learning job already in progress"}), 409

        update_learning_status(
            running=True,
            message=f"Learning started for {len(pending)} new PCAP(s)",
            path=learn_path,
            started_at=time.time(),
            finished_at=None,
            new_pcaps=len(pending),
            processed_pcaps=0,
            last_result=None,
            learning_job_id=None,
        )

        job = create_job(
            "learning",
            path=learn_path,
            progress=0,
            processed_pcaps=0,
            total_pcaps=len(pending),
            pending_pcaps=len(pending),
        )
        update_learning_status(learning_job_id=job["job_id"])
        Thread(
            target=run_learning_job,
            args=(learn_path, pending, job["job_id"]),
            daemon=True,
        ).start()

        return jsonify(
            {
                "started": True,
                "job_id": job["job_id"],
                "job": job,
                "status": get_learning_status(),
                "knowledge": load_learning_metrics(),
            }
        )

    @app.route("/upload", methods=["POST"])
    def upload():
        purge_expired_sessions()
        purge_expired_jobs()
        uploaded = request.files.get("file")

        if not uploaded or not uploaded.filename:
            return jsonify({"error": "No file uploaded"}), 400

        if not is_allowed_pcap(uploaded.filename):
            return jsonify({"error": "Unsupported file type"}), 400

        save_path = build_upload_path(uploaded.filename)

        try:
            save_path.parent.mkdir(parents=True, exist_ok=True)
            uploaded.save(save_path)
            job = create_job(
                "upload",
                filename=save_path.name,
                original_filename=Path(uploaded.filename or save_path.name).name,
                path=str(save_path),
                progress=5,
            )
            Thread(
                target=_run_upload_job,
                args=(job["job_id"], save_path, Path(uploaded.filename or save_path.name).name),
                daemon=True,
            ).start()
            return (
                jsonify(
                    {
                        "accepted": True,
                        "job_id": job["job_id"],
                        "filename": save_path.name,
                        "status": job,
                    }
                ),
                202,
            )
        except FileNotFoundError as exc:
            logger.error(f"Upload file error: {exc}")
            return jsonify({"error": str(exc)}), 404
        except ValueError as exc:
            logger.error(f"Upload validation error: {exc}")
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            logger.exception(f"Upload processing failed: {exc}")
            return jsonify({"error": "Failed to process uploaded PCAP"}), 500

    @app.route("/api/upload-status/<job_id>")
    def upload_status(job_id: str):
        job = get_job(job_id)
        if not job or job.get("kind") != "upload":
            return jsonify({"error": "Upload job not found"}), 404
        return jsonify(job)

    @app.route("/api/job-status/<job_id>")
    def job_status(job_id: str):
        job = get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify(job)

    @app.route("/api/analyze-call", methods=["POST"])
    def analyze_call():
        data = request.get_json(silent=True) or {}
        call_id = data.get("call_id")
        token = data.get("token")

        if not call_id:
            return jsonify({"error": "call_id is required"}), 400

        session = find_session(call_id, token=token)
        if not session:
            return jsonify({"error": "Session not found"}), 404

        try:
            result = predict_session(session)
            return jsonify({**result, "features": extract_features(session)})
        except Exception as exc:
            logger.exception(f"Analysis failed for {call_id}: {exc}")
            return jsonify({"error": "Failed to analyze session"}), 500

    return app


def build_upload_path(original_name: str) -> Path:
    safe_name = secure_filename(Path(original_name).name) or f"upload-{uuid.uuid4().hex}.pcap"
    stem = Path(safe_name).stem[:80] or "upload"
    suffix = Path(safe_name).suffix.lower() or ".pcap"
    upload_dir = Path(cfg_path("data.raw_pcaps", "data/raw_pcaps"))
    unique_name = f"{stem}-{uuid.uuid4().hex[:8]}{suffix}"
    return upload_dir / unique_name


def is_allowed_pcap(filename: str) -> bool:
    allowed = {ext.lower() for ext in cfg("server.allowed_extensions", [".pcap", ".pcapng", ".cap"])}
    return Path(filename).suffix.lower() in allowed


def _request_auth_token() -> str | None:
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        candidate = auth_header[7:].strip()
        if candidate:
            return candidate

    for header_name in ("X-API-Key", "X-Auth-Token"):
        candidate = (request.headers.get(header_name) or "").strip()
        if candidate:
            return candidate

    return None


def system_status() -> dict:
    try:
        tshark = TSharkRunner()
        tshark_status = {"available": True, "version": tshark.version()}
    except Exception as exc:
        tshark_status = {"available": False, "error": str(exc)}

    return {"tshark": tshark_status, "model": load_model_status()}


def load_model_status() -> dict:
    model_path = Path(cfg_path("model.path", "data/models/rca_model.pkl"))
    encoder_path = Path(cfg_path("model.encoder_path", "data/models/label_encoder.pkl"))
    meta_path = Path(cfg_path("model.meta_path", "data/models/model_meta.json"))

    status = {
        "trained": model_path.exists() and encoder_path.exists(),
        "model_path": str(model_path),
        "encoder_path": str(encoder_path),
        "meta_path": str(meta_path),
    }

    if meta_path.exists():
        try:
            import json

            status["meta"] = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception as exc:
            status["meta_error"] = str(exc)

    return status


app = create_app()


def _run_upload_job(job_id: str, save_path: Path, original_name: str) -> None:
    try:
        logger.info(f"Loading PCAP asynchronously: {save_path.name}")
        update_job(job_id, status="running", message="Extracting and decoding PCAP", progress=15)

        parsed = load_pcap(str(save_path))
        update_job(job_id, status="running", message="Correlating sessions", progress=45)

        sessions = apply_correlation(apply_rca(build_sessions(parsed)))
        for session in sessions:
            session["pcap_source"] = save_path.stem

        update_job(job_id, status="running", message="Running learning and RCA enrichment", progress=70)
        learning = run_learning_cycle(
            sessions,
            compact=bool(cfg("learning.compact_on_upload", False)),
            export_skills=bool(cfg("learning.export_skill_on_upload", False)),
        )
        sessions = learning["sessions"]
        graph = build_capture_graph(parsed)
        token = store_sessions(sessions)
        payload = {
            "token": token,
            "filename": save_path.name,
            "sessions": [session_summary(s) for s in sessions],
            "graph": graph,
            "summary": build_capture_summary(
                parsed,
                sessions,
                capture_meta={
                    "filename": original_name,
                    "stored_filename": save_path.name,
                    "size_bytes": save_path.stat().st_size if save_path.exists() else None,
                },
            ),
            "learning": learning["metrics"],
            "model": load_model_status(),
        }
        update_job(
            job_id,
            status="completed",
            message=f"Processed {len(sessions)} session(s)",
            progress=100,
            result=payload,
        )
    except FileNotFoundError as exc:
        logger.error(f"Async upload file error: {exc}")
        update_job(job_id, status="failed", message=str(exc), error=str(exc))
    except ValueError as exc:
        logger.error(f"Async upload validation error: {exc}")
        update_job(job_id, status="failed", message=str(exc), error=str(exc))
    except Exception as exc:
        logger.exception(f"Async upload processing failed: {exc}")
        update_job(job_id, status="failed", message="Failed to process uploaded PCAP", error=str(exc))


def _start_feedback_retraining(knowledge: KnowledgeEngine) -> dict | None:
    status = get_learning_status()
    if status.get("retraining_running"):
        job_id = status.get("retraining_job_id")
        return get_job(job_id) if job_id else None

    dataset_path = str((knowledge.base_dir / "feedback_dataset.jsonl").resolve())
    job = create_job(
        "retraining",
        dataset_path=dataset_path,
        progress=0,
        message="Queued retraining candidate models from analyst feedback",
    )
    update_learning_status(
        retraining_running=True,
        retraining_message="Retraining candidate models from analyst feedback…",
        retraining_job_id=job["job_id"],
    )
    Thread(
        target=_run_feedback_retraining,
        args=(dataset_path, job["job_id"]),
        daemon=True,
    ).start()
    return job


def _run_feedback_retraining(dataset_path: str, job_id: str) -> None:
    try:
        update_job(
            job_id,
            status="running",
            message="Retraining candidate models from analyst feedback…",
            progress=15,
        )
        retraining = retrain_from_feedback(
            dataset_path=dataset_path,
            min_samples=int(cfg("learning.feedback_min_samples", 3)),
        )
        update_job(
            job_id,
            status="completed",
            message=(retraining or {}).get("message", "Retraining complete"),
            progress=100,
            result=retraining,
        )
        update_learning_status(
            last_retraining=retraining,
            last_retraining_at=time.time(),
            retraining_running=False,
            retraining_message="Retraining complete",
            retraining_job_id=job_id,
        )
    except Exception as exc:
        logger.exception(f"Feedback retraining failed: {exc}")
        update_job(
            job_id,
            status="failed",
            message=f"Retraining failed: {exc}",
            error=str(exc),
        )
        update_learning_status(
            retraining_running=False,
            retraining_message=f"Retraining failed: {exc}",
            retraining_job_id=job_id,
        )
