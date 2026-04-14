from src.app import (
    app,
    build_capture_graph,
    build_capture_summary,
    build_session_details_summary,
    build_session_graph,
    build_trace_details_summary,
    classify_node,
    create_app,
)
from src.app.factory import configure_logging, load_model_status, system_status


if __name__ == "__main__":
    from loguru import logger

    from src.config import cfg

    configure_logging()
    status = system_status()
    logger.info("=" * 50)
    logger.info("Telecom RCA Platform")
    logger.info("=" * 50)
    if status["tshark"]["available"]:
        logger.info(f"TShark OK: {status['tshark']['version']}")
    else:
        logger.warning(f"TShark unavailable: {status['tshark'].get('error', 'unknown error')}")

    host = cfg("server.host", "0.0.0.0")
    port = int(cfg("server.port", 5050))
    debug = bool(cfg("server.debug", False))
    logger.info(f"Running on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
