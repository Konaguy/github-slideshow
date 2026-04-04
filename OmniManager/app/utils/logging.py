"""
Structured logging setup for OmniManager.
Configures a rotating file handler and a console handler.
Call setup_logging(app) once inside create_app().
"""
import logging
import os
from logging.handlers import RotatingFileHandler

LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(app):
    level = logging.DEBUG if app.debug else logging.INFO
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    # ── Rotating file handler ─────────────────────────────────────────────────
    log_dir = os.path.join(app.root_path, "..", "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "omnimanager.log")

    file_handler = RotatingFileHandler(
        log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    # ── Console handler ───────────────────────────────────────────────────────
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    # Apply to Flask app logger
    app.logger.handlers.clear()
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(level)

    # Apply to root logger so background thread errors are captured too
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(file_handler)
    root.addHandler(console_handler)
    root.setLevel(level)

    # Quieten noisy third-party loggers
    for noisy in ("werkzeug", "engineio", "socketio", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    app.logger.info("OmniManager starting — log level: %s", logging.getLevelName(level))
