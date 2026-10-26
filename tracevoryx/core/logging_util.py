"""Structured logging with secret redaction.

All tracevoryx logs go through here: JSON-lines to stdout + rotation to
data/logs/tw.log. Values whose keys look secret-bearing are redacted before
formatting; loggers must never stringify raw evidence.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any

_REDACT_KEYS = {"token", "password", "secret", "authorization", "cookie",
                "apikey", "api_key", "clipboard_text", "content"}
_LOG = None


class _RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return True


def _safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if k.lower() in _REDACT_KEYS else _safe(v))
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe(v) for v in obj]
    if isinstance(obj, str):
        return obj[:500]
    return obj


def setup_logging(data_dir: Path, level: str = "INFO",
                  console_json: bool = False) -> logging.Logger:
    global _LOG
    if _LOG is not None:
        return _LOG
    log_dir = data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("tracevoryx")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    fmt = logging.Formatter(
        '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s",'
        '"msg":%(message)s}', "%Y-%m-%dT%H:%M:%S")

    fh = logging.handlers.RotatingFileHandler(
        log_dir / "tw.log", maxBytes=5 * 1024 * 1024, backupCount=5,
        encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    _LOG = logger
    return logger


def log_event(logger: logging.Logger, msg: str, **fields: Any) -> None:
    logger.info(json.dumps(_safe({"event": msg, **fields}), default=str))


def log_error(logger: logging.Logger, msg: str, **fields: Any) -> None:
    logger.error(json.dumps(_safe({"event": msg, **fields}), default=str))
