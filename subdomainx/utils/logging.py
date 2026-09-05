"""Structured logging setup for SUBDOMAINX.

Two formats are supported:

``text`` (default)
    ``INFO  Source completed: crt.sh``

``json``
    one JSON object per line, suitable for ingestion by log pipelines.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict, Optional

DEFAULT_LOGGER_NAME = "subdomainx"

_LEVEL_COLORS = {
    "DEBUG": "dim cyan",
    "INFO": "green",
    "WARN": "yellow",
    "WARNING": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold red",
}


class JSONFormatter(logging.Formatter):
    """Emit each record as a single JSON object."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D102
        payload: Dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info and isinstance(record.exc_info, tuple):
            payload["exception"] = self.formatException(record.exc_info)
        try:
            return json.dumps(payload, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return json.dumps({"message": "log record serialisation failed", "level": "ERROR"})


class ConsoleFormatter(logging.Formatter):
    """Human readable formatter with optional colourisation."""

    def __init__(self, color: bool = True) -> None:
        super().__init__(fmt="%(message)s")
        self.color = color

    def _paint(self, level: str, text: str) -> str:
        if not self.color:
            return text
        style = _LEVEL_COLORS.get(level)
        if not style:
            return text
        try:
            from rich.console import Console

            console = Console(quiet=True, no_color=False)
            with console.capture() as capture:
                console.print(text, style=style, end="")
            return capture.get()
        except Exception:  # pragma: no cover - rich is optional at runtime
            return text

    def format(self, record: logging.LogRecord) -> str:  # noqa: D102
        level = record.levelname
        label = "WARN" if level == "WARNING" else level
        message = record.getMessage()
        prefix = f"{label:<5} "
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict) and extra:
            rendered = " ".join(f"{k}={v}" for k, v in extra.items())
            message = f"{message} ({rendered})" if message else rendered
        return self._paint(level, f"{prefix}{message}")


def setup_logging(
    level: str = "INFO",
    json_format: bool = False,
    color: bool = True,
    quiet: bool = False,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Configure and return the SUBDOMAINX root logger."""
    logger = logging.getLogger(DEFAULT_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    numeric_level = getattr(logging, str(level).upper(), logging.INFO)

    if quiet:
        numeric_level = logging.ERROR

    stream_handler = logging.StreamHandler(stream=sys.stderr)
    stream_handler.setLevel(numeric_level)
    if json_format:
        stream_handler.setFormatter(JSONFormatter())
    else:
        stream_handler.setFormatter(ConsoleFormatter(color=color and not log_file))
    logger.addHandler(stream_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s %(message)s")
        )
        logger.addHandler(file_handler)

    return logger


def get_logger() -> logging.Logger:
    """Return the SUBDOMAINX logger (creating a default one if needed)."""
    logger = logging.getLogger(DEFAULT_LOGGER_NAME)
    if not logger.handlers:
        setup_logging()
    return logger


def log_with(logger: logging.Logger, level: int, message: str, **fields: Any) -> None:
    """Emit a record carrying structured ``fields``."""
    logger.log(level, message, extra={"extra_fields": fields or None})
