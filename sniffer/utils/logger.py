"""
Centralized Logging Setup
==========================

Configures Python's built-in ``logging`` module for the entire application.
All other modules obtain their loggers via ``logging.getLogger(__name__)``;
this module configures the handlers, formatters, and levels centrally.

"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ─── Constants ──────────────────────────────────────────────────────────────

# Log format: timestamp | level | module name | message
LOG_FORMAT = "%(asctime)s │ %(levelname)-8s │ %(name)-25s │ %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# File rotation settings
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "sniffer.log"
MAX_LOG_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
BACKUP_COUNT = 3  # Keep 3 old log files


def setup_logging(
    console_level: int = logging.WARNING,
    log_dir: Path | None = None,
) -> logging.Logger:
    """Configure the root ``sniffer`` logger with console and file handlers.

    This function should be called **once** at application startup, before
    any other module attempts to log. Subsequent calls will add duplicate
    handlers, so this is guarded with a check.

    Args:
        console_level: Logging level for console output.
            - ``logging.WARNING`` (default) — quiet mode
            - ``logging.INFO`` — verbose mode (``--verbose``)
            - ``logging.DEBUG`` — debug mode (``--debug``)
        log_dir: Directory for log files. Defaults to ``./logs/``.

    Returns:
        The configured root ``sniffer`` logger.

    Example:
        >>> from sniffer.utils.logger import setup_logging
        >>> import logging
        >>> logger = setup_logging(console_level=logging.DEBUG)
        >>> logger.info("Logging is configured!")
    """
    # Use the package-level logger as the root for all sniffer modules.
    # This means loggers like "sniffer.core.capture" will inherit config.
    root_logger = logging.getLogger("sniffer")

    # Guard against duplicate handler attachment on repeated calls
    if root_logger.handlers:
        return root_logger

    # Set the root logger to DEBUG so handlers can filter independently
    root_logger.setLevel(logging.DEBUG)

    # Create the shared formatter
    formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    # ─── Console Handler ────────────────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # ─── File Handler ───────────────────────────────────────────────────
    target_dir = log_dir or LOG_DIR
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / "sniffer.log"

        file_handler = RotatingFileHandler(
            filename=target_file,
            maxBytes=MAX_LOG_SIZE_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)  # Capture everything to file
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

        root_logger.debug("Log file initialized at %s", target_file.resolve())
    except OSError as exc:
        # If we can't write to disk, log to console only — don't crash.
        console_handler.setLevel(logging.DEBUG)
        root_logger.warning(
            "Could not create log file at %s: %s. "
            "Falling back to console-only logging.",
            target_dir,
            exc,
        )

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the ``sniffer`` namespace.

    This is a convenience wrapper around ``logging.getLogger()`` that
    ensures the logger name is always prefixed with ``sniffer.``.

    Args:
        name: The module's ``__name__`` attribute (e.g., ``sniffer.core.capture``).

    Returns:
        A configured child logger.

    Example:
        >>> from sniffer.utils.logger import get_logger
        >>> logger = get_logger(__name__)
        >>> logger.info("Parser initialized")
    """
    # If the name already starts with "sniffer", use it directly.
    # Otherwise, prefix it (handles edge cases in testing).
    if not name.startswith("sniffer"):
        name = f"sniffer.{name}"
    return logging.getLogger(name)
