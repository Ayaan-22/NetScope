"""
NetScope logging configuration.
Sets up structured, colourised console + rotating file logging.
"""

import logging
import logging.handlers
import sys
from pathlib import Path


RESET  = "\033[0m"
GREY   = "\033[38;5;244m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
RED    = "\033[31m"
BRED   = "\033[1;31m"


class _ColourFormatter(logging.Formatter):
    _COLOURS = {
        logging.DEBUG:    GREY,
        logging.INFO:     CYAN,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: BRED,
    }

    def format(self, record: logging.LogRecord) -> str:
        colour = self._COLOURS.get(record.levelno, RESET)
        record.levelname = f"{colour}{record.levelname:<8}{RESET}"
        return super().format(record)


def setup_logging(
    level: str = "INFO",
    log_dir: str = "logs",
    log_file: str = "netscope.log",
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 3,
) -> None:
    """
    Configure root logger with:
      - Colour-formatted console handler
      - Rotating file handler (plain text)
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Remove pre-existing handlers
    root.handlers.clear()

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(numeric_level)
    ch.setFormatter(
        _ColourFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    root.addHandler(ch)

    # File
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(
        filename=Path(log_dir) / log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root.addHandler(fh)

    # Silence noisy third-party loggers
    for noisy in ("urllib3", "requests", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
