import logging
import sys
from typing import Optional


def setup_logging(level: Optional[str] = None, verbose: bool = False) -> None:
    if level is None:
        level = "DEBUG" if verbose else "INFO"

    root_logger = logging.getLogger("ludi")
    root_logger.setLevel(getattr(logging, level.upper()))
    root_logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(getattr(logging, level.upper()))

    if verbose:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
    else:
        formatter = logging.Formatter("%(levelname)s: %(message)s")

    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    root_logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"ludi.{name}")
