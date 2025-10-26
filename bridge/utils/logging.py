"""Logging helpers for the bridge."""
from __future__ import annotations

import logging
from contextlib import contextmanager
from time import monotonic
from typing import Dict, Iterator, Optional


def configure_root(level: int = logging.INFO) -> None:
    logging.basicConfig(level=level, format="%(levelname)s:%(name)s:%(message)s")


@contextmanager
def scoped_timer(logger: logging.Logger, message: str, *, extra: Optional[Dict[str, object]] = None) -> Iterator[None]:
    start = monotonic()
    try:
        yield
    finally:
        elapsed = monotonic() - start
        logger.debug("%s", message, extra={"duration_s": elapsed, **(extra or {})})
