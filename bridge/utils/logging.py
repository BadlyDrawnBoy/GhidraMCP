"""Logging helpers for the bridge."""
from __future__ import annotations

import logging
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from time import monotonic
from typing import Dict, Iterator, Mapping, Optional

import contextvars

from .config import MAX_ITEMS_PER_BATCH, MAX_WRITES_PER_REQUEST


_REQUEST_CONTEXT: contextvars.ContextVar["RequestContext | None"] = contextvars.ContextVar(
    "bridge_request_context", default=None
)


def configure_root(level: int = logging.INFO) -> None:
    logging.basicConfig(level=level, format="%(levelname)s:%(name)s:%(message)s")


@contextmanager
def scoped_timer(
    logger: logging.Logger, message: str, *, extra: Optional[Dict[str, object]] = None
) -> Iterator[None]:
    start = monotonic()
    try:
        yield
    finally:
        elapsed = monotonic() - start
        logger.debug("%s", message, extra={"duration_s": elapsed, **(extra or {})})


class SafetyLimitExceeded(RuntimeError):
    """Raised when a request exceeds configured safety limits."""

    def __init__(self, kind: str, limit: int, attempted: int):
        super().__init__(f"{kind} limit exceeded: attempted {attempted} > allowed {limit}")
        self.kind = kind
        self.limit = limit
        self.attempted = attempted


@dataclass(slots=True)
class RequestContext:
    """Structured per-request logging context."""

    name: str
    request_id: str
    logger: logging.Logger
    max_writes: int = MAX_WRITES_PER_REQUEST
    max_items: int = MAX_ITEMS_PER_BATCH
    metadata: Dict[str, object] = field(default_factory=dict)
    counters: Dict[str, int] = field(default_factory=dict)
    start_time: float = field(default_factory=monotonic)

    def extra(self, **values: object) -> Dict[str, object]:
        payload = {"request_id": self.request_id, "request": self.name, **self.metadata}
        payload.update(values)
        return payload

    def log(
        self, level: int, message: str, *, extra: Optional[Mapping[str, object]] = None
    ) -> None:
        payload = self.extra(**(dict(extra) if extra else {}))
        self.logger.log(level, message, extra=payload)

    def increment(self, counter: str, amount: int = 1) -> int:
        value = self.counters.get(counter, 0) + amount
        self.counters[counter] = value
        self.logger.debug(
            "counter.%s", counter, extra=self.extra(counter=counter, value=value)
        )
        return value


@contextmanager
def request_scope(
    name: str,
    *,
    logger: Optional[logging.Logger] = None,
    extra: Optional[Mapping[str, object]] = None,
    max_writes: Optional[int] = None,
    max_items: Optional[int] = None,
) -> Iterator[RequestContext]:
    """Create a structured logging scope for a single request."""

    logger = logger or logging.getLogger("bridge.request")
    context = RequestContext(
        name=name,
        request_id=str(uuid.uuid4()),
        logger=logger,
        max_writes=max_writes if max_writes is not None else MAX_WRITES_PER_REQUEST,
        max_items=max_items if max_items is not None else MAX_ITEMS_PER_BATCH,
        metadata=dict(extra or {}),
    )
    token = _REQUEST_CONTEXT.set(context)
    context.log(logging.INFO, "request.start")
    try:
        with scoped_timer(logger, f"{name}.duration", extra=context.extra(event="timer")):
            yield context
    except Exception:
        logger.exception("request.error", extra=context.extra())
        raise
    finally:
        duration = monotonic() - context.start_time
        context.log(
            logging.INFO,
            "request.finish",
            extra={"duration_s": duration, "counters": dict(context.counters)},
        )
        _REQUEST_CONTEXT.reset(token)


def current_request() -> Optional[RequestContext]:
    """Return the active request context if one is present."""

    return _REQUEST_CONTEXT.get(None)


def increment_counter(name: str, amount: int = 1) -> None:
    """Increment a named counter on the current request."""

    context = current_request()
    if context is not None:
        context.increment(name, amount)


def record_write_attempt(amount: int = 1) -> None:
    """Record an attempted write and enforce per-request limits."""

    context = current_request()
    if context is None:
        return
    total = context.increment("writes", amount)
    if total > context.max_writes:
        context.log(
            logging.WARNING,
            "limit.writes_exceeded",
            extra={"attempted": total, "limit": context.max_writes},
        )
        raise SafetyLimitExceeded("writes", context.max_writes, total)


def enforce_batch_limit(size: int, *, counter: str = "batch_size") -> None:
    """Enforce the maximum number of items allowed in a single request batch."""

    context = current_request()
    limit = context.max_items if context is not None else MAX_ITEMS_PER_BATCH
    if size > limit:
        if context is not None:
            context.log(
                logging.WARNING,
                "limit.items_exceeded",
                extra={"attempted": size, "limit": limit, "counter": counter},
            )
        raise SafetyLimitExceeded(counter, limit, size)
    if context is not None:
        context.increment(counter, size)


__all__ = [
    "SafetyLimitExceeded",
    "configure_root",
    "current_request",
    "enforce_batch_limit",
    "increment_counter",
    "record_write_attempt",
    "request_scope",
    "scoped_timer",
]
