"""Unit tests for logging helpers and safety limits."""
from __future__ import annotations

import logging

import pytest

from bridge.utils.logging import (
    SafetyLimitExceeded,
    current_request,
    enforce_batch_limit,
    increment_counter,
    record_write_attempt,
    request_scope,
)


def test_request_scope_provides_context():
    logger = logging.getLogger("test.logger")
    with request_scope("unit_test", logger=logger, max_writes=3, max_items=5) as ctx:
        assert current_request() is ctx
        increment_counter("example")
        record_write_attempt()
        enforce_batch_limit(2, counter="batch")
        assert ctx.counters["example"] == 1
        assert ctx.counters["writes"] == 1
        assert ctx.counters["batch"] == 2
    assert current_request() is None


def test_record_write_attempt_enforces_limit():
    with request_scope("writes", max_writes=1):
        record_write_attempt()
        with pytest.raises(SafetyLimitExceeded):
            record_write_attempt()


def test_enforce_batch_limit_enforces_limit():
    with request_scope("batch", max_items=3):
        enforce_batch_limit(3)
        with pytest.raises(SafetyLimitExceeded):
            enforce_batch_limit(4)
