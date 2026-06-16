"""Unit tests for the shared asyncio.Queue singleton helpers."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from collectors.shared import queue as q
from collectors.shared.schema import UnifiedLogEvent


@pytest.fixture(autouse=True)
def fresh_queue():
    q._reset_for_tests()
    yield
    q._reset_for_tests()


def _event() -> UnifiedLogEvent:
    return UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="host-01",
        event_type="dns",
        source_process="chrome.exe",
        pid=1,
        queried_domain="example.com",
    )


def test_get_queue_is_singleton():
    assert q.get_queue() is q.get_queue()


async def test_put_and_get_roundtrip():
    evt = _event()
    await q.put_event(evt)
    assert q.qsize() == 1
    got = await q.get_event()
    assert got is evt
    q.task_done()


def test_put_nowait_returns_true_with_capacity():
    assert q.put_event_nowait(_event()) is True
    assert q.qsize() == 1


def test_put_nowait_returns_false_when_full(monkeypatch):
    # Shrink the queue to capacity 1 to exercise the QueueFull branch.
    q._reset_for_tests()
    monkeypatch.setattr(q, "DEFAULT_MAXSIZE", 1)
    assert q.put_event_nowait(_event()) is True
    assert q.put_event_nowait(_event()) is False
