"""
⑰ Async-commit seam follower (Gap G6) — pure, I/O-free decision logic.

On a 202/saga/CQRS commit the engine used to `return` (abstain). Zero-FP but loses
recall: a real async mutation that DOES commit is never followed to its landed
state. This FOLLOWS it: poll read_back() over a bounded window, confirm ONLY a
persisted effect. An optimistic ack the backend later rejects never persists ->
still abstains. Layer A (logic) here; Layer B (I/O) reuses the engine's _readback.
"""
from __future__ import annotations
from typing import Callable, Optional, Any


def async_seam_follow(read_back: Callable[[], Any], persisted: Callable[[Any], bool],
                      *, max_polls: int = 4, interval_s: float = 0.0,
                      sleep: Optional[Callable[[float], None]] = None) -> Optional[Any]:
    """Follow an async (202/saga/CQRS) commit to its landed state. Polls read_back()
    up to max_polls; returns the first read-back for which persisted(rb) is True,
    else None (abstain). A None read-back is never persisted."""
    if sleep is None:
        import time
        sleep = time.sleep
    n = max(1, int(max_polls))
    for i in range(n):
        rb = read_back()
        if rb is not None and persisted(rb):
            return rb
        if i < n - 1:
            sleep(interval_s)
    return None


_ASYNC_STATUS = frozenset({202})
_ASYNC_BODY_HINTS = frozenset({"pending", "queued", "processing", "accepted",
                               "in_progress", "in-progress", "submitted"})


def is_async_commit(status: int, body: Any = None) -> bool:
    if status in _ASYNC_STATUS:
        return True
    if isinstance(body, dict):
        for key in ("status", "state", "job_status", "processing_status"):
            v = body.get(key)
            if isinstance(v, str) and v.strip().lower() in _ASYNC_BODY_HINTS:
                return True
        for key in ("status_url", "status_uri", "process_status", "poll_url",
                    "location", "job_id", "task_id", "process_id"):
            if body.get(key):
                return True
    return False
