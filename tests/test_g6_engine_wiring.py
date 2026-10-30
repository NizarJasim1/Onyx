"""
Engine ON-path test for G6 (INTEGRATION #6): the engine's own _readback +
_write_persisted composed with async_seam_follow — the exact composition the 202
site uses. A fake target models an async commit that LANDS after a couple of polls,
and one that never lands (optimistic ack). No network; deterministic.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.models import Principal, HTTPRequest, HTTPResponse, Exchange
from authpath.async_seam import async_seam_follow


class _AsyncTarget:
    """PATCH returns 202 (accepted). GET returns the object; the written field only
    APPEARS after `lands_after` reads (async commit landing). If lands_after is huge,
    the effect never persists (optimistic-ack-then-rejected)."""
    host = "t.local"
    def __init__(self, lands_after=2):
        self._reads = 0
        self._lands_after = lands_after
    def send(self, req, principal):
        if req.method == "GET":
            self._reads += 1
            body = {"id": 1}
            if self._reads >= self._lands_after:
                body["note"] = "LANDED-MARK"
            return HTTPResponse(200, body)
        return HTTPResponse(202, {"status": "pending"})   # async ack


def _engine(target):
    return AuthPathEngine(target, {"A": Principal("A", "A", {"Authorization": "Bearer a"})},
                          ScopeConfig(allowed_hosts=["t.local"], dry_run=True,
                                      automation_permitted=True))


def _exchange():
    req = HTTPRequest("PATCH", "/o/1", host="t.local", body={"note": "LANDED-MARK"})
    return Exchange(request=req, response=HTTPResponse(202, {"status": "pending"}),
                    principal=Principal("A", "A", {"Authorization": "Bearer a"}))


def test_engine_primitives_follow_async_landing():
    """The engine's real _readback + _write_persisted, composed exactly as the 202
    site does, must follow the commit to its landed state."""
    tgt = _AsyncTarget(lands_after=2)
    eng = _engine(tgt)
    ex = _exchange()
    rb = async_seam_follow(lambda: eng._readback(ex, "A"),
                           lambda r: eng._write_persisted(ex, r),
                           max_polls=4, interval_s=0.0)
    assert rb is not None and rb.body.get("note") == "LANDED-MARK"


def test_engine_primitives_abstain_when_never_lands():
    """Optimistic ack that never persists ⇒ the follower abstains (None) ⇒ the 202
    site does `continue` (no finding). Zero-FP preserved."""
    tgt = _AsyncTarget(lands_after=999)
    eng = _engine(tgt)
    ex = _exchange()
    rb = async_seam_follow(lambda: eng._readback(ex, "A"),
                           lambda r: eng._write_persisted(ex, r),
                           max_polls=4, interval_s=0.0)
    assert rb is None


def test_flag_default_off():
    """follow_async_commit defaults OFF ⇒ 202 handling is byte-identical to before."""
    eng = _engine(_AsyncTarget())
    assert eng.follow_async_commit is False


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = 0
    for fn in fns:
        try:
            fn(); print(f"PASS  {fn.__name__}"); p += 1
        except Exception:
            print(f"FAIL  {fn.__name__}"); traceback.print_exc()
    print(f"\n{p}/{len(fns)} passed")
