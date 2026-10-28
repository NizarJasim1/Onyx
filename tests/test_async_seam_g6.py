"""Falsification suite for G6 (async-commit seam follower), pure logic. No network."""
import sys, os, itertools
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from authpath.async_seam import async_seam_follow, is_async_commit


def test_landing_on_third_poll_is_followed():
    reads = iter([{"applied": False}, {"applied": False}, {"applied": True}])
    rb = async_seam_follow(lambda: next(reads), persisted=lambda r: r.get("applied") is True,
                           max_polls=4, interval_s=0.0)
    assert rb is not None and rb["applied"] is True


def test_optimistic_ack_then_rejected_abstains():
    rb = async_seam_follow(lambda: {"applied": False}, persisted=lambda r: r.get("applied") is True,
                           max_polls=5, interval_s=0.0)
    assert rb is None


def test_timeout_abstains():
    c = itertools.count()
    rb = async_seam_follow(lambda: {"n": next(c), "applied": False}, persisted=lambda r: r["applied"],
                           max_polls=3, interval_s=0.0)
    assert rb is None


def test_none_readback_is_never_persisted():
    rb = async_seam_follow(lambda: None, persisted=lambda r: True, max_polls=3, interval_s=0.0)
    assert rb is None


def test_bounded_polls_exact_count():
    calls = {"n": 0}
    def rb():
        calls["n"] += 1
        return {"applied": False}
    async_seam_follow(rb, persisted=lambda r: False, max_polls=4, interval_s=0.0)
    assert calls["n"] == 4


def test_is_async_commit_detects_202_and_pending_and_handles():
    assert is_async_commit(202) is True
    assert is_async_commit(200, {"status": "pending"}) is True
    assert is_async_commit(200, {"state": "QUEUED"}) is True
    assert is_async_commit(200, {"status_url": "/jobs/1"}) is True
    assert is_async_commit(200, {"job_id": "abc"}) is True
    assert is_async_commit(200, {"id": 1, "role": "admin"}) is False
    assert is_async_commit(200, None) is False


def test_early_landing_stops_polling_early():
    calls = {"n": 0}
    def rb():
        calls["n"] += 1
        return {"applied": True}
    async_seam_follow(rb, persisted=lambda r: r["applied"], max_polls=5, interval_s=0.0)
    assert calls["n"] == 1


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
