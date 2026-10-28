"""
Falsification suite for G13 (volatile-projected stability voting). Proves that
stripping volatile scaffolding recovers a stable SECURITY verdict that transport
noise would otherwise break — WITHOUT masking a real security change or a status
flip. Drives the confirmer's real _stable_send/_quorum_key with a fake target.
No network.
"""
import sys, os, itertools
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import HTTPRequest, HTTPResponse, Principal


class _Confirmerish:
    """Minimal object carrying just the two methods under test, bound from the real
    class, plus the fields they read."""
    pass


def _mk(target, *, k=5, strip=False):
    from authpath.confirmer import Confirmer as DC
    c = _Confirmerish()
    c.target = target
    c.stability_k = k
    c.stability_strip_volatile = strip
    c.stealth = None
    # bind the real methods
    c._quorum_key = DC._quorum_key.__get__(c)
    c._strip_volatile = staticmethod(DC._strip_volatile)
    c._stable_send = DC._stable_send.__get__(c)
    return c


class _Target:
    """Every read returns the SAME security fields but a DIFFERENT volatile timestamp
    → full-body voting never reaches quorum; volatile-stripped voting does."""
    def __init__(self, security_body, volatile=True, status=200):
        self._sec = security_body
        self._volatile = volatile
        self._status = status
        self._c = itertools.count()
    def send(self, req, principal):
        body = dict(self._sec)
        if self._volatile:
            body["updated_at"] = f"2026-01-01T00:00:{next(self._c):02d}Z"
            body["trace_id"] = f"trace-{next(self._c)}"
        return HTTPResponse(self._status, body)


def _req():
    return HTTPRequest("GET", "/o/1", host="h")


def test_volatile_noise_breaks_quorum_without_g13():
    """Baseline: with strip OFF, per-read volatile fields prevent an 80% quorum ⇒
    abstain (None). This is the recall loss G13 fixes."""
    c = _mk(_Target({"ssn": "SECRET-1", "owner": "A"}, volatile=True), k=5, strip=False)
    assert c._stable_send(_req(), Principal("p", "p")) is None


def test_g13_recovers_stable_security_verdict():
    """With strip ON, the volatile fields are projected out, the security body is
    unanimous ⇒ the read-back is returned (recall recovered)."""
    c = _mk(_Target({"ssn": "SECRET-1", "owner": "A"}, volatile=True), k=5, strip=True)
    r = c._stable_send(_req(), Principal("p", "p"))
    assert r is not None and r.body.get("ssn") == "SECRET-1"


def test_g13_does_not_mask_a_real_security_change():
    """If the SECURITY field itself flaps, G13 must still abstain (no quorum on the
    projected key either)."""
    class _Flap:
        def __init__(self): self._c = itertools.count()
        def send(self, req, principal):
            i = next(self._c)
            return HTTPResponse(200, {"ssn": f"SECRET-{i % 2}", "updated_at": str(i)})
    c = _mk(_Flap(), k=5, strip=True)
    assert c._stable_send(_req(), Principal("p", "p")) is None


def test_g13_never_masks_a_status_flip():
    """Status is always part of the key; alternating 200/500 must not reach quorum."""
    class _StatusFlap:
        def __init__(self): self._c = itertools.count()
        def send(self, req, principal):
            i = next(self._c)
            return HTTPResponse(200 if i % 2 == 0 else 500,
                                {"ssn": "SECRET-1"})   # same body, flipping status
    c = _mk(_StatusFlap(), k=6, strip=True)
    assert c._stable_send(_req(), Principal("p", "p")) is None


def test_strip_preserves_security_fields():
    from authpath.confirmer import Confirmer as DC
    stripped = DC._strip_volatile({"id": 7, "owner": "A", "role": "admin",
                                   "amount": 100, "updated_at": "x", "trace_id": "y"})
    assert stripped == {"id": 7, "owner": "A", "role": "admin", "amount": 100}


def test_s5_never_votes_on_nothing():
    """A body made ENTIRELY of volatile fields must fall back to full-body voting,
    not become an empty (always-agreeing) key."""
    class _AllVolatile:
        def __init__(self): self._c = itertools.count()
        def send(self, req, principal):
            i = next(self._c)
            return HTTPResponse(200, {"updated_at": str(i), "trace_id": str(i)})
    c = _mk(_AllVolatile(), k=5, strip=True)
    # every read differs and stripping would empty the body ⇒ fallback to full body
    # ⇒ no quorum ⇒ abstain (does NOT falsely confirm on an empty key)
    assert c._stable_send(_req(), Principal("p", "p")) is None


def test_default_off_is_byte_identical():
    """strip=False must behave exactly like the pre-G13 key (full body)."""
    from authpath.confirmer import Confirmer as DC
    c = _mk(_Target({"ssn": "S"}, volatile=False), k=3, strip=False)
    r = c._stable_send(_req(), Principal("p", "p"))
    assert r is not None and r.body.get("ssn") == "S"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS  {fn.__name__}"); passed += 1
        except Exception:
            print(f"FAIL  {fn.__name__}"); traceback.print_exc()
    print(f"\n{passed}/{len(fns)} passed")
