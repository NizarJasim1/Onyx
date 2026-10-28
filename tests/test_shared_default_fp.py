"""
Regression tests for the shared-default false positive (GAP #2).

A value that is a shared DEFAULT/sentinel (video_id=0, status="pending",
role="ROLE_USER", booleans, empty) must NEVER be confirmed as a cross-principal
leak — even though it matches identically across principals. Closing this hole is
non-negotiable: it is the zero-false-positive core, the tool's whole differentiator.

The gate is default-OFF (byte-identical calibration) and enabled on real runs.
These tests prove: (a) with the gate ON the FP is killed via BOTH confirmation
routes; (b) with the gate ON no true finding is lost (the discriminating helper
admits every value real confirmations rely on).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.confirmer import _value_is_discriminating, _substantive_leak_value


class _T:
    """Target where a shared default appears in EVERY response body."""
    host = "app.local"
    def send(self, req, principal):
        return HTTPResponse(200, {"id": 99, "category_id": 0, "status": "pending",
                                  "name": principal.pid})


def _engine(strict):
    A = Principal("A", "A", auth={"Authorization": "Bearer A"})
    B = Principal("B", "B", auth={"Authorization": "Bearer B"})
    C = Principal("C", "C", auth={"Authorization": "Bearer C"})
    sc = ScopeConfig(allowed_hosts=["app.local"], automation_permitted=True,
                     target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(_T(), {"A": A, "B": B, "C": C}, sc, contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(eng, f, True)
    eng.confirmer.strict_leak = strict
    return eng, {"A": A, "B": B, "C": C}


def _ex(P, who, method, path, body):
    return Exchange(request=HTTPRequest(method, path, host="app.local"),
                    response=HTTPResponse(200, body), principal=P[who])


def test_shared_default_fp_killed_when_gate_on():
    """B reading its OWN item 2 must NOT be flagged just because the body carries
    the shared defaults category_id=0 / status=pending that A's item also had."""
    eng, P = _engine(strict=True)
    eng.observe(_ex(P, "A", "GET", "/api/items/1",
                    {"id": 1, "category_id": 0, "status": "pending", "name": "A"}))
    eng.analyze(_ex(P, "B", "GET", "/api/items/2",
                    {"id": 2, "category_id": 0, "status": "pending", "name": "B"}))
    eng.drain_deferred()
    assert len(eng.findings) == 0, \
        f"shared-default FP not killed: {[f.law_name for f in eng.findings]}"


def test_fp_present_when_gate_off_proves_gate_is_load_bearing():
    """Sanity: with the gate OFF the same input DOES produce the false finding —
    proving the gate is what suppresses it (not some unrelated abstention)."""
    eng, P = _engine(strict=False)
    eng.observe(_ex(P, "A", "GET", "/api/items/1",
                    {"id": 1, "category_id": 0, "status": "pending", "name": "A"}))
    eng.analyze(_ex(P, "B", "GET", "/api/items/2",
                    {"id": 2, "category_id": 0, "status": "pending", "name": "B"}))
    eng.drain_deferred()
    assert len(eng.findings) >= 1  # the FP exists without the gate


def test_discriminating_helper_admits_real_leak_values():
    """Every value real demo confirmations rely on must pass (no recall loss)."""
    for v in [250.0, [{"sku": "x", "price": 250.0}], "***-**-1111", "1 Alice St",
              "victim@example.com", "1929186d-8f2a-uuid"]:
        assert _value_is_discriminating(v), f"real leak value wrongly filtered: {v!r}"
    assert _substantive_leak_value("owner_id", "A")      # OWNER-class kept
    assert _substantive_leak_value("total", 250.0)        # AMOUNT-class kept
    assert _substantive_leak_value("ssn", "***-**-1111")  # sensitive kept


def test_discriminating_helper_rejects_shared_defaults():
    """Shared defaults/sentinels must be filtered."""
    for v in [0, 1, -1, True, False, "", "pending", "active", "ROLE_USER", "A"]:
        assert not _value_is_discriminating(v), f"sentinel wrongly kept: {v!r}"
    assert not _substantive_leak_value("category_id", 0)
    assert not _substantive_leak_value("status", "pending")


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    p = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e:
            print(f"  FAIL {fn.__name__}: {e}")
    print(f"\n{p}/{len(fns)} passed")
