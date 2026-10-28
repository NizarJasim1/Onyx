"""
Deficiency #3 (static identity vs live auth protocol) — solved-criterion, every gap.

The safety-critical root: a bare 401 from a DEAD token is indistinguishable from a real
authorization denial. ONYX now trusts a negative ONLY when an independent liveness probe
proves the credential was live — making 401-conflation impossible by construction.

  GAP-1/2 a dead-token 401 is NOT counted as "safe" (it abstains, authN-contaminated)
  live-token 401 IS trusted as a real authZ signal (no spurious abstention)
  GAP-3 re-auth restores liveness (revived -> re-issue)
  GAP-5 attestation-closed principal -> abstain + declared
  MSI: gate default OFF -> unchanged behaviour
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.session import SessionManager


def _eng(sm=None, gating=False):
    class Store:
        host = "svc.test"
        def send(self, req, principal): return HTTPResponse(200, {"ok": True})
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    scope = ScopeConfig(allowed_hosts=["svc.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(Store(), P, scope, contract={})
    if sm is not None:
        eng.session_manager = sm
    eng.liveness_gating = gating
    return eng, P


def _attack(eng, P, status):
    """An attack read that came back with `status` (e.g. 401)."""
    req = HTTPRequest("GET", "/api/v1/orders/999", host="svc.test")   # B's object, as A
    ex = Exchange(request=req, response=HTTPResponse(status, {"error": "denied"}), principal=P["A"])
    return eng.analyze(ex)


def test_dead_token_401_is_not_trusted_as_safe():
    # A's token is DEAD -> liveness probe fails, no re-auth
    sm = SessionManager(liveness_prober=lambda pid: False)
    eng, P = _eng(sm, gating=True)
    tr = _attack(eng, P, 401)
    assert tr.outcome == "authn_contaminated", \
        "a dead-token 401 must abstain, never be trusted as 'access denied = safe'"
    assert getattr(eng, "_authn_contaminated", 0) == 1


def test_live_token_401_is_trusted_as_real_authz_denial():
    # A's token is LIVE -> the 401 is a genuine authZ denial, processed normally (no abstain)
    sm = SessionManager(liveness_prober=lambda pid: True)
    eng, P = _eng(sm, gating=True)
    tr = _attack(eng, P, 401)
    assert tr.outcome != "authn_contaminated", \
        "a live-token 401 is a real authZ signal and must not be treated as contaminated"


def test_reauth_marks_response_stale_for_reissue():
    calls = {"n": 0}
    def probe(pid):
        calls["n"] += 1
        return calls["n"] > 1          # first probe fails (dead), after re-auth it passes
    sm = SessionManager(liveness_prober=probe, reauth=lambda pid: {"Authorization": "Bearer fresh"})
    eng, P = _eng(sm, gating=True)
    tr = _attack(eng, P, 401)
    assert tr.outcome == "authn_contaminated"     # current (stale) response abstained
    assert P["A"].auth["Authorization"] == "Bearer fresh"   # liveness restored for re-issue


def test_attestation_closed_surface_abstains_and_is_declared():
    sm = SessionManager(liveness_prober=lambda pid: True, attestation_closed={"A"})
    eng, P = _eng(sm, gating=True)
    tr = _attack(eng, P, 401)
    assert tr.outcome == "authn_contaminated"
    assert any("attestation-closed" in s.detail for s in tr.stages)


def test_gate_off_is_unchanged_behaviour():
    eng, P = _eng(sm=None, gating=False)
    tr = _attack(eng, P, 401)
    assert tr.outcome != "authn_contaminated"     # no gate -> exactly as before


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
