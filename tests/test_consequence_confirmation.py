"""
Deficiency #4 (invisible-Δstate blindness) — solved-criterion, every gap in the [19]
inventory. Confirmation is generalised from a DIRECT read-back to a DERIVABLE CONSEQUENCE
the effect necessarily entails (a consequence oracle), so effects with no direct read-back
become confirmable — without any probabilistic step (zero-FP preserved).

  GAP-1 credential takeover (the file's OWN flagship miss, on VAmPI)
  GAP-2 capability acquisition (privilege escalation, before-denied -> after-allowed)
  FP-safety: no consequence -> abstain; safe app -> zero findings
  GAP-3/4/5 walls: no oracle -> unchanged behaviour (declared)
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "external_targets"))
from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.consequence import ConsequenceOracle


def test_gap1_credential_takeover_closed_on_vampi():
    """The deficiency file's own example: VAmPI password change, previously MISSED, is now
    confirmed via the re-auth consequence — recall 3/3, precision 1.0."""
    import run_vampi
    r = run_vampi.run_mode(vuln=True, use_http=False)
    recall = r["tp"] / (r["tp"] + r["fn"])
    assert r["fp"] == 0 and recall == 1.0, f"expected 3/3 zero-FP, got recall={recall} fp={r['fp']}"


def test_gap1_safe_app_stays_zero_fp():
    """On erev0s's fixed app the takeover is blocked, so the consequence never confirms."""
    import run_vampi
    r = run_vampi.run_mode(vuln=False, use_http=False)
    assert r["fp"] == 0 and r["n_findings"] == 0


def test_gap2_capability_acquisition_confirmed_and_fp_safe():
    """Privilege escalation with no visible data: a denied action flips to allowed after
    the actor's write. Confirmed only on the real flip; a no-op write does not fire."""
    caps = {"A": set(), "B": set()}                 # nobody can 'delete_any' at baseline

    class Store:
        host = "svc.test"
        def send(self, req, principal):
            if req.method == "POST" and req.path.endswith("/escalate"):
                caps[principal.pid].add("delete_any")     # the escalation write
                return HTTPResponse(200, {"ok": True})
            if req.method == "POST" and req.path.endswith("/noop"):
                return HTTPResponse(200, {"ok": True})
            return HTTPResponse(404, {})

    store = Store()
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    scope = ScopeConfig(allowed_hosts=["svc.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(store, P, scope, contract={})
    eng.consequence_confirmation = True
    eng.consequence_oracle = ConsequenceOracle(
        capability_prober=lambda pid, action: action in caps[pid],
        actions=["delete_any"])

    def ex(pid, method, path, body=None):
        req = HTTPRequest(method, path, body=body, host="svc.test")
        return Exchange(request=req, response=store.send(req, P[pid]), principal=P[pid])

    eng.observe(ex("A", "GET", "/svc/v1/me"))       # triggers baseline capture (all denied)
    eng.analyze(ex("B", "POST", "/svc/v1/noop"))    # a write that grants nothing -> no finding
    assert len(eng.findings) == 0, "a no-op write must not confirm an escalation (FP-safety)"
    eng.analyze(ex("A", "POST", "/svc/v1/escalate"))  # real escalation -> denied->allowed flip
    eng.drain_deferred()
    assert any(f.law_name.startswith("CONSEQUENCE_CAPABILITY") for f in eng.findings), \
        "the real capability acquisition must be confirmed"


def test_walls_no_oracle_is_unchanged_behaviour():
    """GAP-3/4/5 residue: with no consequence oracle, ONYX behaves exactly as before —
    it abstains on invisible effects rather than guessing (the honest wall)."""
    class Store:
        host = "svc.test"
        def send(self, req, principal): return HTTPResponse(200, {"ok": True})
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    scope = ScopeConfig(allowed_hosts=["svc.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(Store(), P, scope, contract={})
    eng.consequence_confirmation = True             # flag on, but no oracle provided
    req = HTTPRequest("PUT", "/users/v1/B/password", body={"password": "x"}, host="svc.test")
    eng.analyze(Exchange(request=req, response=HTTPResponse(200, {}), principal=P["A"]))
    eng.drain_deferred()
    assert len(eng.findings) == 0                    # no oracle -> abstain, no fabrication


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
