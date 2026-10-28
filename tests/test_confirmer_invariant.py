"""
Confirmer RL3/RL5 invariant + real-evidence certificate wiring.
===============================================================

Closes the soundness column on ONYX's OWN decision path (the real Confirmer,
driven through AuthPathEngine), additively — this file modifies no decision code.

  (A) RL3 over the real demo: every finding the real confirmer produces is
      Δstate-CONFIRMED (state_proof.confirmed) with a genuine delta (before != after)
      and a reportable PoC (RL4). No finding is ever emitted without a proven Δstate.
  (B) RL5 dual on a minimal REAL BOLA scenario: the vulnerable target yields a
      confirmed finding; the fixed target (403 to non-owners) yields ZERO findings —
      the confirmer abstains rather than guess.
  (C) Transcript wiring end-to-end: a certificate built from ONYX's REAL captured
      run evidence (owner's legitimate read + attacker's read, both driven through the
      real engine) is independently CERTIFIED by the decision-free checker — proving
      the certifying-algorithm layer works on ONYX's real output, not just fixtures.

Note (honest boundary): the demo confirms some read-leaks via the confirmer's own
internal read-back probes, which are not in engine.capture; wiring certificates for
those would need an additive capture hook INSIDE the confirmer (a separate change,
deliberately not made here to keep this decision-code-free). The minimal BOLA
scenario below has a faithful captured transcript (the attacker's response truly
carries the owner's data), so it certifies from real evidence with no such hook.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from fixtures.demo_scenario import run_demo
from authpath import certificate as C


# --------------------------------------------------------------------------- #
# (A) RL3 invariant over the REAL demo run.                                    #
# --------------------------------------------------------------------------- #

def _demo_engine():
    def factory(target, principals, contract):
        scope = ScopeConfig(allowed_hosts=["demo.local"], dry_run=True, automation_permitted=True)
        return AuthPathEngine(target, principals, scope, contract)
    eng, _ = run_demo(factory)
    if hasattr(eng, "drain_deferred"):
        eng.drain_deferred()
    return eng


def test_rl3_every_real_finding_is_delta_confirmed():
    eng = _demo_engine()
    assert len(eng.findings) >= 10, f"expected the demo's planted bugs, got {len(eng.findings)}"
    for f in eng.findings:
        assert f.state_proof.confirmed is True, f"finding without a confirmed Δstate: {f.law_name}"
        assert f.state_proof.before != f.state_proof.after, f"no delta in proof: {f.law_name}"


def test_rl4_every_real_finding_is_reportable():
    eng = _demo_engine()
    for f in eng.findings:
        assert getattr(f, "poc", None) and f.poc.steps, f"finding without a PoC: {f.law_name}"


# --------------------------------------------------------------------------- #
# (B)+(C) minimal REAL BOLA scenario through the real engine/confirmer.        #
# --------------------------------------------------------------------------- #

_OBJ = {"101": {"id": 101, "owner_id": "A", "total": 500, "iban": "SECRET-A-IBAN"}}


def _bola_run(vuln: bool):
    def send(req, principal):
        if req.method == "GET" and req.path.startswith("/api/orders/"):
            obj = _OBJ.get(req.path.rsplit("/", 1)[-1])
            if obj is None:
                return HTTPResponse(404, {})
            if vuln or principal.pid == obj["owner_id"]:
                return HTTPResponse(200, dict(obj))            # BOLA: any principal gets it
            return HTTPResponse(403, {"error": "forbidden"})
        return HTTPResponse(404, {})

    class Store:
        host = "svc.test"
        def send(self, req, principal):
            return send(req, principal)

    store = Store()
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    scope = ScopeConfig(allowed_hosts=["svc.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(store, P, scope,
                         contract={"GET /api/orders/{id}": {"effect": "OBJECT_ACCESS",
                                                            "critical_params": ["id"]}})

    def mk(pid, path):
        req = HTTPRequest("GET", path, host="svc.test")
        return Exchange(request=req, response=store.send(req, P[pid]), principal=P[pid])

    owner_ex = mk("A", "/api/orders/101")      # A legitimately owns 101 (observe)
    atk_ex = mk("B", "/api/orders/101")        # B attacks (analyze)
    eng.observe(owner_ex)
    eng.analyze(atk_ex)
    if hasattr(eng, "drain_deferred"):
        eng.drain_deferred()
    return eng, owner_ex, atk_ex


def test_rl3_real_confirmer_fires_on_genuine_bola():
    eng, _, _ = _bola_run(vuln=True)
    assert len(eng.findings) >= 1, "the real confirmer must confirm a genuine BOLA"
    assert all(f.state_proof.confirmed for f in eng.findings)


def test_rl5_real_confirmer_abstains_on_safe_target():
    eng, _, _ = _bola_run(vuln=False)
    assert len(eng.findings) == 0, "a fixed target must yield zero findings (RL5 abstain)"


def _to_attacker(e):
    return {"principal": e.principal.pid,
            "request": {"method": e.request.method, "path": e.request.path, "host": e.request.host},
            "response": {"status": e.response.status, "body": e.response.body}}


def _to_owner_view(e):
    return {"response": {"status": e.response.status, "body": e.response.body}}


def test_real_finding_certifies_from_engine_evidence():
    # A certificate built from ONYX's REAL run (real owner + attacker exchanges) is
    # independently CERTIFIED by the decision-free checker — end-to-end, no fixtures.
    eng, owner_ex, atk_ex = _bola_run(vuln=True)
    f = eng.findings[0]
    cert = C.certificate_from_finding(
        f, attacker_exchange=_to_attacker(atk_ex), owner_view=_to_owner_view(owner_ex),
        sensitive_field="iban", kind=C.KIND_READ_LEAK)
    r = C.check_certificate(cert)
    assert r["status"] == C.CERTIFIED, r


def test_safe_target_leaves_nothing_to_certify():
    eng, _, _ = _bola_run(vuln=False)
    assert eng.findings == [] or len(eng.findings) == 0


if __name__ == "__main__":
    import traceback
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    print("\nConfirmer RL3/RL5 invariant + real-evidence certificate wiring\n" + "-" * 60)
    p = _fail = 0
    for n, f in fns:
        try:
            f(); p += 1; print(f"  [PASS] {n}")
        except Exception:
            _fail += 1; print(f"  [FAIL] {n}"); traceback.print_exc()
    print("-" * 60); print(f"  {p}/{len(fns)} passed\n")
    sys.exit(1 if _fail else 0)
