"""
ASSURANCE-2 — RecordingTarget: transparent transcript capture for certificate wiring.

Proves the wrapper is behaviourally transparent (delegates send, proxies attributes,
changes no finding) and that a real BOLA finding certifies from the RECORDED
transcript alone (no manual exchange tracking) — closing the transcript-wiring gap
without touching any decision code.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath import certificate as C
from authpath.recording_target import RecordingTarget, find_exchange, certificate_for_finding

_OBJ = {"101": {"id": 101, "owner_id": "A", "total": 500, "iban": "SECRET-A-IBAN"}}


def _store(vuln=True):
    def send(req, principal):
        if req.method == "GET" and req.path.startswith("/api/orders/"):
            obj = _OBJ.get(req.path.rsplit("/", 1)[-1])
            if obj is None:
                return HTTPResponse(404, {})
            if vuln or principal.pid == obj["owner_id"]:
                return HTTPResponse(200, dict(obj))
            return HTTPResponse(403, {"error": "forbidden"})
        return HTTPResponse(404, {})

    class Store:
        host = "svc.test"
        def send(self, req, principal):
            return send(req, principal)
    return Store()


def _run_bola(vuln=True, wrap=True):
    store = _store(vuln)
    target = RecordingTarget(store) if wrap else store
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    scope = ScopeConfig(allowed_hosts=["svc.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(target, P, scope,
                         contract={"GET /api/orders/{id}": {"effect": "OBJECT_ACCESS",
                                                            "critical_params": ["id"]}})

    def mk(pid, path):
        req = HTTPRequest("GET", path, host="svc.test")
        return Exchange(request=req, response=target.send(req, P[pid]), principal=P[pid])

    eng.observe(mk("A", "/api/orders/101"))
    eng.analyze(mk("B", "/api/orders/101"))
    if hasattr(eng, "drain_deferred"):
        eng.drain_deferred()
    return eng, target


# --------------------------------------------------------------------------- #
# Transparency                                                                 #
# --------------------------------------------------------------------------- #

def test_recording_target_is_transparent():
    store = _store(vuln=True)
    rec = RecordingTarget(store)
    assert rec.host == "svc.test"                     # attribute proxied
    P = Principal("B", "B", auth={})
    req = HTTPRequest("GET", "/api/orders/101", host="svc.test")
    resp = rec.send(req, P)
    assert resp.status == 200 and resp.body["iban"] == "SECRET-A-IBAN"   # response unchanged
    assert len(rec.exchanges) == 1                    # and recorded
    assert rec.exchanges[0]["response"]["body"]["iban"] == "SECRET-A-IBAN"


def test_wrapping_the_target_changes_no_findings():
    wrapped, _ = _run_bola(vuln=True, wrap=True)
    plain, _ = _run_bola(vuln=True, wrap=False)
    assert len(wrapped.findings) == len(plain.findings) >= 1


# --------------------------------------------------------------------------- #
# Certificate wiring from the RECORDED transcript                              #
# --------------------------------------------------------------------------- #

def test_recording_captures_all_exchanges_including_probes():
    eng, rec = _run_bola(vuln=True, wrap=True)
    # every exchange the confirmer drove is recorded (>= the two we issued).
    assert len(rec.exchanges) >= 2
    assert find_exchange(rec, "B", "101") is not None
    assert find_exchange(rec, "A", "101") is not None


def test_real_finding_certifies_from_recorded_transcript():
    eng, rec = _run_bola(vuln=True, wrap=True)
    f = eng.findings[0]
    cert = certificate_for_finding(f, rec, sensitive_field="iban", kind=C.KIND_READ_LEAK,
                                   provenance="self")
    assert cert is not None, "recording should carry the exchanges needed"
    assert C.check_certificate(cert)["status"] == C.CERTIFIED


def test_safe_target_yields_no_finding_to_certify_via_recording():
    eng, rec = _run_bola(vuln=False, wrap=True)
    assert len(eng.findings) == 0


if __name__ == "__main__":
    import traceback
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    print("\nASSURANCE-2 RecordingTarget tests\n" + "-" * 60)
    p = _fail = 0
    for n, f in fns:
        try:
            f(); p += 1; print(f"  [PASS] {n}")
        except Exception:
            _fail += 1; print(f"  [FAIL] {n}"); traceback.print_exc()
    print("-" * 60); print(f"  {p}/{len(fns)} passed\n")
    sys.exit(1 if _fail else 0)
