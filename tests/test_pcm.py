"""Proof-Carrying Measurement: the evidence bundle must verify when honest and be
caught when tampered or lied about — by a verifier that re-derives findings by
replaying the raw transcript through ONYX, trusting nothing the runner claims."""
import os, sys, copy
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "p0"))
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.models import HTTPRequest, Principal
from authpath.transport import make_exchange
from conformance import CrapiReplayTarget
import pcm

def _record():
    tgt = CrapiReplayTarget(patched=False)
    A = Principal("A", "user A", auth={"Authorization": "Bearer A"})
    B = Principal("B", "user B", auth={"Authorization": "Bearer B"})
    sc = ScopeConfig(allowed_hosts=["crapi.local"], automation_permitted=True, target_provenance="third_party")
    eng = AuthPathEngine(tgt, {"A": A, "B": B}, sc, contract={})
    for f in ("provisional_leads", "active_probing", "conservation"):
        setattr(eng, f, True)
    tr = []
    def rec(phase, m, path, p, q):
        ex = make_exchange(tgt, HTTPRequest(m, path, query=dict(q)), p)
        tr.append({"phase": phase, "request": {"method": m, "path": path, "principal": p.pid, "query": q},
                   "response": {"status": ex.response.status, "body": ex.response.body}})
        return ex
    eng.observe(rec("observe", "GET", "/identity/api/v2/vehicle/x/location", A, {"_res": "vehicleA"}))
    eng.analyze(rec("analyze", "GET", "/identity/api/v2/vehicle/x/location", B, {"_res": "vehicleA"}))
    findings = [{"effect": f.effect.value, "actor_pid": f.actor_pid, "target_ref": getattr(f,"target_ref","") or ""} for f in eng.findings]
    return pcm.build_bundle({"spec_hash": "abc"}, "SEAL123", tr, findings, {"tp": len(findings)})

_SEAL = lambda s: s == "SEAL123"

def test_honest_bundle_verifies():
    b = _record()
    v = pcm.verify_bundle(b, _SEAL)
    assert v["verified"], v
    assert v["checks"]["findings_reproduced"]

def test_tampered_transcript_is_caught():
    b = _record(); b["transcript"][1]["response"]["status"] = 403
    v = pcm.verify_bundle(b, _SEAL)
    assert not v["verified"] and not v["checks"]["chain_intact"]

def test_lied_findings_are_caught():
    b = _record()
    b["findings"].append({"effect": "AUTHORITY", "actor_pid": "B"})
    b["chain_root"] = pcm.chain_root(b["transcript"])      # re-chain to hide the lie
    v = pcm.verify_bundle(b, _SEAL)
    assert not v["verified"] and not v["checks"]["findings_reproduced"]

def test_broken_oracle_seal_is_caught():
    b = _record()
    v = pcm.verify_bundle(b, lambda s: False)              # seal does not verify
    assert not v["verified"] and not v["checks"]["oracle_seal_ok"]

def test_chain_root_is_order_sensitive():
    b = _record()
    rev = list(reversed(b["transcript"]))
    assert pcm.chain_root(rev) != b["chain_root"]

if __name__ == "__main__":
    fns=[(n,f) for n,f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    print("\nProof-Carrying Measurement (session 5)\n"+"-"*55); p=0; fail=0
    for n,f in fns:
        try: f(); p+=1; print(f"  [PASS] {n}")
        except Exception as e: fail+=1; print(f"  [FAIL] {n}: {e!r}")
    print("-"*55); print(f"  {p}/{len(fns)} passed\n"); sys.exit(1 if fail else 0)
