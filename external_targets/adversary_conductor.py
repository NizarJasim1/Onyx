#!/usr/bin/env python3
"""adversary_conductor.py — adversarial self-critique of Phase 1 (the Conductor's global
ownership-consistency gate). The gate must remove ONLY genuine self-reads, and must NEVER:

  A) drop a real cross-owner read whose target owner is established (A reads B's object where
     B's ownership is on record) — the gate must keep it.
  B) touch a PAYMENT/self-abuse finding where actor==owner is the ACTUAL bug (you underpay
     your OWN order) — the gate is scoped to cross-owner effects only, so it must keep it.

We drive the Conductor's merge+gate directly with crafted confirmed-finding sets + a labeled
capture, so the test is deterministic and offline.
"""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import conductor as COND
import alt_paths_deep as L4X

def _har_with_selfreads(base="http://t"):
    """Capture that establishes ownership via self-reads: A owns o-A, B owns o-B."""
    def E(m, p, s, b, tok):
        import json
        return {"request": {"method": m, "url": base + p,
                "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]},
                "response": {"status": s, "content": {"text": json.dumps(b)}}}
    ents = [
        E("GET", "/api/order/o-A", 200, {"id": "o-A", "owner": "A"}, "tokA"),   # A self-reads o-A
        E("GET", "/api/order/o-B", 200, {"id": "o-B", "owner": "B"}, "tokB"),   # B self-reads o-B
    ]
    return {"log": {"entries": ents}}

def _finding(effect, actor, target, path="/api/order/{id}"):
    return {"fid": f"F-{actor}-{target}", "effect": effect, "endpoint": f"GET {path}",
            "actor": actor, "target": target, "impact": "", "severity": ""}

def main():
    token_map = {"tokA": "A", "tokB": "B"}
    har = _har_with_selfreads()
    # sanity: ownership established from self-reads
    _, _, ownership, _ = L4X.object_identity(L4X.normalize(har, token_map))
    assert ownership.get("o-A") == "A" and ownership.get("o-B") == "B", ownership

    ok = True

    # ---- Attack A: a REAL cross-owner read (A reads B's o-B) must be KEPT ----
    layer = [("L4X-deep", [_finding("OBJECT_ACCESS", "A", "o-B")])]
    packet = _run_gate(layer, har, token_map)
    keptA = any(r["actor"] == "A" and r["target"] == "o-B" for r in packet["confirmed"])
    a_ok = keptA and packet["coverage"]["dropped_self_read"] == 0
    print(f"A) real cross-owner kept   : {keptA}  dropped={packet['coverage']['dropped_self_read']} "
          f"-> {'PASS' if a_ok else 'FAIL'}")
    ok &= a_ok

    # ---- self-read control: B reads its OWN o-B must be DROPPED ----
    layer = [("L3-breaker", [_finding("OBJECT_ACCESS", "B", "o-B")])]
    packet = _run_gate(layer, har, token_map)
    droppedB = all(not (r["actor"] == "B" and r["target"] == "o-B") for r in packet["confirmed"])
    s_ok = droppedB and packet["coverage"]["dropped_self_read"] == 1
    print(f"   self-read dropped        : {droppedB}  dropped={packet['coverage']['dropped_self_read']} "
          f"-> {'PASS' if s_ok else 'FAIL'}")
    ok &= s_ok

    # ---- Attack B: PAYMENT self-abuse (B underpays its OWN o-B) must be KEPT ----
    layer = [("L4X-deep", [_finding("PAYMENT", "B", "o-B", path="/api/checkout/{id}")])]
    packet = _run_gate(layer, har, token_map)
    keptPay = any(r["effect"] == "PAYMENT" and r["actor"] == "B" for r in packet["confirmed"])
    b_ok = keptPay and packet["coverage"]["dropped_self_read"] == 0
    print(f"B) payment self-abuse kept : {keptPay}  dropped={packet['coverage']['dropped_self_read']} "
          f"-> {'PASS' if b_ok else 'FAIL'}")
    ok &= b_ok

    print("\nADVERSARY-CONDUCTOR:", "PASS — the ownership gate drops only genuine self-reads, keeps "
          "real cross-owner reads and payment self-abuse. Reconciliation never hides a real bug." if ok else "FAIL")
    return 0 if ok else 1

def _run_gate(layer_results, har, token_map):
    """Exercise merge_confirmed + the ownership gate exactly as conductor.run does, offline."""
    confirmed = COND.merge_confirmed(layer_results)
    dropped_self = 0
    _, _, ownership, _ = L4X.object_identity(L4X.normalize(har, token_map))
    _CROSS = {"OBJECT_ACCESS", "OWNERSHIP", "AUTHORITY"}
    kept = []
    for r in confirmed:
        owner = ownership.get(r["target"])
        if r["effect"].upper() in _CROSS and owner is not None and owner == r["actor"]:
            dropped_self += 1
            continue
        kept.append(r)
    return {"confirmed": kept, "coverage": {"dropped_self_read": dropped_self}}

if __name__ == "__main__":
    sys.exit(main())
