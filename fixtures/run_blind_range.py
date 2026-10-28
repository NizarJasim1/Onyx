"""
fixtures.run_blind_range — the VERITAS blind harness.

Runs ONYX against the architecture-faithful RealWorldRange with NO oracle leak (the
contract is reconstructed only from what a real tester observes in traffic), then
scores the findings against the HIDDEN ground truth and prints an honest scorecard:
true positives, false positives (must be zero), false negatives, and the structurally
UNREACHABLE classes — so the internal run predicts a real engagement *including* its
limits.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.transport import make_exchange
from authpath.models import HTTPRequest, Principal
from realworld_range import RealWorldRange, ORACLE, DECOYS, UNREACHABLE


def _contract_from_observed_traffic() -> dict:
    """The contract a REAL tester reconstructs from observed responses — endpoint
    effect classes and the ownership tree visible in resource bodies. It contains NO
    bug locations and NO sensitivity hints (VERITAS V2). r3's parent p9 is exactly
    what the resource body advertises ('project': 'p9')."""
    return {
        "GET /api/projects/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "GET /api/resources/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "GET /api/orgs": {"effect": "READ"},
        "GET /api/cards/{id}": {"effect": "OBJECT_ACCESS"},
        # the ownership link a tester reads straight out of the resource body
        "resource_parents": {"resource:r3": "project:p9"},
    }


def run_blind(verbose: bool = True):
    t = RealWorldRange()
    U = Principal("U", "Member of org o1", {"Authorization": "Bearer U"})
    V = Principal("V", "Admin of org o9", {"Authorization": "Bearer V"})
    scope = ScopeConfig(allowed_hosts=["range.local"], dry_run=True, automation_permitted=True)
    eng = AuthPathEngine(t, {"U": U, "V": V}, scope, contract=_contract_from_observed_traffic())
    eng.cross_surface = eng.temporal_shape = eng.combinatorial = eng.global_invariants = True

    def obs(req, who=U):
        eng.observe(make_exchange(t, req, who))

    def ana(req, who=U):
        return eng.analyze(make_exchange(t, req, who))

    # ---- BASELINE (legitimate traffic a real capture would contain) ---------- #
    # canonical project details (the authoritative reference that filters tax_id)
    obs(HTTPRequest("GET", "/api/projects/p1"))
    obs(HTTPRequest("GET", "/api/projects/p2"))
    # GraphQL org canonical → FORBIDDEN on webhook_secret (intent-declared canonical)
    obs(HTTPRequest("POST", "/graphql", body={"query": "query($id:ID!){ org(id:$id){ webhook_secret } }",
                                              "variables": {"id": "o1"}}))
    # resource r1 first read — ssn correctly filtered (the pre-deploy snapshot)
    obs(HTTPRequest("GET", "/api/resources/r1"))
    # U legitimately reads child r3, and is FORBIDDEN its re-homed parent project p9
    obs(HTTPRequest("GET", "/api/resources/r3"))
    obs(HTTPRequest("GET", "/api/projects/p9"))      # → 403 for U (parent forbidden)
    # decoy baselines (canonical card detail; richer than the list by design)
    obs(HTTPRequest("GET", "/api/cards/c1"))

    # ---- PROBES (the leaking doors a tester would exercise) ------------------ #
    ana(HTTPRequest("GET", "/api/orgs"))             # B1: leaks webhook_secret (vs GraphQL FORBIDDEN)
    ana(HTTPRequest("GET", "/api/projects"))         # B2: list over-projects tax_id (+ RL17 sibling)
    ana(HTTPRequest("GET", "/api/resources/r1"))     # B4: deploy drift exposes ssn
    ana(HTTPRequest("GET", "/api/resources/r3"))     # B3: child accessible, parent p9 forbidden
    # decoy probes — MUST stay clean
    ana(HTTPRequest("GET", "/api/cards"))            # D1: lean list (no leak)
    ana(HTTPRequest("GET", "/api/status"))           # D2: public token (by design)

    # DECLARED-UNREACHABLE probe — prove ONYX misses the cross-operation leak (U1).
    pre = len(eng.findings)
    ana(HTTPRequest("POST", "/graphql", body={"query": "query{ orgWebhooks(id:\"o1\"){ secret } }",
                                              "variables": {"id": "o1"}}))
    u1_missed = len(eng.findings) == pre             # expected True: it is unreachable

    # ---- SCORE against the hidden oracle ------------------------------------ #
    found = []
    for f in eng.findings:
        rid = str(getattr(f, "target_ref", "") or "")
        field = ""
        sp = getattr(f, "state_proof", None)
        blob = " ".join(str(getattr(sp, k, "")) for k in ("before", "after", "detail")) if sp else ""
        found.append((f.effect.value, rid, blob.lower()))

    # the effect class each bug MUST be caught by — a finding of the wrong class on
    # the right resource does NOT count (VERITAS V5: no self-deception).
    _EXPECTED_EFFECT = {"B1": "CROSS_SURFACE", "B2": "CROSS_SURFACE",
                        "B3": "EMERGENT_BREAK", "B4": "AUTH_REGRESSION"}

    def _matches(bug):
        bid, ident, field, _mech = bug
        rid_token = ident.split(":")[-1]
        want = _EXPECTED_EFFECT[bid]
        for eff, tref, blob in found:
            if eff != want:
                continue                       # wrong mechanism → not a real catch
            if rid_token == tref or rid_token in blob:
                if field is None or field.lower() in blob or field.lower() in (tref or ""):
                    return eff
        return None

    tp, fn = [], []
    for bug in ORACLE:
        hit = _matches(bug)
        (tp if hit else fn).append((bug, hit))

    # false positives = findings that map to NO oracle entry and are not the
    # expected RL17 sibling of a real bug
    oracle_tokens = {b[1].split(":")[-1] for b in ORACLE}
    fp = [(eff, tref) for eff, tref, _ in found if tref not in oracle_tokens
          and not any(tok in (tref or "") for tok in oracle_tokens)]

    if verbose:
        print("=" * 70)
        print("  VERITAS — BLIND REAL-WORLD RANGE  ·  honest scorecard")
        print("=" * 70)
        print(f"  findings emitted: {len(eng.findings)}   pass-errors: {eng._pass_errors}")
        print(f"\n  TRUE POSITIVES (real emergent bugs caught): {len(tp)}/{len(ORACLE)}")
        for bug, hit in tp:
            print(f"    ✓ {bug[0]} {bug[1]:14} [{hit}]  ← {bug[3]}")
        print(f"\n  FALSE POSITIVES (must be 0): {len(fp)}")
        for eff, tref in fp:
            print(f"    ✗ {eff} {tref}")
        print(f"\n  FALSE NEGATIVES / UNREACHABLE: {len(fn)}")
        for bug, _ in fn:
            print(f"    – {bug[0]} {bug[1]:14}  {bug[3]}")
        print(f"\n  decoys that must stay clean: {len(DECOYS)} (cards, status)")
        clean_decoys = not any(tok in (tref or "") for _, tref, _ in found for tok in ("c1", "status", "card"))
        print(f"    decoys correctly NOT flagged: {clean_decoys}")
        print(f"\n  DECLARED BLIND SPOTS (predicted real-target misses — VERITAS V6):")
        print(f"    U1 cross-operation leak empirically missed by ONYX: {u1_missed}")
        for uid, ident, desc, need in UNREACHABLE:
            print(f"    – {uid} {desc}")
            print(f"         capability needed: {need}")
        print("=" * 70)

    return {"findings": len(eng.findings), "tp": len(tp), "fp": len(fp),
            "fn": len(fn), "pass_errors": eng._pass_errors, "u1_missed": u1_missed,
            "engine": eng}


if __name__ == "__main__":
    run_blind()
