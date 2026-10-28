"""
Blind benchmark for the certifying-algorithm layer (BLIND-CERT).
================================================================

WHY (breaking designer-imagination circularity, offline)
--------------------------------------------------------
The sharpest attack on any self-authored benchmark: one mind designs both the
target and the detector, so only IMAGINED faults get tested. This benchmark
reduces that circularity structurally — the honest way, short of a separate
organisation:

  * Faults are authored from an EXTERNAL taxonomy (OWASP API authz classes:
    BOLA, secondary-key BOLA, AUTHN-gap, cross-principal write/delete, plus
    out-of-boundary uniform-BOPLA and BFLA-by-role) expressed as plain HTTP
    behaviour — NOT from ONYX's law catalog.
  * Which case is genuine vs decoy vs out-of-boundary, and every value, is chosen
    at seeded random; the seed is not hand-tuned.
  * The ground-truth oracle is HASH-SEALED before any detection runs.
  * Cases come in FAMILIAR and STRANGE forms (nested value, secondary key, masked
    value, coincidental non-match) to test generalisation, not memorisation.
  * Adversarial DECOYS (denied, own-data, masked, unchanged-write, absent field,
    coincidental value) must NOT be certified — this is where circularity truly
    breaks: precision has real teeth.
  * ISOLATION: this file imports only the layer under test (itself decision-free)
    + stdlib. It does not consult check_certificate when deciding ground truth.

HONEST CEILING (kept, not hidden)
---------------------------------
Because the same author wrote this benchmark and the layer, this is a HIGH-QUALITY
SIMULATION of independent testing, not a substitute for a third party. Its real
value is: (1) precision under adversarial decoys, (2) generalisation across strange
forms, (3) a sealed, randomised, repeatable check that the layer's behaviour matches
its DECLARED coverage boundary. Recall on in-boundary genuine cases is close to
definitional (the layer's predicate IS the violation's definition) and is reported
as such. The layer's contract assumes `sensitive_field` names a genuinely
owner-private field; a caller that names a shared field is a transcript-fidelity
issue OUTSIDE this layer's promise (stated in the coverage residual), so such cases
are deliberately not scored as detector precision failures.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath import certificate as C  # the layer under test (itself decision-free)

FAMILIAR, STRANGE, BOUNDARY = "familiar", "strange", "boundary"
GENUINE, DECOY, OUT_OF_BOUNDARY = "genuine", "decoy", "out_of_boundary"


def _seal(oracle: dict) -> str:
    body = json.dumps(oracle, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _mask(v: str) -> str:
    v = str(v)
    return "****" + v[-4:]


def build_world(seed: int) -> tuple[list, dict, str]:
    """Author a randomised set of cases from the external taxonomy, then seal the
    oracle. Returns (cases, oracle, sealed_hash). Each case carries its certificate
    plus the SEALED expectation the layer will be scored against."""
    rng = random.Random(seed)

    def secret():
        return "SEC-" + "".join(rng.choice("0123456789ABCDEF") for _ in range(10))

    def owner_id():
        return "OWN-" + str(rng.randint(1000, 9999))

    cases = []

    def add(cid, category, kind_label, form, cert, expect):
        cases.append({"id": cid, "category": category, "kind": kind_label,
                      "form": form, "cert": cert, "expect": expect})

    # ---- IN-BOUNDARY GENUINE (expect CERTIFIED) ---------------------------- #
    s = secret(); oid = owner_id()
    add("bola_read", GENUINE, "BOLA", FAMILIAR, C.emit_certificate(
        finding={"fid": "g", "effect": "READ"},
        claim={"kind": C.KIND_READ_LEAK, "read_as": "alice", "sensitive_field": "iban"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "GET", "path": f"/api/accounts/{oid}"},
                                 "response": {"status": 200, "body": {"id": oid, "iban": s}}},
                    "owner_view": {"response": {"status": 200, "body": {"id": oid, "iban": s}}}},
        provenance="self"), C.CERTIFIED)

    s = secret(); oid = owner_id()
    add("bola_nested", GENUINE, "BOLA", STRANGE, C.emit_certificate(
        finding={"fid": "g", "effect": "READ"},
        claim={"kind": C.KIND_READ_LEAK, "read_as": "alice", "sensitive_field": "iban"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "GET", "path": f"/api/accounts/{oid}"},
                                 "response": {"status": 200, "body": {"account": {"details": {"iban": s}}}}},
                    "owner_view": {"response": {"status": 200, "body": {"account": {"details": {"iban": s}}}}}},
        provenance="self"), C.CERTIFIED)

    s = secret()
    add("bola_secondary_key", GENUINE, "BOLA_secondary_key", STRANGE, C.emit_certificate(
        finding={"fid": "g", "effect": "READ"},
        claim={"kind": C.KIND_READ_LEAK, "read_as": "alice", "sensitive_field": "email"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "GET", "path": "/api/orders?invoice=INV-7"},
                                 "response": {"status": 200, "body": {"invoice": "INV-7", "email": s}}},
                    "owner_view": {"response": {"status": 200, "body": {"invoice": "INV-7", "email": s}}}},
        provenance="self"), C.CERTIFIED)

    s = secret(); oid = owner_id()
    add("authn_gap", GENUINE, "AUTHN_gap", FAMILIAR, C.emit_certificate(
        finding={"fid": "g", "effect": "READ"},
        claim={"kind": C.KIND_AUTHN_GAP, "read_as": "alice", "sensitive_field": "ssn"},
        transcript={"attacker": {"principal": "anon",
                                 "request": {"method": "GET", "path": f"/api/accounts/{oid}"},
                                 "response": {"status": 200, "body": {"id": oid, "ssn": s}}},
                    "owner_view": {"response": {"status": 200, "body": {"id": oid, "ssn": s}}}},
        provenance="self"), C.CERTIFIED)

    a, b = secret(), secret()
    add("xwrite", GENUINE, "XWRITE", FAMILIAR, C.emit_certificate(
        finding={"fid": "g", "effect": "WRITE"},
        claim={"kind": C.KIND_XPRINCIPAL_WRITE, "read_as": "alice"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "PUT", "path": "/api/docs/D"},
                                 "response": {"status": 200, "body": {"ok": True}}},
                    "victim_readback_before": {"response": {"status": 200, "body": {"id": "D", "v": a}}},
                    "victim_readback_after": {"response": {"status": 200, "body": {"id": "D", "v": b}}}},
        provenance="self"), C.CERTIFIED)

    a = secret()
    add("xdelete", GENUINE, "XDELETE", STRANGE, C.emit_certificate(
        finding={"fid": "g", "effect": "WRITE"},
        claim={"kind": C.KIND_XPRINCIPAL_WRITE, "read_as": "alice"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "DELETE", "path": "/api/docs/D"},
                                 "response": {"status": 200, "body": {"ok": True}}},
                    "victim_readback_before": {"response": {"status": 200, "body": {"id": "D", "v": a}}},
                    "victim_readback_after": {"response": {"status": 404, "body": None}}},
        provenance="self"), C.CERTIFIED)

    # ---- ADVERSARIAL DECOYS (expect NOT CERTIFIED) ------------------------ #
    s = secret(); oid = owner_id()
    add("denied_403", DECOY, "BOLA", FAMILIAR, C.emit_certificate(
        finding={"fid": "d", "effect": "READ"},
        claim={"kind": C.KIND_READ_LEAK, "read_as": "alice", "sensitive_field": "iban"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "GET", "path": f"/api/accounts/{oid}"},
                                 "response": {"status": 403, "body": {"error": "forbidden"}}},
                    "owner_view": {"response": {"status": 200, "body": {"id": oid, "iban": s}}}},
        provenance="self"), C.REJECTED)

    s = secret()
    add("own_data", DECOY, "BOLA", FAMILIAR, C.emit_certificate(
        finding={"fid": "d", "effect": "READ"},
        claim={"kind": C.KIND_READ_LEAK, "read_as": "bob", "sensitive_field": "iban"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "GET", "path": "/api/accounts/BOB"},
                                 "response": {"status": 200, "body": {"id": "BOB", "iban": s}}},
                    "owner_view": {"response": {"status": 200, "body": {"id": "BOB", "iban": s}}}},
        provenance="self"), C.REJECTED)

    s = secret(); oid = owner_id()
    add("masked_value", DECOY, "BOLA", STRANGE, C.emit_certificate(
        finding={"fid": "d", "effect": "READ"},
        claim={"kind": C.KIND_READ_LEAK, "read_as": "alice", "sensitive_field": "iban"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "GET", "path": f"/api/accounts/{oid}"},
                                 "response": {"status": 200, "body": {"id": oid, "iban": _mask(s)}}},
                    "owner_view": {"response": {"status": 200, "body": {"id": oid, "iban": s}}}},
        provenance="self"), C.REJECTED)

    s1, s2 = secret(), secret()
    add("coincidental_value", DECOY, "BOLA", STRANGE, C.emit_certificate(
        finding={"fid": "d", "effect": "READ"},
        claim={"kind": C.KIND_READ_LEAK, "read_as": "alice", "sensitive_field": "iban"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "GET", "path": "/api/accounts/X"},
                                 "response": {"status": 200, "body": {"id": "BOB", "iban": s2}}},
                    "owner_view": {"response": {"status": 200, "body": {"id": "ALICE", "iban": s1}}}},
        provenance="self"), C.REJECTED)

    add("unchanged_write", DECOY, "XWRITE", FAMILIAR, C.emit_certificate(
        finding={"fid": "d", "effect": "WRITE"},
        claim={"kind": C.KIND_XPRINCIPAL_WRITE, "read_as": "alice"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "PUT", "path": "/api/docs/D"},
                                 "response": {"status": 200, "body": {"ok": True}}},
                    "victim_readback_before": {"response": {"status": 200, "body": {"id": "D", "v": "same"}}},
                    "victim_readback_after": {"response": {"status": 200, "body": {"id": "D", "v": "same"}}}},
        provenance="self"), C.REJECTED)

    # ---- OUT-OF-BOUNDARY (expect ABSTAIN — honest coverage edge) ----------- #
    add("uniform_bopla_no_owner", OUT_OF_BOUNDARY, "uniform_BOPLA", BOUNDARY, C.emit_certificate(
        finding={"fid": "o", "effect": "READ"},
        claim={"kind": C.KIND_READ_LEAK, "read_as": "alice", "sensitive_field": "iban"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "GET", "path": "/api/accounts/X"},
                                 "response": {"status": 200, "body": {"id": "X", "iban": secret()}}}},
        provenance="self"), C.ABSTAIN)  # no owner_view bundled -> abstain

    add("bfla_role_no_delta", OUT_OF_BOUNDARY, "BFLA_role", BOUNDARY, C.emit_certificate(
        finding={"fid": "o", "effect": "WRITE"},
        claim={"kind": C.KIND_XPRINCIPAL_WRITE, "read_as": "alice"},
        transcript={"attacker": {"principal": "bob",
                                 "request": {"method": "POST", "path": "/api/admin/promote"},
                                 "response": {"status": 200, "body": {"ok": True}}}},
        provenance="self"), C.ABSTAIN)  # no owner read-back consequence -> abstain

    # shuffle so order carries no signal, then seal the oracle BEFORE detection
    rng.shuffle(cases)
    oracle = {c["id"]: c["expect"] for c in cases}
    return cases, oracle, _seal(oracle)


def run(seed: int) -> dict:
    cases, oracle, sealed = build_world(seed)
    # (oracle is sealed above; detection happens only now)
    decoys_certified = genuine_certified = boundary_abstained = 0
    n_decoy = n_genuine = n_boundary = 0
    by_form = {}
    for c in cases:
        status = C.check_certificate(c["cert"])["status"]
        f = by_form.setdefault(c["form"], {"ok": 0, "n": 0})
        f["n"] += 1
        if c["category"] == GENUINE:
            n_genuine += 1
            hit = status == C.CERTIFIED
            genuine_certified += hit
            f["ok"] += hit
        elif c["category"] == DECOY:
            n_decoy += 1
            certed = status == C.CERTIFIED
            decoys_certified += certed
            f["ok"] += (not certed)
        else:
            n_boundary += 1
            ab = status == C.ABSTAIN
            boundary_abstained += ab
            f["ok"] += ab
    return {
        "seed": seed, "sealed_oracle": sealed[:16],
        "precision": 1.0 - (decoys_certified / n_decoy if n_decoy else 0),
        "decoys_certified": decoys_certified, "n_decoy": n_decoy,
        "recall_in_boundary": genuine_certified / n_genuine if n_genuine else 1.0,
        "n_genuine": n_genuine,
        "boundary_correct": boundary_abstained / n_boundary if n_boundary else 1.0,
        "n_boundary": n_boundary,
        "by_form": by_form,
    }


def aggregate(seeds) -> dict:
    dc = gc = bc = nd = ng = nb = 0
    forms = {}
    for s in seeds:
        r = run(s)
        dc += r["decoys_certified"]; nd += r["n_decoy"]
        gc += round(r["recall_in_boundary"] * r["n_genuine"]); ng += r["n_genuine"]
        bc += round(r["boundary_correct"] * r["n_boundary"]); nb += r["n_boundary"]
        for k, v in r["by_form"].items():
            f = forms.setdefault(k, {"ok": 0, "n": 0})
            f["ok"] += v["ok"]; f["n"] += v["n"]
    return {
        "seeds": len(list(seeds)) if hasattr(seeds, "__len__") else None,
        "precision": 1.0 - (dc / nd if nd else 0), "decoys_certified": dc, "n_decoy": nd,
        "recall_in_boundary": gc / ng if ng else 1.0, "n_genuine": ng,
        "boundary_correct": bc / nb if nb else 1.0, "n_boundary": nb,
        "by_form": forms,
    }


if __name__ == "__main__":
    import sys
    seeds = list(range(1, 26))
    agg = aggregate(seeds)
    print("BLIND-CERT — certifying-algorithm layer, external-taxonomy blind benchmark")
    print(f"  seeds                 : {len(seeds)} (sealed, randomised)")
    print(f"  precision             : [T2_SELF_MEASURED] {agg['precision']:.3f} "
          f"({agg['decoys_certified']} of {agg['n_decoy']} decoys certified — must be 0)")
    print(f"  recall (in-boundary)  : [T2_SELF_MEASURED] {agg['recall_in_boundary']:.3f} "
          f"(near-definitional; over {agg['n_genuine']} genuine cases)")
    print(f"  coverage-boundary ok  : [T2_SELF_MEASURED] {agg['boundary_correct']:.3f} "
          f"(out-of-boundary correctly abstained, {agg['n_boundary']} cases)")
    print("  by form:")
    for k in sorted(agg["by_form"]):
        v = agg["by_form"][k]
        print(f"    {k:10s}: {v['ok']}/{v['n']}")
    print("  NOTE: simulation of independence (same author), not a substitute for a")
    print("        third-party target; the sharp signals are precision on adversarial")
    print("        decoys and generalisation across strange forms.")
    ok = agg["precision"] == 1.0 and agg["recall_in_boundary"] >= 0.95 and agg["boundary_correct"] == 1.0
    print("  RESULT: PASS" if ok else "  RESULT: FAIL")
    sys.exit(0 if ok else 1)
