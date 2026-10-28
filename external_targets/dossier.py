#!/usr/bin/env python3
"""
dossier.py — fuses ONYX Layer 1 (site model) + Layer 2 (invariants) into a single, ranked
DOSSIER for a reasoning agent (the analyst): the object/relation map, the learned rules, and —
the crown jewels — the CROSS-CUTTING HYPOTHESES that arise only when the two layers meet.

A deep authorization / business-logic flaw usually lives at an intersection: a rule that
says "this reference stays within its owner" (Layer 2) sitting on a relation that links to
another principal's object (Layer 1); a state gate (Layer 2) reachable by a mutating op on
a resource the site otherwise guards (Layer 1). This module surfaces those intersections
as ranked, actionable HYPOTHESES — not findings. ONYX (Layer 3) will try to prove/refute
them with Δstate; the analyst decides which are worth it.

ZERO-FALSE-POSITIVE CONTRACT (structural):
  * READ-ONLY. Imports only sitemodel + invariants (both detection-free). Sends no probe,
    emits no finding, touches no accept/reject decision — it cannot add a false positive.
  * Hypotheses are explicitly labelled as HYPOTHESES with the evidence they rest on; they
    are never presented as confirmed. Confirmation is ONYX's job, downstream, with proof.
"""
from __future__ import annotations
import json, argparse, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sitemodel as SM
import invariants as INV


def _hyp(title, signal, owasp, rationale, probe):
    return {"hypothesis": title, "signal": signal, "owasp": owasp,
            "rests_on": rationale, "suggested_probe": probe}


def build(har=None, openapi=None, token_map=None):
    model = SM.from_sources(har=har, openapi=openapi, token_map=token_map)
    l1 = model.report()
    l2 = INV.extract(har, token_map) if har else {"counts": {}, "invariants": []}
    invs = l2["invariants"]
    by_kind = {}
    for i in invs:
        by_kind.setdefault(i["kind"], []).append(i)

    H = []

    # H1 — state-gate skip (state-machine missing transition + a mutating op that drives it)
    for i in by_kind.get("state-machine", []):
        muts = i.get("driven_by") or []
        for skip in (i.get("candidate_skips") or [])[:6]:
            H.append(_hyp(
                f"Skip the {skip[0]}→{skip[1]} gate on {i['type']}.{i['field']}",
                i["signal"] + 4, "API6 business-logic",
                f"state-machine invariant: transition {skip} was never observed (implicitly forbidden); "
                f"resource is mutated by {muts or 'an unknown op'}",
                f"drive {i['type']} directly from '{skip[0]}' to '{skip[1]}' via {muts or 'a mutating call'} "
                f"and read the state back — a jump that reaches a privileged state (paid/approved/delivered) "
                f"without its gate is the break"))

    # H2 — client-trusted money value (server changed a money field by a client-supplied amount)
    for i in by_kind.get("client-trusted-value", []):
        H.append(_hyp(
            f"Manipulate the client-controlled amount driving {i['type']}.{i['field']}",
            i["signal"] + 3, "API6 business-logic / API3 mass-assignment",
            "client-trusted-value invariant: a money field changed by exactly a value the client sent",
            f"replay the driving request with a manipulated amount (negative, zero, huge, or another "
            f"principal's id) and read {i['field']} back — if the server honours it, that's the break"))

    # H3 — payment/price tamper (money cross-field equality)
    for i in by_kind.get("cross-field-equality", []):
        if i["signal"] >= 80:
            H.append(_hyp(
                f"Break the {i['field']} equality on {i['type']}",
                i["signal"] + 2, "API6 business-logic",
                "cross-field-equality invariant on money fields (e.g. paid_amount == total)",
                f"submit values that violate {i['field']} (pay less than total / set price below cost) "
                f"and read back the persisted object"))

    # H4 — one-time value reuse (money/coupon uniqueness)
    for i in by_kind.get("uniqueness", []):
        if i["signal"] >= 80:
            H.append(_hyp(
                f"Reuse the one-time {i['field']} on {i['type']}",
                i["signal"] + 2, "API6 business-logic",
                "uniqueness invariant: the value is distinct per object (a one-time code/token)",
                f"apply the same {i['field']} twice and read the balance/credit back — a second success "
                f"is a double-spend / replay"))

    # H5 — ownership takeover (an owner field that never changes)
    for i in by_kind.get("ownership-constant", []):
        H.append(_hyp(
            f"Take over ownership by changing {i['type']}.{i['field']}",
            i["signal"], "API1 BOLA / API3 mass-assignment",
            "ownership-constant invariant: the owner field was never observed to change",
            f"send a write that sets {i['field']} to another principal, then read back as that "
            f"principal — persistence = takeover"))

    # H6 — same-owner-reference violated (make a within-owner reference point cross-owner)
    for i in by_kind.get("same-owner-reference", []):
        H.append(_hyp(
            f"Point {i['type']}.{i['field']} at another owner's object",
            i["signal"] + 2, "API1 BOLA (authority inheritance)",
            "same-owner-reference invariant: this reference always stayed within its owner",
            f"create/update {i['type']} with {i['field']} set to an object id owned by a different "
            f"principal, then read the linked data back — cross-owner access = the break"))

    # H7 — relation BOLA (Layer-1 cross-ownership relation actually observed)
    for r in l1.get("cross_ownership_relations", []):
        H.append(_hyp(
            f"Reach {r['to_type']} through {r['from_type']}.{r['field']} across owners",
            r.get("score", 90) + 5, "API1 BOLA",
            f"Layer-1 fact: an observed {r['from_type']} owned by {r['from_owner']} references a "
            f"{r['to_type']} owned by {r['to_owner']} via .{r['field']}",
            f"as {r['from_owner']}, follow .{r['field']} to the {r['to_type']} and confirm you read "
            f"{r['to_owner']}'s private fields you were never granted"))

    # H8 — authority-inheritance chain (multi-hop)
    for c in l1.get("authority_inheritance_chains", []):
        H.append(_hyp(
            f"Traverse authority-inheritance chain ({c['length']} hops)",
            c.get("score", 96), "API1 BOLA (chained)",
            f"Layer-1 fact: {c['hops']}",
            "walk the chain hop by hop; each hop that yields another owner's object without a fresh "
            "authorization check is the break — chains are the deepest, least-tested seams"))

    # H9 — BFLA (privileged endpoint tried as the unprivileged principal)
    admin = l1.get("roles", {}).get("admin_like")
    for d in l1.get("decision_points", []):
        H.append(_hyp(
            f"Invoke {d['endpoint']} as a non-privileged principal",
            d.get("score", 80) + (5 if admin in d.get("allowed_for", []) else 0),
            "API5 BFLA",
            f"Layer-1 decision point: allowed for {d['allowed_for']}, denied for {d['denied_for']}",
            f"replay {d['endpoint']} with a denied principal's token; a 2xx with real data is function-"
            f"level authorization broken"))

    H.sort(key=lambda x: -x["signal"])

    unified = list(l1.get("attention_list", []))
    return {
        "counts": {**{"l1_" + k: v for k, v in l1["counts"].items()},
                   **{"l2_invariants": len(invs)}, "hypotheses": len(H)},
        "roles": l1.get("roles", {}),
        "hypotheses": H,
        "layer1": l1,
        "layer2": {"invariants": invs},
    }


def render_markdown(dos):
    L = ["# ONYX dossier for the analyst — fused map + rules + hypotheses\n",
         f"L1: objects={dos['counts'].get('l1_objects',0)} "
         f"cross-ownership={dos['counts'].get('l1_cross_ownership',0)} "
         f"chains={dos['counts'].get('l1_chains',0)} "
         f"decision-points={dos['counts'].get('l1_decision_points',0)}  |  "
         f"L2: invariants={dos['counts'].get('l2_invariants',0)}  |  "
         f"**hypotheses={dos['counts']['hypotheses']}**\n"]
    if dos["roles"].get("admin_like"):
        L.append(f"Likely privileged principal: `{dos['roles']['admin_like']}`\n")
    L.append("## 🎯 Ranked hypotheses (what to probe, highest-value first)")
    L.append("_These are HYPOTHESES for you to judge — ONYX will prove/refute the ones you pick with Δstate._\n")
    for h in dos["hypotheses"][:25]:
        L.append(f"### [{h['signal']}] {h['hypothesis']}  ·  _{h['owasp']}_")
        L.append(f"- rests on: {h['rests_on']}")
        L.append(f"- probe: {h['suggested_probe']}\n")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX dossier — fuse Layers 1+2 for the analyst (read-only, zero-FP).")
    ap.add_argument("--har"); ap.add_argument("--openapi"); ap.add_argument("--tokens"); ap.add_argument("--out")
    args = ap.parse_args(argv)
    if not args.har and not args.openapi:
        ap.error("give --har and/or --openapi")
    har = json.load(open(args.har)) if args.har else None
    spec = json.load(open(args.openapi)) if args.openapi else None
    token_map = json.loads(args.tokens) if args.tokens else None
    dos = build(har=har, openapi=spec, token_map=token_map)
    print(render_markdown(dos))
    if args.out:
        json.dump(dos, open(args.out, "w"), indent=2, default=list)
        print(f"\n[full JSON dossier written to {args.out}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
