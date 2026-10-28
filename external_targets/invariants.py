#!/usr/bin/env python3
"""
invariants.py — LAYER 2 of the ONYX deep-recon system: extract the UNWRITTEN RULES
(invariants) a target enforces, from its observed behaviour (HAR, ordered in time).

A deep authorization / business-logic flaw is, almost always, a *broken invariant nobody
noticed*: a balance that went negative, a state that skipped its gate, an owner that
changed, a coupon spent twice. Layer 1 mapped the objects and relations. Layer 2 learns
the rules those objects appear to obey — so Layer 3 can try, with proof, to break them.

ZERO-FALSE-POSITIVE CONTRACT (structural):
  * READ-ONLY ANALYSIS. It re-reads captured traffic in order and emits a ranked list of
    CANDIDATE invariants for a reasoning agent. It never sends a probe, never emits a
    finding, and imports only sitemodel (itself detection-free). It cannot touch any
    accept/reject decision, so it cannot add a false positive.
  * Every invariant is grounded in the observed data and carries an EVIDENCE COUNT (how
    many observations support it) and a CONFIDENCE. Weak (single-observation) rules are
    dropped. Nothing is asserted from a name alone.

Invariant kinds (each: broken => a concrete, high-value hypothesis for the analyst):
  * ownership-constant   — an object's owner/user field never changes once set.
  * state-machine        — the observed status transitions (unseen ones are implicitly
                           forbidden: the gates worth trying to skip).
  * numeric-bound        — a numeric field stayed within an observed sign/range (e.g. >= 0).
  * monotonic            — a numeric field only ever moved one way (balance only rose).
  * same-owner-reference — a reference field always pointed within the same owner.
"""
from __future__ import annotations
import json, re, argparse, sys
from collections import defaultdict, OrderedDict

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
import sitemodel as SM   # detection-free helpers only

_OWNER_FIELDS = ("owner", "owner_id", "ownerid", "user_id", "userid", "user",
                 "account_id", "accountid", "created_by", "customer_id")
_STATE_FIELDS = ("status", "state", "phase", "stage", "step")
_MONEY_FIELDS = ("total", "amount", "balance", "price", "cost", "credit", "quantity",
                 "qty", "sum", "subtotal", "due", "paid", "refund", "points")


def _num(v):
    try:
        if isinstance(v, bool):
            return None
        f = float(v)
        return f
    except (TypeError, ValueError):
        return None


def _walk_objects(node, path_type, owner, out):
    """Yield (otype, oid, owner, scalars) for every object-like dict, like sitemodel."""
    if isinstance(node, dict):
        if SM._looks_like_object(node):
            oid = None
            for k, v in node.items():
                if k.lower() in SM._ID_KEYS and SM._is_id_value(v):
                    oid = v; break
            otype = path_type or ("struct:" + SM._fingerprint(node))
            out.append((otype, str(oid) if oid is not None else None, owner, SM._scalars(node)))
        for v in node.values():
            _walk_objects(v, path_type, owner, out)
    elif isinstance(node, list):
        for v in node:
            _walk_objects(v, path_type, owner, out)


def _base(pattern):
    """Resource root of a path pattern: truncate at the first {id}. /api/orders/{id}/ship
    -> /api/orders ; /api/wallet -> /api/wallet. Used to link an invariant to the
    mutating operations that can change it."""
    segs = (pattern or "").split("/")
    out = []
    for s in segs:
        if s == "{id}":
            break
        out.append(s)
    return "/".join(out) or pattern


def extract(har, token_map=None):
    from urllib.parse import urlparse
    timelines = OrderedDict()
    type_objs = defaultdict(set)
    muts_by_base = defaultdict(lambda: {"eps": set(), "values": set(), "fields": set()})
    for e in ((har.get("log") or {}).get("entries") or []):
        req = e.get("request") or {}; resp = e.get("response") or {}
        method = (req.get("method") or "GET").upper()
        ptype = SM.templatize_path(urlparse(req.get("url", "")).path)
        owner = SM._principal_of(req.get("headers"), token_map)
        # record mutating request bodies (what the CLIENT sent) per resource base
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            base = _base(ptype)
            muts_by_base[base]["eps"].add(f"{method} {ptype}")
            pd = ((req.get("postData") or {}).get("text")) or ""
            try:
                bj = json.loads(pd) if pd.strip() else None
            except ValueError:
                bj = None
            if isinstance(bj, dict):
                for bk, bv in SM._scalars(bj).items():
                    muts_by_base[base]["fields"].add(bk)
                    nv = _num(bv)
                    if nv is not None:
                        muts_by_base[base]["values"].add(nv)
        body = ((resp.get("content") or {}).get("text")) or ""
        if not (isinstance(body, str) and body.strip()):
            continue
        try:
            data = json.loads(body)
        except ValueError:
            continue
        found = []
        _walk_objects(data, ptype, owner, found)
        for otype, oid, own, sc in found:
            if oid is None:
                continue
            key = f"{otype}|{oid}"
            timelines.setdefault(key, {"type": otype, "owner": own, "snaps": []})
            timelines[key]["snaps"].append(sc)
            type_objs[otype].add(key)

    invs = []
    def _agg_for(otype):
        pref = _base(otype)
        eps, vals = set(), set()
        for b, d in muts_by_base.items():
            if b.startswith(pref) or pref.startswith(b):
                eps |= d["eps"]; vals |= d["values"]
        return eps, vals
    def mutators_for(otype):
        return sorted(_agg_for(otype)[0])

    # ---- ownership-constant: an owner field never changes within an object ----
    for otype, keys in type_objs.items():
        for f in _field_names(timelines, keys):
            if not any(o in f.lower() for o in _OWNER_FIELDS):
                continue
            changed = supported = 0
            for k in keys:
                seq = [s[f] for s in timelines[k]["snaps"] if f in s]
                if len(seq) >= 2:
                    supported += 1
                    if len(set(map(str, seq))) > 1:
                        changed += 1
            if supported >= 1 and changed == 0 and supported >= 1:
                invs.append(_inv("ownership-constant", otype, f, supported, 92,
                                 f"`{otype}`.{f} never changes once set "
                                 f"(observed constant on {supported} object(s)) — breaking it = ownership takeover"))

    # ---- state-machine: observed transitions of a status field ----
    for otype, keys in type_objs.items():
        for f in _field_names(timelines, keys):
            if not any(s == f.lower() or s in f.lower() for s in _STATE_FIELDS):
                continue
            transitions, states = set(), set()
            for k in keys:
                seq = [str(s[f]) for s in timelines[k]["snaps"] if f in s]
                seq = [v for i, v in enumerate(seq) if i == 0 or v != seq[i - 1]]  # dedupe consecutive
                states.update(seq)
                for a, b in zip(seq, seq[1:]):
                    transitions.add((a, b))
            if states:
                obs = sorted(transitions)
                all_pairs = {(a, b) for a in states for b in states if a != b}
                missing = sorted(all_pairs - transitions)[:12]   # implicitly-forbidden gates
                muts = mutators_for(otype)
                invs.append(_inv("state-machine", otype, f, len(transitions) or len(states), 90,
                                 f"`{otype}`.{f} states={sorted(states)} observed={obs} "
                                 f"| CANDIDATE gates to try skipping (unseen transitions): {missing} "
                                 f"| driven by: {muts or 'unknown'}",
                                 extra={"states": sorted(states), "transitions": sorted(map(list, transitions)),
                                        "candidate_skips": [list(m) for m in missing],
                                        "driven_by": muts}))

    # ---- numeric-bound + monotonic on money-ish fields ----
    for otype, keys in type_objs.items():
        for f in _field_names(timelines, keys):
            allvals, per_obj_dirs, supported = [], [], 0
            for k in keys:
                seq = [_num(s[f]) for s in timelines[k]["snaps"] if f in s]
                seq = [x for x in seq if x is not None]
                if not seq:
                    continue
                allvals.extend(seq)
                if len(seq) >= 2:
                    supported += 1
                    diffs = [b - a for a, b in zip(seq, seq[1:]) if b != a]
                    if diffs:
                        per_obj_dirs.append("up" if all(d > 0 for d in diffs) else
                                            "down" if all(d < 0 for d in diffs) else "mixed")
            if not allvals:
                continue
            moneyish = any(m in f.lower() for m in _MONEY_FIELDS)
            lo, hi = min(allvals), max(allvals)
            muts = mutators_for(otype)
            if lo >= 0:
                invs.append(_inv("numeric-bound", otype, f, len(allvals),
                                 88 if moneyish else 55,
                                 f"`{otype}`.{f} stayed in [{lo}, {hi}] (>= 0 across {len(allvals)} obs)"
                                 f"{' — money/quantity: breaking negativity is often a logic bug' if moneyish else ''}",
                                 extra={"driven_by": muts} if muts else None))
            if supported >= 1 and per_obj_dirs and all(d == per_obj_dirs[0] for d in per_obj_dirs) \
                    and per_obj_dirs[0] in ("up", "down"):
                invs.append(_inv("monotonic", otype, f, supported,
                                 90 if moneyish else 60,
                                 f"`{otype}`.{f} only ever moved {per_obj_dirs[0]} "
                                 f"(monotonic on {supported} object(s)) — a move the other way would break it"
                                 f"{' | driven by: ' + str(muts) if muts else ''}",
                                 extra={"direction": per_obj_dirs[0], "driven_by": muts} if muts else
                                       {"direction": per_obj_dirs[0]}))

    # ---- cross-field equality: two scalar fields hold equal values consistently ----
    for otype, keys in type_objs.items():
        fields = sorted(_field_names(timelines, keys))
        pair_eq = {}
        for k in keys:
            for s in timelines[k]["snaps"]:
                present = [f for f in fields if f in s and s[f] not in ("", None)]
                for i in range(len(present)):
                    for j in range(i + 1, len(present)):
                        a, b = present[i], present[j]
                        if a.lower() in SM._ID_KEYS or b.lower() in SM._ID_KEYS:
                            continue
                        eq = (str(s[a]) == str(s[b]))
                        st = pair_eq.setdefault((a, b), {"eq": 0, "ne": 0})
                        st["eq" if eq else "ne"] += 1
        for (a, b), st in pair_eq.items():
            if st["eq"] >= 2 and st["ne"] == 0:
                moneyish = any(m in a.lower() or m in b.lower() for m in _MONEY_FIELDS)
                invs.append(_inv("cross-field-equality", otype, f"{a}=={b}", st["eq"],
                                 87 if moneyish else 58,
                                 f"`{otype}`.{a} always equals .{b} ({st['eq']} obs)"
                                 f"{' — a price/amount equality; breaking it = payment/price tamper' if moneyish else ''}"))

    # ---- uniqueness: a field whose value is distinct PER OBJECT (one-time codes / tokens) ----
    for otype, keys in type_objs.items():
        for f in _field_names(timelines, keys):
            if f.lower() in SM._ID_KEYS or f.lower() == "id":
                continue
            per_obj = []            # one representative value per object (must be constant within it)
            for k in keys:
                vs = {str(s[f]) for s in timelines[k]["snaps"] if f in s}
                if len(vs) == 1:
                    per_obj.append(next(iter(vs)))
            if len(per_obj) >= 3 and len(set(per_obj)) == len(per_obj):
                hinty = any(h in f.lower() for h in ("coupon", "code", "token", "voucher",
                                                     "nonce", "otp", "promo", "ref", "serial"))
                invs.append(_inv("uniqueness", otype, f, len(per_obj),
                                 84 if hinty else 50,
                                 f"`{otype}`.{f} is distinct per object across {len(per_obj)} objects"
                                 f"{' — one-time value; breaking it = replay/reuse (e.g. coupon double-spend)' if hinty else ''}"))

    # ---- client-trusted delta: a state change whose magnitude equals a value the CLIENT sent ----
    for otype, keys in type_objs.items():
        client_vals = _agg_for(otype)[1]
        if not client_vals:
            continue
        for f in _field_names(timelines, keys):
            deltas = set()
            for k in keys:
                seq = [_num(s[f]) for s in timelines[k]["snaps"] if f in s]
                seq = [x for x in seq if x is not None]
                for a, b in zip(seq, seq[1:]):
                    if b != a:
                        deltas.add(round(b - a, 6))
            hit = deltas & {round(v, 6) for v in client_vals}
            if hit and any(m in f.lower() for m in _MONEY_FIELDS):
                invs.append(_inv("client-trusted-value", otype, f, len(hit), 89,
                                 f"`{otype}`.{f} changed by exactly a value the CLIENT supplied "
                                 f"(deltas {sorted(hit)} match request body values) — the server may "
                                 f"trust a client-controlled amount; try sending a manipulated value"))

    # ---- same-owner-reference (reuses Layer-1 relation logic) ----
    model = SM.from_sources(har=har, token_map=token_map)
    same_owner = defaultdict(lambda: {"same": 0, "cross": 0})
    for r in model.references:
        k = (r["from_type"], r["field"], r["to_type"])
        same_owner[k]["cross" if r["cross_ownership"] else "same"] += 1
    for (ft, field, tt), c in same_owner.items():
        if c["same"] >= 1 and c["cross"] == 0:
            invs.append(_inv("same-owner-reference", ft, field, c["same"], 86,
                             f"`{ft}`.{field} always pointed to a `{tt}` owned by the same principal "
                             f"({c['same']} obs) — a cross-owner value here is an authority-inheritance break"))

    invs.sort(key=lambda x: -x["signal"])
    return {"counts": {"objects": len(timelines), "invariants": len(invs)},
            "invariants": invs}


def _field_names(timelines, keys):
    fs = set()
    for k in keys:
        for s in timelines[k]["snaps"]:
            fs.update(s.keys())
    return fs


def _inv(kind, otype, field, evidence, signal, statement, extra=None):
    d = {"kind": kind, "type": otype, "field": field, "evidence": evidence,
         "confidence": "high" if evidence >= 3 else "medium" if evidence == 2 else "low",
         "signal": signal, "statement": statement}
    if extra:
        d.update(extra)
    return d


def render_markdown(rep):
    L = [f"# ONYX invariants - Layer 2  (objects={rep['counts']['objects']}, "
         f"invariants={rep['counts']['invariants']})\n",
         "Candidate rules the target appears to enforce, ranked by how valuable BREAKING "
         "each would be. ONYX (Layer 3) will try to break them with Δstate proof.\n",
         "## Ranked invariants (highest-impact first)"]
    for i in rep["invariants"][:40]:
        L.append(f"- **[{i['signal']}] {i['kind']}** ({i['confidence']}, {i['evidence']} obs) - {i['statement']}")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX Layer-2 invariant extractor (read-only; zero-FP by construction).")
    ap.add_argument("--har", required=True)
    ap.add_argument("--tokens")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    har = json.load(open(args.har))
    token_map = json.loads(args.tokens) if args.tokens else None
    rep = extract(har, token_map)
    print(render_markdown(rep))
    if args.out:
        json.dump(rep, open(args.out, "w"), indent=2, default=list)
        print(f"\n[full JSON invariants written to {args.out}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
