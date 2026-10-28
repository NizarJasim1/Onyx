#!/usr/bin/env python3
"""
agent_loop.py — Phase 6 (part 1): THE CLOSED ANALYST-IN-THE-LOOP.

The vision's last mile: ONYX dissects → the analyst reasons like a researcher and PROPOSES a probe
→ ONYX proves or refutes it by Δstate → only NEW confirmed findings rise to a human. This module
is the safe socket the analyst plugs into. The analyst PROPOSES; the engine DISPOSES.

THE WALL (why an LLM in the loop cannot widen risk or manufacture a finding):
  An analyst proposal is a constrained cfg, and validate_proposal REJECTS it before it ever runs if:
    * it names an off-scope or absolute-URL target (Scope-Guard),
    * it probes an id that was NOT observed/harvested from THIS target (no invented ids),
    * it requests a write without an explicit confirm grant (read-only by default),
    * it asks for an effect outside the allowed set.
  A proposal that passes the wall is run ONLY through the proven path (serve._build_scan → gate →
  IARC/ownership). So a WRONG proposal simply yields 0 confirmed (the engine disposes), and an
  UNSAFE proposal never reaches the engine at all. The analyst cannot bypass the gate, cannot invent a
  finding, and cannot steer ONYX off-scope. Humans touch only: accounts, scope, final submission.
"""
from __future__ import annotations
import json, argparse, sys, os
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onyx_recon as OR
import alt_paths_deep as L4X
import conductor as COND

ALLOWED_EFFECTS = {"OBJECT_ACCESS", "OWNERSHIP", "AUTHORITY", "PAYMENT", "PRICE",
                   "STATE_GATE", "INVENTORY", "COUPON"}
CROSS_EFFECTS = {"OBJECT_ACCESS", "OWNERSHIP", "AUTHORITY"}


def grounding_from_capture(har, token_map):
    """Everything the analyst is ALLOWED to reference: ids the server actually disclosed, plus the
    authoritative ownership map (from self-reads). Anything else is 'invented'."""
    id_doors, _id_path, ownership, _leaks = L4X.object_identity(L4X.normalize(har, token_map))
    return set(id_doors.keys()), ownership


def validate_proposal(p, *, scope, grounded_ids, ownership, principals, allow_writes=False):
    """The security wall. Returns (ok, reason)."""
    path = str(p.get("path", ""))
    if ("://" in path or not path.startswith("/") or path.startswith("//")
            or "@" in path.split("?")[0] or "\\" in path):
        # reject absolute URLs, protocol-relative (//host = host escape), userinfo, backslashes
        return False, "path must be a relative, in-scope path (no absolute/protocol-relative URL)"
    method = str(p.get("method", "GET")).upper()
    if method != "GET" and not allow_writes:
        return False, f"{method} is a write — needs an explicit confirm grant (read-only by default)"
    eff = str(p.get("effect", "object-access")).upper().replace("-", "_")
    if eff not in ALLOWED_EFFECTS:
        return False, f"effect '{eff}' is not in the allowed set"
    ids = p.get("target_ids") or {}
    flat = [str(i) for v in ids.values() for i in (v if isinstance(v, list) else [v])]
    if not flat:
        return False, "no target ids proposed"
    ungrounded = sorted({i for i in flat if i not in grounded_ids})
    if ungrounded:
        return False, f"ungrounded (not observed on this target) ids — refusing to invent: {ungrounded}"
    return True, "ok"


def run_proposal(base_url, principals, proposal, *, grounded_ids, ownership, scope=None,
                 researcher="", allow_writes=False):
    """Validate then run ONE the analyst proposal through the proven path. Returns
    {accepted, reason, confirmed:[...]}. confirmed is always engine-decided."""
    ok, reason = validate_proposal(proposal, scope=scope, grounded_ids=grounded_ids,
                                   ownership=ownership, principals=principals, allow_writes=allow_writes)
    if not ok:
        return {"accepted": False, "reason": reason, "confirmed": []}

    from authpath.serve import _build_scan
    host = urlparse(base_url).hostname
    cli = OR.Client(scope or [host], researcher=researcher)
    eff = str(proposal.get("effect", "object-access")).upper().replace("-", "_")
    ep = {"method": str(proposal.get("method", "GET")).upper(), "path": proposal["path"],
          "effect": eff, "ids": {k: [str(i) for i in (v if isinstance(v, list) else [v])]
                                 for k, v in (proposal.get("target_ids") or {}).items()}}
    if proposal.get("body"):
        ep["body"] = json.dumps(proposal["body"]) if isinstance(proposal["body"], dict) else proposal["body"]
    cfg = {"base_url": base_url, "authorized": True, "dry_run": not allow_writes, "researcher": researcher,
           "program": "authorized engagement",
           "principals": {p: {"value": t, "type": "bearer"} for p, t in principals.items()},
           "endpoints": [ep], "seeds": [],
           "test_resources": sorted({str(i) for v in ep["ids"].values() for i in v}),
           "engagement_id": "analyst-proposal"}
    engine, _ = _build_scan(cfg)
    snap = engine.snapshot()
    grounded = grounded_ids | {str(i) for v in ep["ids"].values() for i in v}
    gate = [fd for fd in snap["findings"]
            if OR._is_probeable(str(fd.get("endpoint", ""))) and OR._looks_like_id(fd.get("target", ""))
            and str(fd.get("target", "")) in grounded]
    ep_meta = OR._ep_meta([ep])
    kept = [fd for fd in gate if OR.reconfirm(cli, base_url, principals, pool={}, finding=fd, ep_meta=ep_meta)[0]]
    # ownership consistency: drop any self-read (actor == established owner) for cross effects
    out = []
    for fd in kept:
        owner = ownership.get(str(fd.get("target")))
        if eff in CROSS_EFFECTS and owner is not None and owner == str(fd.get("actor")):
            continue
        fd = dict(fd); fd["hypothesis"] = proposal.get("hypothesis", "")
        out.append(fd)
    return {"accepted": True, "reason": "ran via proven path", "confirmed": out}


def loop(base_url, principals, har, propose_fn, *, token_map=None, scope=None, researcher="",
         max_rounds=3, allow_writes=False):
    """Closed loop: dissect → the analyst proposes (propose_fn(packet, known)) → engine confirms →
    only NEW confirmed rise. propose_fn simulates the analyst; in production it IS the analyst reading the
    packet. Returns {baseline, new_confirmed, rejected, rounds}."""
    token_map = token_map or {t: p for p, t in principals.items()}
    grounded_ids, ownership = grounding_from_capture(har, token_map)
    packet = COND.run(base_url, principals, har=har, token_map=token_map, scope=scope, researcher=researcher)
    known = {(r["effect"], r["actor"], r["target"]) for r in packet["confirmed"]}
    new_confirmed, rejected = [], []
    for rnd in range(max_rounds):
        proposals = propose_fn(packet, known) or []
        if not proposals:
            break
        progressed = False
        for p in proposals:
            res = run_proposal(base_url, principals, p, grounded_ids=grounded_ids,
                               ownership=ownership, scope=scope, researcher=researcher,
                               allow_writes=allow_writes)
            if not res["accepted"]:
                rejected.append({"proposal": p, "reason": res["reason"]})
                continue
            for fd in res["confirmed"]:
                key = (str(fd.get("effect")), str(fd.get("actor")), str(fd.get("target")))
                if key not in known:
                    known.add(key); new_confirmed.append(fd); progressed = True
        if not progressed:
            break
    return {"baseline": len(packet["confirmed"]), "new_confirmed": new_confirmed,
            "rejected": rejected, "rounds": rnd + 1}


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX closed loop — The analyst proposes, the engine disposes (wall-guarded).")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--base-url", required=True); ap.add_argument("--har", required=True)
    ap.add_argument("--proposals", required=True, help="JSON list of the analyst proposals")
    ap.add_argument("--scope"); ap.add_argument("--principal", action="append", default=[])
    ap.add_argument("--tokens"); ap.add_argument("--researcher", default="")
    args = ap.parse_args(argv)
    if not args.authorized:
        sys.exit("Refusing to run: pass --authorized.")
    principals = dict(s.split(":", 1) for s in args.principal)
    har = json.load(open(args.har)); proposals = json.load(open(args.proposals))
    token_map = json.loads(args.tokens) if args.tokens else {t: p for p, t in principals.items()}
    scope = [h.strip() for h in args.scope.split(",")] if args.scope else None
    res = loop(args.base_url, principals, har, lambda pkt, known: proposals,
               token_map=token_map, scope=scope, researcher=args.researcher, max_rounds=1)
    print(f"baseline={res['baseline']}  NEW confirmed={len(res['new_confirmed'])}  rejected={len(res['rejected'])}")
    for fd in res["new_confirmed"]:
        print(f"  [NEW] {fd.get('actor')} → {fd.get('target')}  {fd.get('endpoint')}  «{fd.get('hypothesis','')}»")
    for r in res["rejected"]:
        print(f"  [REJECTED] {r['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
