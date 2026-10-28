#!/usr/bin/env python3
"""
breaker.py — LAYER 3 of the ONYX deep-recon system: turn the dossier's HYPOTHESES into
ONYX probe plans and let the PROVEN decision path prove or refute each one.

THE ARCHITECTURAL WALL (why this stays zero-false-positive):
  * Layer 3 has NO authority to accept a finding. It only *translates* a hypothesis into
    the exact cfg shape ONYX already consumes, then hands it to the proven pipeline:
        serve._build_scan  →  onyx_recon's structural gate  →  onyx_recon.reconfirm (IARC)
    Every accept/reject decision is made by those three already-measured systems. This
    module adds ZERO new judgement, so it cannot introduce a false positive. If a
    hypothesis is not proven by Δstate through all three, it is dropped — exactly as any
    other candidate would be.
  * It never invents ids: it probes only ids ONYX harvested from owner-scoped collections,
    filtered by onyx_recon._looks_like_id / _is_probeable — the same input hygiene.
  * Mutating (state/business-logic) probes require --confirm and act only on the tester's
    own ids; dry-run is the default.

Scope of this build: translate the SAFE, already-proven hypothesis classes —
  * relation / chain BOLA  → cross-principal object-access probes,
  * state-gate skip        → the driving mutating op with the forbidden target state,
and confirm them through the proven path. Money-logic hypotheses (client-trusted / coupon)
are left for a later, separately-measured session.
"""
from __future__ import annotations
import json, argparse, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onyx_recon as OR          # the PROVEN decision path (gate + IARC live here)
import dossier as DOS
from authpath.serve import _build_scan, ScanError


def _slot_path(t):
    """Return an ONYX {id}-slot template for an object path. If the path already carries a
    template slot, keep it. If its LAST segment is a concrete id (numeric OR non-numeric like
    'inv-B-22', which templatize_path does not catch), REPLACE that segment with {id} — never
    append a second slot, which would mangle the path (…/inv-A-11/{id}) and scramble the
    engine's ownership accounting into self-read false positives. Only a collection path (no
    trailing id) gets a slot appended."""
    if "{id}" in t:
        return t
    import sitemodel as SM
    segs = t.rstrip("/").split("/")
    if segs and SM._is_id_value(segs[-1]):
        segs[-1] = "{id}"
        return "/".join(segs)
    return t.rstrip("/") + "/{id}"


def translate(dos, pool, principals, confirm):
    """Hypotheses -> ONYX endpoint specs. Ids come ONLY from ONYX's harvested owned pool."""
    eps, notes = [], []
    pids = [p for p in principals if pool.get(p)]

    # relation / chain BOLA -> cross-principal object-access on the referenced resource
    seen = set()
    for r in dos["layer1"].get("cross_ownership_relations", []):
        path = _slot_path(r["to_type"])
        if ("GET", path) in seen:
            continue
        seen.add(("GET", path))
        ids = {p: pool[p][:4] for p in pids}
        if len(ids) >= 2:
            eps.append({"method": "GET", "path": path, "effect": "object-access", "ids": ids})
            notes.append(("relation-BOLA", f"GET {path} (from {r['from_type']}.{r['field']} seam)"))
    for c in dos["layer1"].get("authority_inheritance_chains", []):
        # target the last hop's resource
        tail = c["hops"].split("->")[-1].split("(")[0].strip()
        if tail and tail.startswith("/"):
            path = _slot_path(tail)
            if ("GET", path) not in seen:
                seen.add(("GET", path))
                ids = {p: pool[p][:4] for p in pids}
                if len(ids) >= 2:
                    eps.append({"method": "GET", "path": path, "effect": "object-access", "ids": ids})
                    notes.append(("chain-BOLA", f"GET {path} (chain tail)"))

    # state-gate skip -> the driving mutating op with the forbidden target state (self, --confirm)
    if confirm:
        for i in dos["layer2"].get("invariants", []):
            if i.get("kind") != "state-machine":
                continue
            actor = pids[0] if pids else None
            if not actor:
                continue
            own = pool.get(actor, [])[:1]
            if not own:
                continue
            for op in (i.get("driven_by") or []):
                try:
                    method, pat = op.split(" ", 1)
                except ValueError:
                    continue
                for skip in (i.get("candidate_skips") or [])[:2]:
                    target = skip[1]
                    eps.append({"method": method.upper(), "path": pat, "effect": "state-gate",
                                "ids": {actor: own}, "body": json.dumps({i["field"]: target})})
                    notes.append(("state-gate", f"{method} {pat} -> {i['field']}={target}"))
    return eps, notes


def confirm_via_proven_path(cli, base_url, principals, pool, plan_eps, seeds):
    """Run the plan through ONYX's proven pipeline and return the findings it ACCEPTS.
    Every decision here is made by _build_scan / the gate / reconfirm — not by us."""
    cfg = {"base_url": base_url, "authorized": True, "dry_run": True, "researcher": "breaker",
           "program": "authorized engagement",
           "principals": {p: {"value": t, "type": "bearer"} for p, t in principals.items()},
           "endpoints": plan_eps, "seeds": seeds,
           "test_resources": sorted({i for e in plan_eps for v in e.get("ids", {}).values() for i in v}),
           "engagement_id": "breaker"}
    # honour --confirm only if any endpoint is mutating (dry-run otherwise)
    if any(e["method"] != "GET" for e in plan_eps):
        cfg["dry_run"] = False
    engine, _ = _build_scan(cfg)
    snap = engine.snapshot()
    grounded = {str(x) for v in pool.values() for x in v} | \
               {str(x) for e in plan_eps for v in e.get("ids", {}).values() for x in v}
    gate_kept = [f for f in snap["findings"]
                 if OR._is_probeable(str(f.get("endpoint", ""))) and OR._looks_like_id(f.get("target", ""))
                 and str(f.get("target", "")) in grounded]
    ep_meta = OR._ep_meta(plan_eps)
    kept = [f for f in gate_kept
            if OR.reconfirm(cli, base_url, principals, pool, f, ep_meta)[0]]
    return kept, len(snap["findings"])


def run(base_url, principals, har=None, openapi=None, token_map=None, scope=None, confirm=False,
        researcher="", insecure=False, delay=(0.0, 0.0)):
    scope = scope or [__import__("urllib.parse", fromlist=["urlparse"]).urlparse(base_url).hostname]
    cli = OR.Client(scope, researcher=researcher, verify=not insecure, delay=delay)
    # 1) dossier (Layers 1+2) from the capture — read-only, offline
    dos = DOS.build(har=har, openapi=openapi, token_map=token_map)
    # 2) harvest owned ids LIVE via ONYX's proven harvester (owner-scoped, hygiene-filtered)
    surface = []
    for key in dos["layer1"]["object_types"]:
        # object types are path patterns; recon needs endpoint dicts to harvest collections
        pass
    # derive collection endpoints to harvest: the referenced resources + their bases
    paths = set()
    for r in dos["layer1"].get("cross_ownership_relations", []):
        paths.add(r["to_type"]); paths.add(r["from_type"])
    surface = [{"method": "GET", "path": (p if "{id}" not in p else p.split("/{id}")[0]),
                "params": [], "other_params": [], "query_id": None, "body": {}, "multi_param": False}
               for p in {pp.rstrip("/") for pp in paths}]
    owned, pool, _hrep = OR.harvest(cli, base_url, surface, principals)
    seeds = [(pid, "GET", e["path"]) for e in surface for pid in principals]
    # 3) translate hypotheses -> plan, then CONFIRM via the proven path
    plan, notes = translate(dos, pool, principals, confirm)
    if not plan:
        return {"confirmed": [], "raw": 0, "notes": notes, "hypotheses": len(dos["hypotheses"])}
    kept, raw = confirm_via_proven_path(cli, base_url, principals, pool, plan, seeds)
    return {"confirmed": kept, "raw": raw, "notes": notes, "hypotheses": len(dos["hypotheses"]),
            "pool": pool}


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX Layer-3 invariant breaker (confirms via the proven path; zero new accept logic).")
    ap.add_argument("--authorized", action="store_true", required=False)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--har"); ap.add_argument("--openapi")
    ap.add_argument("--scope"); ap.add_argument("--tokens")
    ap.add_argument("--principal", action="append", default=[], help="PID:TOKEN")
    ap.add_argument("--confirm", action="store_true")
    ap.add_argument("--researcher", default="")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    if not args.authorized:
        sys.exit("Refusing to run: pass --authorized (you affirm scope + permission).")
    principals = {}
    for spec in args.principal:
        pid, tok = spec.split(":", 1); principals[pid.strip()] = tok.strip()
    if len(principals) < 2:
        sys.exit("need >=2 --principal PID:TOKEN")
    har = json.load(open(args.har)) if args.har else None
    spec = json.load(open(args.openapi)) if args.openapi else None
    token_map = json.loads(args.tokens) if args.tokens else {t: p for p, t in principals.items()}
    scope = [h.strip() for h in args.scope.split(",")] if args.scope else None
    res = run(args.base_url, principals, har=har, openapi=spec, token_map=token_map,
              scope=scope, confirm=args.confirm, researcher=args.researcher)
    print(f"hypotheses={res['hypotheses']}  raw-engine-candidates={res['raw']}  "
          f"CONFIRMED(after gate+IARC)={len(res['confirmed'])}")
    for f in res["confirmed"]:
        print(f"  [CONFIRMED] {f['effect']} {f['actor']} -> {f['target']}  {f['endpoint']}")
    if args.out:
        json.dump(res, open(args.out, "w"), indent=2, default=list)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
