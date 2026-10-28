#!/usr/bin/env python3
"""
alt_paths.py — LAYER 4 of the ONYX deep-recon system: LEARN FROM REFUSAL and LINK ACROSS
SURFACES. Every 403/401 the capture recorded is a *rule the server enforces on ONE door*.
Layer 4 asks the only question that turns a rule into a finding: **is there ANOTHER door to
the SAME object whose access the server did NOT refuse?** It emits those alternate doors as
ONYX probe plans and lets the PROVEN path decide.

THE ARCHITECTURAL WALL (identical to Layer 3 — this is why it stays zero-false-positive):
  * Layer 4 has NO authority to accept anything. It reads the capture (offline, read-only),
    proposes alternate-surface probe plans, and hands them to the already-measured pipeline:
        serve._build_scan  ->  onyx_recon structural gate  ->  onyx_recon.reconfirm (IARC)
    (+ payment_guard for money effects). Every accept/reject is made THERE. Zero new judgement
    here => it cannot manufacture a false positive. A refusal alone is NEVER a finding; only a
    Delta-state-proven alternate read/write is.
  * It invents no ids: a target id must be one ONYX harvested into the owner-scoped pool, and
    must pass onyx_recon._looks_like_id. A refusal on a door tells us the RULE exists; the
    alternate door is probed only with real, owned, harvested ids.

WHAT IT LEARNS (all measured from the capture, none assumed):
  1. REFUSAL MAP: for every (method, path-template) the capture shows a 4xx auth-refusal on,
     record the object TYPE that door guards and the OP class it denies (read / write / state).
  2. SAME-OBJECT ALTERNATE DOORS: for that guarded object type, find every OTHER door in the
     capture (different path, different method, different SURFACE) that reads or mutates the
     same object type — and was NOT uniformly refused. Each becomes an alternate-path plan.
  3. CROSS-SURFACE LINK: the same object id observed under two surfaces (REST path id, a query
     id, or a GraphQL node id) means a door closed on one surface may be open on another; emit
     the open surface as the alternate.

The output is a set of PLANS. Proof is the engine's job.
"""
from __future__ import annotations
import json, argparse, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onyx_recon as OR
import sitemodel as SM


# --------------------------------------------------------------------------- #
# op-class of a door: what kind of authority it exercises                      #
# --------------------------------------------------------------------------- #
_READ = "read"
_WRITE = "write"

def _op_class(method):
    return _READ if (method or "GET").upper() == "GET" else _WRITE


def _slot(path):
    """ONYX {id} slot: a path template already carrying an id placeholder, or with one
    appended. sitemodel templatizes numeric/uuid segments to {id} already."""
    return path if "{id}" in path else (path.rstrip("/") + "/{id}")


# --------------------------------------------------------------------------- #
# 1) refusal map: doors the server actively refused, and the object they guard #
# --------------------------------------------------------------------------- #
def refusal_map(model, har=None, token_map=None):
    """(method, path) -> {denied_owners, object_type, op_class}. A door counts as a
    'guarded refusal' ONLY on a 401/403 (an authorization RULE) — never a 404/400/405,
    which signal a missing resource or a shape error, not an authz decision.

    sitemodel.decisions buckets every 4xx together, so it cannot tell 403 from 404. We
    therefore recompute refusals from the RAW HAR statuses here (offline, read-only),
    reusing sitemodel's own path/principal normalizers so the keys line up with the model.
    Without a HAR (spec-only run) there is nothing to learn a refusal from."""
    from urllib.parse import urlparse
    refused = {}
    id_index = getattr(model, "_id_index", {})
    entries = ((har or {}).get("log") or {}).get("entries") or []
    for e in entries:
        req = e.get("request") or {}; resp = e.get("response") or {}
        status = resp.get("status", 0)
        if status not in (401, 403):          # ONLY authorization refusals
            continue
        method = (req.get("method") or "GET").upper()
        path = SM.templatize_path(urlparse(req.get("url", "")).path)
        owner = SM._principal_of(req.get("headers"), token_map)
        key = f"{method} {path}"
        rec = refused.setdefault(key, {
            "method": method, "path": path,
            "denied_owners": set(), "allowed_owners": set(),
            "object_type": _type_for_path(model, path, id_index),
            "op_class": _op_class(method)})
        rec["denied_owners"].add(owner)
    # fold in any 2xx owners the model recorded on the same door (context, not required)
    for key, rec in refused.items():
        dec = model.decisions.get(key, {})
        rec["allowed_owners"] |= set(dec.get("ok") or set())
    return refused


def _type_for_path(model, path, id_index):
    """Best-effort object type a path template addresses: a type name matching the path's
    last static segment, else the path template itself as the type key."""
    tail = [seg for seg in path.split("/") if seg and "{" not in seg]
    guess = tail[-1] if tail else path
    for otype in model.types:
        if isinstance(otype, str) and (otype == path or otype.endswith(guess) or guess in otype):
            return otype
    return path


# --------------------------------------------------------------------------- #
# 2+3) alternate doors to the same object, across paths and surfaces           #
# --------------------------------------------------------------------------- #
def alternate_doors(model, refused):
    """For each refused door, find OTHER doors (different key) that touch the same object
    type and were NOT uniformly refused for the same principal set. Returns a list of
    alternate plans, each tagged with the refusal it routes around."""
    plans = []
    seen_alt = set()
    doors = _door_index(model)
    for rkey, r in refused.items():
        otype = r["object_type"]
        denied = r["denied_owners"]
        for akey, a in doors.items():
            if akey == rkey:
                continue
            if a["object_type"] != otype:
                continue
            a_denied = a.get("denied_owners", set())
            # an alternate that ALSO refused every denied principal is no escape
            if denied and denied.issubset(a_denied):
                continue
            surface_shift = _surface_of(a["path"]) != _surface_of(r["path"])
            method_shift = a["method"] != r["method"]
            path_shift = a["path"] != r["path"]
            if not (surface_shift or method_shift or path_shift):
                continue
            dedup = (a["method"], a["path"])
            if dedup in seen_alt:
                continue
            seen_alt.add(dedup)
            plans.append({
                "alt_method": a["method"], "alt_path": a["path"],
                "alt_op": a["op_class"], "object_type": otype,
                "routes_around": {"method": r["method"], "path": r["path"],
                                  "denied_owners": sorted(denied)},
                "reason": _why(surface_shift, method_shift, path_shift),
            })
    return plans


def _door_index(model):
    """key -> {method, path, object_type, op_class, denied_owners}. Union of endpoints seen
    in the capture and the decision map."""
    id_index = getattr(model, "_id_index", {})
    out = {}
    keys = set(model.decisions) | set(getattr(model, "endpoints", {}))
    for key in keys:
        try:
            method, path = key.split(" ", 1)
        except ValueError:
            continue
        dec = model.decisions.get(key, {})
        out[key] = {
            "method": method, "path": path,
            "object_type": _type_for_path(model, path, id_index),
            "op_class": _op_class(method),
            "denied_owners": set(dec.get("denied") or set()),
            "allowed_owners": set(dec.get("ok") or set()),
        }
    return out


def _surface_of(path):
    """Classify the API surface a path belongs to, so a 'cross-surface' alternate is real."""
    p = (path or "").lower()
    if "graphql" in p:
        return "graphql"
    if "/ws" in p or "socket" in p:
        return "websocket"
    if "?" in p or "report_id" in p or "=" in p:
        return "query"
    return "rest"


def _why(surface, method, path):
    bits = []
    if surface: bits.append("different surface")
    if method: bits.append("different method")
    if path and not surface: bits.append("different path")
    return "same object via " + " + ".join(bits or ["alternate door"])


# --------------------------------------------------------------------------- #
# translate alternate plans -> ONYX endpoint specs (ids ONLY from the pool)    #
# --------------------------------------------------------------------------- #
def to_endpoints(plans, pool, principals):
    """Alternate doors -> ONYX endpoint specs, cross-principal for reads (BOLA) and
    self-scoped for writes. Ids come ONLY from ONYX's harvested owned pool."""
    pids = [p for p in principals if pool.get(p)]
    eps, notes = [], []
    seen = set()
    for pl in plans:
        method, path = pl["alt_method"], _slot(pl["alt_path"])
        if pl["alt_op"] == _READ:
            if len(pids) < 2:
                continue
            ids = {p: pool[p][:4] for p in pids}
            key = ("GET", path)
            if key in seen:
                continue
            seen.add(key)
            eps.append({"method": "GET", "path": path, "effect": "object-access", "ids": ids})
            notes.append(("alt-read", f"GET {path} — {pl['reason']}; "
                          f"routes around {pl['routes_around']['method']} {pl['routes_around']['path']}"))
        else:
            actor = pids[0] if pids else None
            if not actor or not pool.get(actor):
                continue
            key = (method, path)
            if key in seen:
                continue
            seen.add(key)
            eps.append({"method": method, "path": path, "effect": "object-access",
                        "ids": {actor: pool[actor][:1]}})
            notes.append(("alt-write", f"{method} {path} — {pl['reason']}; "
                          f"routes around {pl['routes_around']['method']} {pl['routes_around']['path']}"))
    return eps, notes


# --------------------------------------------------------------------------- #
# confirm via the PROVEN path (identical wall to breaker.py)                   #
# --------------------------------------------------------------------------- #
def confirm_via_proven_path(cli, base_url, principals, pool, plan_eps, seeds):
    from authpath.serve import _build_scan
    cfg = {"base_url": base_url, "authorized": True, "dry_run": True, "researcher": "alt_paths",
           "program": "authorized engagement",
           "principals": {p: {"value": t, "type": "bearer"} for p, t in principals.items()},
           "endpoints": plan_eps, "seeds": seeds,
           "test_resources": sorted({i for e in plan_eps for v in e.get("ids", {}).values() for i in v}),
           "engagement_id": "alt_paths"}
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
    return kept, len(snap["findings"]), engine


def run(base_url, principals, har=None, openapi=None, token_map=None, scope=None,
        researcher="", insecure=False, delay=(0.0, 0.0)):
    scope = scope or [__import__("urllib.parse", fromlist=["urlparse"]).urlparse(base_url).hostname]
    cli = OR.Client(scope, researcher=researcher, verify=not insecure, delay=delay)
    model = SM.from_sources(har=har, openapi=openapi, token_map=token_map)
    refused = refusal_map(model, har=har, token_map=token_map)
    plans = alternate_doors(model, refused)
    paths = {pl["alt_path"] for pl in plans}
    surface = [{"method": "GET", "path": (p if "{id}" not in p else p.split("/{id}")[0]),
                "params": [], "other_params": [], "query_id": None, "body": {}, "multi_param": False}
               for p in {pp.rstrip("/") for pp in paths}]
    owned, pool, _hrep = OR.harvest(cli, base_url, surface, principals) if surface else ({}, {}, {})
    seeds = [(pid, "GET", e["path"]) for e in surface for pid in principals]
    eps, notes = to_endpoints(plans, pool, principals)
    if not eps:
        return {"confirmed": [], "raw": 0, "refusals": len(refused),
                "alternates": len(plans), "notes": notes, "pool": pool}
    kept, raw, _eng = confirm_via_proven_path(cli, base_url, principals, pool, eps, seeds)
    return {"confirmed": kept, "raw": raw, "refusals": len(refused),
            "alternates": len(plans), "notes": notes, "pool": pool}


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="ONYX Layer-4: learn from refusal + cross-surface (confirms via the proven path; zero new accept logic).")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--har"); ap.add_argument("--openapi")
    ap.add_argument("--scope"); ap.add_argument("--tokens")
    ap.add_argument("--principal", action="append", default=[], help="PID:TOKEN")
    ap.add_argument("--researcher", default=""); ap.add_argument("--out")
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
              scope=scope, researcher=args.researcher)
    print(f"refusals-learned={res['refusals']}  alternate-doors={res['alternates']}  "
          f"raw-engine-candidates={res['raw']}  CONFIRMED(after gate+IARC)={len(res['confirmed'])}")
    for n in res["notes"]:
        print(f"  [plan:{n[0]}] {n[1]}")
    for f in res["confirmed"]:
        print(f"  [CONFIRMED] {f.get('effect')} {f.get('actor')} -> {f.get('target')}  {f.get('endpoint')}")
    if args.out:
        json.dump(res, open(args.out, "w"), indent=2, default=list)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
