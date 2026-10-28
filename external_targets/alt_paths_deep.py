#!/usr/bin/env python3
"""
alt_paths_deep.py — LAYER 4-X: the qualitative deepening of Layer 4.

Base Layer 4 (alt_paths.py) learns a refused door and looks for an alternate door to the
SAME OBJECT TYPE, matched by path-tail name. That is a heuristic. This module replaces the
heuristic with an AUTHORIZATION THEORY of the target, built from the capture, in three
integrated, genius-grade upgrades — every one of which still confirms ONLY through the
already-measured proven path (serve._build_scan -> onyx_recon gate -> reconfirm/IARC). Zero
new accept logic ⇒ structurally zero-false-positive, exactly like Layers 3 and 4.

  (1) OBJECT IDENTITY BY ID-LINKAGE  [the backbone]
      Two doors address the same object because a CONCRETE id flowed through BOTH — proven
      by shared id, not guessed by path name. This makes cross-surface real: a door named
      /billing/x and a door named /admin/y that both carry id "inv-77" are the same object
      family even though their names never rhyme.

  (2) AUTHZ-KEY DIFFERENTIAL  [the discriminator brain]
      "العائق هو التمييز لا التوليد." For any door the capture shows BOTH allowed (2xx) and
      denied (403/401) on, compute the MINIMAL request-feature delta between an allowed and a
      denied exchange. That delta is the exact signal the server keys its authorization on.
      A door whose access does NOT depend on that key is a principled bypass; the key also
      tells the pivot which edge to walk. Plan-only — the engine still proves via Δstate.

  (3) REFUSAL-PIVOT CHAINS  [multi-hop — where real bounty bugs live]
      A refused door guards an object whose id the attacker does not own and cannot list.
      But an ALLOWED door LEAKS that id (an over-sharing feed / activity / search result).
      Layer 4-X reads the leak, recovers the cross-owner id AND its true owner (established
      from an allowed self-read), and feeds it to an alternate door. Base Layer 4 MISSES this
      entirely (the id is in no owner-scoped collection). The engine confirms each hop.

Honesty guarantees preserved:
  * No invented ids — every probed id was disclosed by the server in the capture.
  * Cross-owner claims require an ESTABLISHED distinct owner (an allowed self-read); an id
    whose owner cannot be established is skipped, never assumed.
  * A refusal is learned ONLY from 401/403 (an authz rule), never a 404/400/405.
  * Every accept/reject decision is the engine's + IARC's. This module cannot emit a finding.
"""
from __future__ import annotations
import json, argparse, sys, os
from urllib.parse import urlparse, parse_qs
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onyx_recon as OR
import sitemodel as SM
import alt_paths as L4          # base Layer 4 primitives (reused, not modified)


# =========================================================================== #
# capture normalization: one record per HAR exchange, concrete + templatized   #
# =========================================================================== #
def _header_get(headers, name):
    for h in (headers or []):
        if (h.get("name") or "").lower() == name.lower():
            return h.get("value")
    return None


def _body_obj(raw):
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except ValueError:
            return None
    return None


def normalize(har, token_map):
    """HAR -> list of exchange records with everything the analyses need."""
    out = []
    for e in ((har or {}).get("log") or {}).get("entries") or []:
        req = e.get("request") or {}; resp = e.get("response") or {}
        url = req.get("url", ""); path = urlparse(url).path
        method = (req.get("method") or "GET").upper()
        status = resp.get("status", 0)
        principal = SM._principal_of(req.get("headers"), token_map)
        rbody = _body_obj((resp.get("content") or {}).get("text"))
        qbody = _body_obj((req.get("postData") or {}).get("text")) if req.get("postData") else None
        out.append({
            "method": method, "path": path, "tmpl": SM.templatize_path(path),
            "status": status, "principal": principal,
            "url": url, "query": parse_qs(urlparse(url).query),
            "req_headers": req.get("headers") or [], "req_body": qbody,
            "resp_body": rbody, "key": f"{method} {SM.templatize_path(path)}",
        })
    return out


def _ids_in(obj, acc):
    """Collect concrete id-shaped scalars anywhere in a JSON value."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _ids_in(v, acc)
            elif SM._is_id_value(v):
                acc.add(str(v))
    elif isinstance(obj, list):
        for v in obj:
            _ids_in(v, acc)
    return acc


def _path_ids(path):
    return {seg for seg in path.split("/") if seg and SM._is_id_value(seg)}


# =========================================================================== #
# (1) OBJECT IDENTITY BY ID-LINKAGE                                            #
# =========================================================================== #
def object_identity(records):
    """Return:
      id_doors     : concrete id -> set of door keys (templatized) that carried it anywhere.
      id_path_doors: concrete id -> set of (method, CONCRETE path) where the id was in the
                     request PATH — i.e. a probeable {id} slot. The probe template is built
                     by replacing THAT id with {id}, never via templatize_path (which does
                     not recognize non-numeric ids like 'inv-B-222').
      ownership    : concrete id -> principal, established ONLY from an allowed SELF-READ
                     (2xx whose REQUEST PATH contained the id), unique across principals.
      leaks        : list of (principal, id, door_key) where the principal SAW an id in a
                     response WITHOUT it being in their request path (a disclosure).
    """
    id_doors = {}
    id_path_doors = {}
    self_readers = {}     # id -> set(principals who self-read it 2xx)
    saw_in_resp = []      # (principal, id, key, had_in_path)
    for r in records:
        pth_ids = _path_ids(r["path"])
        body_ids = _ids_in(r["req_body"] or {}, set())
        resp_ids = _ids_in(r["resp_body"] or {}, set()) if 200 <= r["status"] < 300 else set()
        for i in (pth_ids | body_ids | resp_ids):
            id_doors.setdefault(i, set()).add(r["key"])
        for i in pth_ids:
            id_path_doors.setdefault(i, set()).add((r["method"], r["path"]))
        if 200 <= r["status"] < 300:
            for i in pth_ids:                       # self-read: caller addressed the id
                self_readers.setdefault(i, set()).add(r["principal"])
            for i in resp_ids:
                saw_in_resp.append((r["principal"], i, r["key"], i in pth_ids))
    ownership = {i: next(iter(ps)) for i, ps in self_readers.items() if len(ps) == 1}
    leaks = [(p, i, k) for (p, i, k, had) in saw_in_resp
             if not had and ownership.get(i) not in (None, p)]
    return id_doors, id_path_doors, ownership, leaks


def _slot_for_id(concrete_path, oid):
    """Probe template: replace the concrete id with {id} in its own path segment. This is
    correct even for ids templatize_path does not recognize (e.g. 'inv-B-222')."""
    segs = concrete_path.split("/")
    return "/".join("{id}" if s == str(oid) else s for s in segs)


def same_object_alternates(records, refused, id_path_doors):
    """Cross-surface alternates proven by SHARED ID in the PATH (not path-tail names). For
    each refused door, any OTHER door whose path carried an id the refused door's path also
    carried is a same-object alternate — regardless of naming or surface. The probe template
    is rebuilt from the concrete path, so non-numeric ids slot correctly."""
    refused_ids = {}                      # refused door -> ids seen in ITS path
    for r in records:
        if r["key"] in refused:
            refused_ids.setdefault(r["key"], set()).update(_path_ids(r["path"]))
    plans = []
    seen = set()
    for rkey, rids in refused_ids.items():
        rmethod, rpath = rkey.split(" ", 1)
        for i in rids:
            for (amethod, aconcrete) in id_path_doors.get(i, ()):
                slot = _slot_for_id(aconcrete, i)
                if (amethod, slot) == (rmethod, rpath) or (amethod, slot) in seen:
                    continue
                seen.add((amethod, slot))
                plans.append({
                    "alt_method": amethod, "alt_path": slot,
                    "alt_op": L4._op_class(amethod), "linked_by_id": i,
                    "routes_around": {"method": rmethod, "path": rpath},
                    "reason": f"same object proven by shared id {i!r} "
                              f"({L4._surface_of(rpath)}→{L4._surface_of(slot)})",
                })
    return plans


# =========================================================================== #
# (2) AUTHZ-KEY DIFFERENTIAL                                                   #
# =========================================================================== #
def _req_features(r):
    """Comparable request features that could carry an authorization decision, EXCLUDING
    the object id itself (which is the target, not the key) and the auth token (identity is
    the baseline axis)."""
    feats = {}
    for h in r["req_headers"]:
        n = (h.get("name") or "").lower()
        if n in ("authorization", "cookie", "content-length", "host", "user-agent", "content-type"):
            continue
        feats[f"header:{n}"] = h.get("value")
    for k, v in (r["query"] or {}).items():
        feats[f"query:{k.lower()}"] = ",".join(v)
    if isinstance(r["req_body"], dict):
        for k, v in r["req_body"].items():
            if not isinstance(v, (dict, list)):
                feats[f"body:{k.lower()}"] = str(v)
    return feats


def authz_key_differential(records):
    """Per door with BOTH 2xx and 403/401 exchanges, the authorization key is a request
    feature whose value is CONSISTENT across ALL allowed samples and CONSISTENTLY ABSENT or
    DIFFERENT across ALL denied samples. Requiring consistency across multiple samples is
    what separates a real key from per-request NOISE (a request-id, a timestamp, a nonce),
    which varies within the allowed set and is therefore rejected. Returns
    door_key -> {feature: unlocking_value}.

    A door observed with only ONE allowed or ONE denied sample cannot be discriminated from
    noise, so it yields NO key (honest abstention over a guessed key)."""
    by_door = {}
    for r in records:
        g = by_door.setdefault(r["key"], {"ok": [], "deny": []})
        if 200 <= r["status"] < 300:
            g["ok"].append(_req_features(r))
        elif r["status"] in (401, 403):
            g["deny"].append(_req_features(r))

    def _consistent(samples, feat):
        """the single value `feat` takes across all samples, or None if it varies/absent."""
        vals = {s.get(feat) for s in samples}
        return next(iter(vals)) if len(vals) == 1 else None

    keys = {}
    for door, g in by_door.items():
        # need >=2 allowed AND >=1 denied to tell a stable key from noise; and to reject a
        # feature that merely varies, we demand the allowed set AGREE on the value.
        if len(g["ok"]) < 2 or len(g["deny"]) < 1:
            continue
        feats = set().union(*[set(s) for s in g["ok"]])
        found = {}
        for f in feats:
            ok_val = _consistent(g["ok"], f)          # all allowed agree on this value
            if ok_val is None:
                continue                              # varies within allowed => noise
            deny_vals = {s.get(f) for s in g["deny"]}
            if ok_val in deny_vals:
                continue                              # a denied request also had it => not the key
            found[f] = ok_val
        if found:
            keys[door] = found
    return keys


# =========================================================================== #
# (3) REFUSAL-PIVOT CHAINS                                                     #
# =========================================================================== #
def pivot_chains(records, refused, ownership, leaks, id_path_doors):
    """Assemble leak→access chains. For a leaked cross-owner id X (owner=P, leaked to Q):
      find every PATH door that addresses X by id — that door, probed with X tagged to its
      true owner P, is a cross-owner access. Base Layer 4 cannot reach X because X is in no
      owner-scoped collection. The probe template is rebuilt from the concrete path."""
    chains = []
    seen = set()
    for (q, x, leak_key) in leaks:
        owner = ownership.get(x)
        if not owner or owner == q:
            continue
        for (method, concrete) in id_path_doors.get(x, ()):
            if method != "GET":            # confirmable cross-owner READ (writes are engine-governed elsewhere)
                continue
            slot = _slot_for_id(concrete, x)
            if (owner, method, slot) in seen:
                continue
            seen.add((owner, method, slot))
            chains.append({
                "alt_method": "GET", "alt_path": slot,
                "target_id": x, "true_owner": owner, "leaked_to": q,
                "leak_via": leak_key,
                "reason": f"pivot: {leak_key} leaked {x!r} (owner {owner}) to {q}; "
                          f"read it via GET {slot}",
            })
    return chains


# =========================================================================== #
# translate deep plans -> ONYX endpoint specs (ids only real/observed)         #
# =========================================================================== #
def deep_endpoints(alt_plans, pivots, pool, principals):
    pids = [p for p in principals if pool.get(p)]
    eps, notes = [], []
    seen = set()
    # (1)+(2): id-linked cross-surface alternate reads — cross-principal over owned pool
    for pl in alt_plans:
        if pl["alt_op"] != L4._READ or len(pids) < 2:
            continue
        path = L4._slot(pl["alt_path"])
        if ("GET", path) in seen:
            continue
        seen.add(("GET", path))
        eps.append({"method": "GET", "path": path, "effect": "object-access",
                    "ids": {p: pool[p][:4] for p in pids}})
        notes.append(("id-linked-alt", f"GET {path} — {pl['reason']}"))
    # (3): pivot reads — the leaked cross-owner id tagged to its true owner
    for pv in pivots:
        path = pv["alt_path"]
        owner = pv["true_owner"]
        if owner not in principals:
            continue
        key = ("GET", path, pv["target_id"])
        if key in seen:
            continue
        seen.add(key)
        # merge the pivot id into this endpoint's owner id-set (kept minimal)
        existing = next((e for e in eps if e["path"] == path and e["method"] == "GET"), None)
        if existing:
            existing["ids"].setdefault(owner, [])
            if pv["target_id"] not in existing["ids"][owner]:
                existing["ids"][owner].append(pv["target_id"])
        else:
            eps.append({"method": "GET", "path": path, "effect": "object-access",
                        "ids": {owner: [pv["target_id"]]}})
        notes.append(("pivot", pv["reason"]))
    return eps, notes


def confirm_via_proven_path(cli, base_url, principals, pool, plan_eps, seeds):
    from authpath.serve import _build_scan
    cfg = {"base_url": base_url, "authorized": True, "dry_run": True, "researcher": "alt_paths_deep",
           "program": "authorized engagement",
           "principals": {p: {"value": t, "type": "bearer"} for p, t in principals.items()},
           "endpoints": plan_eps, "seeds": seeds,
           "test_resources": sorted({str(i) for e in plan_eps for v in e.get("ids", {}).values() for i in v}),
           "engagement_id": "alt_paths_deep"}
    engine, _ = _build_scan(cfg)
    snap = engine.snapshot()
    grounded = {str(x) for v in pool.values() for x in v} | \
               {str(i) for e in plan_eps for v in e.get("ids", {}).values() for i in v}
    gate_kept = [f for f in snap["findings"]
                 if OR._is_probeable(str(f.get("endpoint", ""))) and OR._looks_like_id(f.get("target", ""))
                 and str(f.get("target", "")) in grounded]
    ep_meta = OR._ep_meta(plan_eps)
    kept = [f for f in gate_kept
            if OR.reconfirm(cli, base_url, principals, pool, f, ep_meta)[0]]
    return kept, len(snap["findings"])


def run_deep(base_url, principals, har=None, openapi=None, token_map=None, scope=None,
             researcher="", insecure=False, delay=(0.0, 0.0)):
    scope = scope or [urlparse(base_url).hostname]
    cli = OR.Client(scope, researcher=researcher, verify=not insecure, delay=delay)
    model = SM.from_sources(har=har, openapi=openapi, token_map=token_map)
    records = normalize(har, token_map)
    refused = L4.refusal_map(model, har=har, token_map=token_map)     # 401/403 only
    id_doors, id_path_doors, ownership, leaks = object_identity(records)
    diff = authz_key_differential(records)
    alt_plans = same_object_alternates(records, refused, id_path_doors)
    pivots = pivot_chains(records, refused, ownership, leaks, id_path_doors)

    # harvest owned ids over all doors the deep plans touch (proven harvester)
    paths = {L4._slot(p["alt_path"]).split("/{id}")[0] for p in alt_plans} | \
            {pv["alt_path"].split("/{id}")[0] for pv in pivots}
    surface = [{"method": "GET", "path": p.rstrip("/"), "params": [], "other_params": [],
                "query_id": None, "body": {}, "multi_param": False} for p in paths]
    owned, pool, _hrep = OR.harvest(cli, base_url, surface, principals) if surface else ({}, {}, {})
    seeds = [(pid, "GET", e["path"]) for e in surface for pid in principals]

    eps, notes = deep_endpoints(alt_plans, pivots, pool, principals)
    if not eps:
        return {"confirmed": [], "raw": 0, "refusals": len(refused),
                "id_links": len(alt_plans), "pivots": len(pivots),
                "authz_keys": diff, "notes": notes, "pool": pool}
    kept, raw = confirm_via_proven_path(cli, base_url, principals, pool, eps, seeds)
    return {"confirmed": kept, "raw": raw, "refusals": len(refused),
            "id_links": len(alt_plans), "pivots": len(pivots),
            "authz_keys": diff, "notes": notes, "pool": pool}


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="ONYX Layer 4-X: id-linkage identity + authz-key differential + refusal-pivot chains (confirms via proven path).")
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
    res = run_deep(args.base_url, principals, har=har, openapi=spec, token_map=token_map,
                   scope=scope, researcher=args.researcher)
    print(f"refusals={res['refusals']}  id-linked-alternates={res['id_links']}  "
          f"pivot-chains={res['pivots']}  authz-keys={len(res['authz_keys'])}  "
          f"raw={res['raw']}  CONFIRMED={len(res['confirmed'])}")
    for door, k in res["authz_keys"].items():
        print(f"  [authz-key] {door}: unlock with {k}")
    for tag, note in res["notes"]:
        print(f"  [plan:{tag}] {note}")
    for f in res["confirmed"]:
        print(f"  [CONFIRMED] {f.get('actor')} -> {f.get('target')}  {f.get('endpoint')}")
    if args.out:
        json.dump(res, open(args.out, "w"), indent=2, default=list)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
