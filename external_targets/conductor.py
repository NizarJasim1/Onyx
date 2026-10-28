#!/usr/bin/env python3
"""
conductor.py — Phase 1 of the six-phase roadmap: THE CONDUCTOR (ties the whole thread).

One command turns a capture into ONE dissection report for the analyst:

    HAR (+OpenAPI) ─▶ dossier (L1 objects/relations + L2 invariants → ranked hypotheses)
                   ─▶ breaker      (L3: relation/chain BOLA, state-gate — proven path)
                   ─▶ alt_paths    (L4: learn-from-refusal alternates — proven path)
                   ─▶ alt_paths_deep (L4-X: id-linkage + authz-key + refusal-pivot chains)
                   ─▶ MERGE + DEDUPE + RANK
                   ─▶ analyst dissection packet  (Markdown for reading + JSON for automation)

THE VISION THIS SERVES (unchanged from day one):
    ONYX dissects deeply and emits a high-signal ANATOMY → the analyst reasons like a researcher
    and names the flaw → ONYX proves it with Δstate. The Conductor is the spine that carries
    the anatomy to the analyst in one packet, with the already-Δstate-CONFIRMED findings separated
    from the HYPOTHESES the analyst must still judge.

ARCHITECTURAL WALL (why the spine adds zero false positives):
  * The Conductor ORCHESTRATES; it never accepts a finding. Every "confirmed" entry it prints
    was accepted by the proven path inside a layer (serve._build_scan → gate → reconfirm/IARC,
    + payment_guard for money). The Conductor only MERGES and DEDUPES those, and forwards the
    dossier's HYPOTHESES verbatim for the analyst — it never promotes a hypothesis to a finding.
  * Determinism: dedupe key is stable; a finding proven by two layers collapses to one, so the
    report is idempotent across re-runs.
  * Engine untouched. Isolated in external_targets/.
"""
from __future__ import annotations
import json, argparse, sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dossier as DOS
import breaker as L3
import alt_paths as L4
import alt_paths_deep as L4X
import onyx_recon as OR


def run_base_recon(base_url, principals, har=None, openapi=None, scope=None, researcher=""):
    """The FOUNDATIONAL direct-BOLA/BFLA detector: ingest → harvest owner-scoped ids →
    build cross-principal plan → engine Δstate → structural gate → IARC. This is the plain
    IDOR path (no refusal/relation/leak required), extracted from onyx_recon.main so the
    Conductor confirms the bread-and-butter cross-owner reads a rich crawl surfaces. Reuses
    onyx_recon's OWN proven functions — zero new accept logic."""
    from authpath.serve import _build_scan
    import capture_normalize as CN
    host = OR.urlparse(base_url).hostname
    cli = OR.Client(scope or [host], researcher=researcher)
    # Surface from EVIDENCE-BASED templatization: numeric AND capture-proven non-numeric item
    # ids collapse to {id}, so item families (e.g. /api/recs/{id}, /api/invoices/{id}) are
    # probeable instead of mis-read as collections. A pure surface-map upgrade — the engine +
    # IARC + ownership gate still decide every verdict, so it cannot add a false positive.
    if openapi:
        surface = OR.ingest_openapi(openapi)
    elif har:
        surface = CN.normalized_surface(har)
    else:
        surface = []
    if not surface:
        return []
    owned, pool, hreport = OR.harvest(cli, base_url, surface, principals)
    plan_eps = OR.build_plan(surface, owned, pool, principals, confirm=False)
    if not plan_eps:
        return []
    owner_scoped = set(hreport["owner_scoped"])
    seeds = [(pid, "GET", e["path"]) for e in surface
             if e["method"] == "GET" and e["path"] in owner_scoped for pid in principals]
    cfg = {"base_url": base_url, "authorized": True, "dry_run": True, "researcher": researcher,
           "program": "authorized engagement",
           "principals": {p: {"value": t, "type": "bearer"} for p, t in principals.items()},
           "endpoints": plan_eps, "seeds": seeds,
           "test_resources": sorted({str(i) for e in plan_eps for v in e["ids"].values() for i in v}),
           "engagement_id": "conductor-base"}
    engine, _ = _build_scan(cfg)
    snap = engine.snapshot()
    grounded = {str(i) for v in pool.values() for i in v} | \
               {str(i) for e in plan_eps for v in e.get("ids", {}).values() for i in v}
    gate = [fd for fd in snap["findings"]
            if OR._is_probeable(str(fd.get("endpoint", ""))) and OR._looks_like_id(fd.get("target", ""))
            and str(fd.get("target", "")) in grounded]
    ep_meta = OR._ep_meta(plan_eps)
    return [fd for fd in gate if OR.reconfirm(cli, base_url, principals, pool, fd, ep_meta)[0]]


# --------------------------------------------------------------------------- #
# normalize a confirmed finding (recon snapshot dict) to a stable record       #
# --------------------------------------------------------------------------- #
def _norm(f, layer):
    ep = str(f.get("endpoint", ""))
    method, path = (ep.split(" ", 1) + [""])[:2] if " " in ep else ("GET", ep)
    return {
        "fid": f.get("fid"),
        "effect": str(f.get("effect", "")),
        "method": method, "path": path, "endpoint": ep,
        "actor": str(f.get("actor", "")), "target": str(f.get("target", "")),
        "impact": str(f.get("impact", f.get("impact_class", ""))),
        "severity": f.get("severity") or f.get("cvss_label") or "",
        "found_by": [layer], "vectors": [ep] if ep else [],
    }


def _id_seg_count(endpoint):
    """How many id-shaped segments a door path carries. A MALFORMED probe path (e.g. a layer
    that could not templatize a non-numeric id and appended a second slot →
    /api/billing/invoice/inv-A-11/inv-B-22) shows >1 and is a worse PoC than the clean
    single-slot door for the SAME vulnerability. Used only to pick the cleanest vector to
    DISPLAY — it never changes accept/reject (the engine already accepted)."""
    import sitemodel as SM
    path = endpoint.split(" ", 1)[-1]
    return sum(1 for s in path.split("/") if s and (s == "{id}" or SM._is_id_value(s)))


def _dedupe_key(r):
    """The SEMANTIC identity of a confirmed read/write: a given actor reaching a given target
    object with a given effect. Different doors that all prove the SAME (actor→target) are the
    SAME vulnerability with multiple PoC vectors — collapsing them yields one clean record
    instead of the same bug repeated once per layer/door (and once more when a layer emitted a
    malformed door string). Cross-layer fids differ (separate engine runs), so we key on the
    semantic tuple, not fid."""
    return (r["effect"], r["actor"], r["target"])


def merge_confirmed(layer_results):
    """layer_results: list of (layer_name, [finding_dicts]) -> deduped, ranked records. One
    record per semantic vulnerability; all proving doors kept as `vectors`; the cleanest door
    shown as the primary endpoint."""
    by_key = {}
    for layer, findings in layer_results:
        for f in findings:
            r = _norm(f, layer)
            k = _dedupe_key(r)
            if k in by_key:
                cur = by_key[k]
                if layer not in cur["found_by"]:
                    cur["found_by"].append(layer)
                for v in r["vectors"]:
                    if v not in cur["vectors"]:
                        cur["vectors"].append(v)
            else:
                by_key[k] = r
    records = list(by_key.values())
    # promote the cleanest vector to the primary endpoint (fewest id segments, then shortest)
    for r in records:
        best = min(r["vectors"], key=lambda e: (_id_seg_count(e), len(e))) if r["vectors"] else r["endpoint"]
        r["endpoint"] = best
        m, p = (best.split(" ", 1) + [""])[:2] if " " in best else ("GET", best)
        r["method"], r["path"] = m, p
    _SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}
    _EFF = {"PAYMENT": 5, "OWNERSHIP": 5, "AUTHORITY": 4, "OBJECT_ACCESS": 3, "PRICE": 4}
    records.sort(key=lambda r: (-_SEV.get(str(r["severity"]).lower(), 0),
                                -_EFF.get(r["effect"].upper(), 0),
                                -len(r["found_by"]), r["path"], r["target"]))
    return records


# --------------------------------------------------------------------------- #
# run every layer over ONE capture, collect confirmed findings + hypotheses    #
# --------------------------------------------------------------------------- #
def run(base_url, principals, har=None, openapi=None, token_map=None, scope=None,
        researcher="", confirm=False, insecure=False, delay=(0.0, 0.0)):
    token_map = token_map or {t: p for p, t in principals.items()}
    t0 = time.time()

    # 1) dossier — the anatomy + ranked hypotheses for the analyst (never auto-accepted)
    dos = DOS.build(har=har, openapi=openapi, token_map=token_map)

    layer_results, errors = [], {}
    # 2a) L-base — foundational direct BOLA/BFLA (plain IDOR, no refusal/relation needed)
    try:
        layer_results.append(("L-base-recon",
                              run_base_recon(base_url, principals, har=har, openapi=openapi,
                                             scope=scope, researcher=researcher)))
    except Exception as e:
        errors["L-base-recon"] = repr(e)
    # 2) L3 breaker — relation/chain BOLA (+ state-gate under --confirm)
    try:
        r3 = L3.run(base_url, principals, har=har, openapi=openapi, token_map=token_map,
                    scope=scope, confirm=confirm, researcher=researcher,
                    insecure=insecure, delay=delay)
        layer_results.append(("L3-breaker", r3.get("confirmed", [])))
    except Exception as e:
        errors["L3-breaker"] = repr(e)
    # 3) L4 base alt_paths — learn-from-refusal alternates
    try:
        r4 = L4.run(base_url, principals, har=har, openapi=openapi, token_map=token_map,
                    scope=scope, researcher=researcher, insecure=insecure, delay=delay)
        layer_results.append(("L4-altpaths", r4.get("confirmed", [])))
    except Exception as e:
        errors["L4-altpaths"] = repr(e)
    # 4) L4-X deep — id-linkage + authz-key + refusal-pivot chains
    authz_keys = {}
    try:
        rx = L4X.run_deep(base_url, principals, har=har, openapi=openapi, token_map=token_map,
                          scope=scope, researcher=researcher, insecure=insecure, delay=delay)
        layer_results.append(("L4X-deep", rx.get("confirmed", [])))
        authz_keys = rx.get("authz_keys", {})
    except Exception as e:
        errors["L4X-deep"] = repr(e)

    confirmed = merge_confirmed(layer_results)

    # GLOBAL OWNERSHIP-CONSISTENCY GATE (the spine's zero-FP reconciliation) ------------
    # A leak/over-sharing feed can mis-attribute an id in a sub-layer's harvest (it assigns
    # a leaked id to the single principal who SAW it, not its true owner), which can make a
    # principal reading its OWN object look "cross-owner". We recompute AUTHORITATIVE
    # ownership from self-reads (a 2xx whose request PATH contained the id — unforgeable
    # provenance) and DROP any cross-principal finding whose actor IS the target's established
    # owner. This only removes (never adds) findings, so it cannot introduce a false positive;
    # self-abuse effects (PAYMENT/PRICE/COUPON, where acting on your OWN object is the bug)
    # are exempt.
    dropped_self = 0
    if har:
        _, _, ownership, _ = L4X.object_identity(L4X.normalize(har, token_map))
        _CROSS = {"OBJECT_ACCESS", "OWNERSHIP", "AUTHORITY"}
        kept = []
        for r in confirmed:
            owner = ownership.get(r["target"])
            if r["effect"].upper() in _CROSS and owner is not None and owner == r["actor"]:
                dropped_self += 1
                continue
            kept.append(r)
        confirmed = kept

    return {
        "target": base_url,
        "confirmed": confirmed,
        "hypotheses": dos["hypotheses"],
        "anatomy": {"layer1": dos["layer1"], "layer2": dos["layer2"], "roles": dos["roles"]},
        "authz_keys": authz_keys,
        "coverage": {
            "objects": dos["counts"].get("l1_objects", 0),
            "cross_ownership": dos["counts"].get("l1_cross_ownership", 0),
            "chains": dos["counts"].get("l1_chains", 0),
            "decision_points": dos["counts"].get("l1_decision_points", 0),
            "invariants": dos["counts"].get("l2_invariants", 0),
            "hypotheses": dos["counts"].get("hypotheses", 0),
            "confirmed": len(confirmed),
            "dropped_self_read": dropped_self,
            "layers_run": [l for l, _ in layer_results],
            "errors": errors,
        },
        "elapsed_sec": round(time.time() - t0, 2),
    }


# --------------------------------------------------------------------------- #
# render analyst dissection packet                                          #
# --------------------------------------------------------------------------- #
def render_markdown(packet):
    c = packet["coverage"]
    L = [f"# ONYX dissection — anatomy for the analyst\n",
         f"**Target:** `{packet['target']}`  ·  scan {packet['elapsed_sec']}s\n",
         f"**Coverage:** objects={c['objects']} · cross-ownership={c['cross_ownership']} · "
         f"chains={c['chains']} · decision-points={c['decision_points']} · "
         f"invariants={c['invariants']} · hypotheses={c['hypotheses']} · "
         f"**CONFIRMED={c['confirmed']}**\n",
         f"_Layers run: {', '.join(c['layers_run']) or 'none'}_"
         + (f"  ·  errors: {c['errors']}" if c["errors"] else "") + "\n"]

    # 1) CONFIRMED — proven by Δstate, zero-FP. The analyst just writes these up.
    L.append("## ✅ Confirmed vulnerabilities (Δstate-proven, zero false positive)")
    if packet["confirmed"]:
        L.append("_Each was accepted by the proven path (engine + IARC/payment-gate). Ready to report._\n")
        for i, r in enumerate(packet["confirmed"], 1):
            L.append(f"**{i}. {r['effect']}** — `{r['endpoint']}`  "
                     f"({'+'.join(r['found_by'])})")
            L.append(f"   - actor `{r['actor']}` accessed target `{r['target']}`"
                     + (f"  ·  impact: {r['impact']}" if r['impact'] else "")
                     + (f"  ·  severity: {r['severity']}" if r['severity'] else ""))
            if len(r["vectors"]) > 1:
                L.append(f"   - alternate proof vectors: "
                         + ", ".join(f"`{v}`" for v in r["vectors"] if v != r["endpoint"]))
    else:
        L.append("_None auto-confirmed on this capture. Work the hypotheses below._")
    L.append("")

    # 2) authz keys the differential learned (high-signal intel for the analyst)
    if packet["authz_keys"]:
        L.append("## 🔑 Authorization keys learned (allowed-vs-denied differential)")
        for door, k in packet["authz_keys"].items():
            L.append(f"- `{door}` unlocks with **{k}** — probe alternates that ignore this key.")
        L.append("")

    # 3) HYPOTHESES — the analyst's reasoning surface. NEVER auto-confirmed.
    L.append("## 🎯 Ranked hypotheses — your call (ONYX will prove the ones you pick)")
    L.append("_These are not findings. Judge them like a researcher; each names the probe ONYX runs to prove/refute with Δstate._\n")
    for h in packet["hypotheses"][:25]:
        L.append(f"### [{h['signal']}] {h['hypothesis']}  ·  _{h['owasp']}_")
        L.append(f"- rests on: {h['rests_on']}")
        L.append(f"- probe: {h['suggested_probe']}\n")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX Conductor — one capture → one analyst dissection packet (orchestration only; zero new accept logic).")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--har"); ap.add_argument("--openapi")
    ap.add_argument("--scope"); ap.add_argument("--tokens")
    ap.add_argument("--principal", action="append", default=[], help="PID:TOKEN")
    ap.add_argument("--confirm", action="store_true", help="allow mutating state-gate probes (self, dry-run off)")
    ap.add_argument("--researcher", default="")
    ap.add_argument("--out", help="write the JSON packet here; Markdown goes to <out>.md")
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
    packet = run(args.base_url, principals, har=har, openapi=spec, token_map=token_map,
                 scope=scope, researcher=args.researcher, confirm=args.confirm)
    md = render_markdown(packet)
    print(md)
    if args.out:
        json.dump(packet, open(args.out, "w"), indent=2, default=list)
        open(args.out + ".md", "w", encoding="utf-8").write(md)
        print(f"\n[packet JSON → {args.out}  ·  Markdown → {args.out}.md]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
