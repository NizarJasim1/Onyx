#!/usr/bin/env python3
"""
onyx_deepmap.py — DEEP structural anatomy from a HAR, using EVERY ONYX analyzer
that is normally library-only (invoked inside the engines). Read-only, zero
network, zero accept logic: each analyzer runs in DESCRIBE mode (enabled=True but
probes are only planned, never issued), exactly as the engines call it.

Analyzers fused here (all shipped in authpath/):
  • surface_aggregator  — the true endpoint surface (observed ∪ spec ∪ derived) + shadow gaps
  • role_matrix         — per-principal role/permission matrix + missing-read plan
  • state_machine       — inferred object state machines + illegal-transition candidates
  • door_map            — sensitive "doors" (admin/internal) + exposure ledger
  • temporal            — credential lifecycle / revocation events (stale-auth drift)
  • mass_assign         — role-tied privileged fields (BOPLA surface)
  • contradiction_detector — the FUSION layer: cross-layer contradictions

Output: deepmap.json (full) + a human summary to stdout (captured as deepmap.md).
Nothing here confirms a finding; it enriches the anatomy the analyst reasons over.
"""
from __future__ import annotations
import argparse, json, os, sys, dataclasses

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)


def _brief(obj, _d=0):
    """Compact, safe summary of any result object (counts for lists, values for scalars)."""
    try:
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            obj = dataclasses.asdict(obj)
    except Exception:
        pass
    if isinstance(obj, dict):
        out = {}
        for k, v in list(obj.items())[:40]:
            out[str(k)] = _brief(v, _d + 1)
        return out
    if isinstance(obj, (list, tuple, set)):
        seq = list(obj)
        head = [_brief(x, _d + 1) for x in seq[:6]] if _d < 2 else f"<{len(seq)} items>"
        return {"count": len(seq), "head": head} if _d < 2 else f"<{len(seq)} items>"
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        s = obj if not isinstance(obj, str) else (obj[:160])
        return s
    d = getattr(obj, "__dict__", None)
    if d:
        return {k: _brief(v, _d + 1) for k, v in list(d.items())[:40] if not k.startswith("_")}
    return str(obj)[:160]


def _section(title, fn):
    try:
        val = fn()
        return {"section": title, "ok": True, "data": _brief(val)}
    except Exception as e:  # noqa: BLE001
        return {"section": title, "ok": False, "error": f"{type(e).__name__}: {e}"}


def main():
    ap = argparse.ArgumentParser(description="ONYX deep structural anatomy (read-only, zero-FP).")
    ap.add_argument("--har", required=True)
    ap.add_argument("--openapi")
    ap.add_argument("--scope", default="localhost")
    ap.add_argument("--out", default="deepmap.json")
    args = ap.parse_args()

    har = json.load(open(args.har))
    spec = json.load(open(args.openapi)) if args.openapi and os.path.exists(args.openapi) else None
    hosts = [h.strip() for h in args.scope.split(",") if h.strip()]

    from authpath import (role_matrix as RM, state_machine as SMX, door_map as DM,
                          surface_aggregator as SAG, contradiction_detector as CD)

    # parse exchanges once (shared by temporal / mass_assign)
    exchanges = []
    try:
        from authpath.harimport import parse_har_exchanges
        _p, exchanges = parse_har_exchanges(har, hosts)
    except Exception:
        exchanges = []

    surface_res = None; roles_res = None; states_res = None; doors_res = None

    def _surface():
        nonlocal surface_res
        surface_res = SAG.aggregate_from_har(har, in_scope_hosts=hosts, openapi_doc=spec, enabled=True)
        return surface_res

    def _roles():
        nonlocal roles_res
        roles_res = RM.role_matrix_from_har(har, in_scope_hosts=hosts, enabled=True)
        return roles_res

    def _states():
        nonlocal states_res
        states_res = SMX.state_machines_from_har(har, in_scope_hosts=hosts, enabled=True)
        return states_res

    def _doors():
        nonlocal doors_res
        doors_res = DM.door_map_from_har(har, scope=hosts, in_scope_hosts=hosts, enabled=True)
        return doors_res

    def _temporal():
        from authpath import temporal as TMP
        led = TMP.LifecycleLedger()
        hits = []
        for ex in exchanges:
            try:
                led.observe(ex.request, ex.response, getattr(ex.principal, "pid", None))
            except Exception:
                pass
        for fn in ("revocations", "hits", "events", "result"):
            if hasattr(led, fn):
                try: hits.append({fn: _brief(getattr(led, fn)() if callable(getattr(led, fn)) else getattr(led, fn))})
                except Exception: pass
        return {"lifecycle": hits or "no revocation/lifecycle events observed"}

    def _mass_assign():
        from authpath import mass_assign as MA
        self_bodies = []
        for ex in exchanges:
            try:
                body = ((ex.response or {}).get("content") or {}).get("text") if isinstance(ex.response, dict) else None
                if body:
                    self_bodies.append(json.loads(body))
            except Exception:
                continue
        return {"role_tied_privileged_fields": _brief(MA.role_tied_privileged_fields(self_bodies))}

    def _cross_op():
        from authpath import cross_operation as CO
        return CO.from_har(har, scope=hosts, in_scope_hosts=hosts)

    def _surface_intel():
        from authpath import surface_intel as SI
        from collections import Counter
        reaches = Counter()
        for ex in exchanges:
            try:
                req = ex.request
                hdrs = req.get("headers") if isinstance(req, dict) else getattr(req, "headers", None)
                hd = {}
                if isinstance(hdrs, list):
                    for h in hdrs: hd[str(h.get("name", "")).lower()] = h.get("value", "")
                elif isinstance(hdrs, dict):
                    hd = {str(k).lower(): v for k, v in hdrs.items()}
                v = SI.classify_surface(request_headers=hd)
                reaches[str(getattr(v, "reach", getattr(v, "verdict", "?")))] += 1
            except Exception:
                continue
        return {"reach_distribution": dict(reaches) or "n/a"}

    def _surface_map():
        from authpath import surface_map as SM
        led = SM.SurfaceLedger(); n = 0
        for ex in exchanges:
            try:
                led.observe_persisted(ex.request); n += 1
            except Exception:
                continue
        out = {"observed_requests": n}
        for attr in ("summary", "result", "ledger", "doors", "exposures"):
            if hasattr(led, attr):
                try:
                    a = getattr(led, attr); out[attr] = _brief(a() if callable(a) else a)
                except Exception:
                    pass
        return out

    def _contradictions():
        return CD.detect(surface=surface_res, doors=doors_res, roles=roles_res,
                         states=states_res, enabled=True)

    report = {"har": os.path.basename(args.har), "exchanges": len(exchanges), "sections": []}
    for title, fn in (("surface_aggregator", _surface), ("role_matrix", _roles),
                      ("state_machine", _states), ("door_map", _doors),
                      ("cross_operation", _cross_op), ("surface_intel_reach", _surface_intel),
                      ("surface_map_ledger", _surface_map),
                      ("temporal_lifecycle", _temporal), ("mass_assign_BOPLA", _mass_assign),
                      ("contradictions_FUSED", _contradictions)):
        report["sections"].append(_section(title, fn))

    json.dump(report, open(args.out, "w"), indent=2, default=str)

    # human summary (captured as deepmap.md)
    print("# ONYX deep structural anatomy\n")
    print(f"Parsed **{report['exchanges']}** exchanges from `{report['har']}`.\n")
    for s in report["sections"]:
        flag = "✅" if s["ok"] else "⚠"
        print(f"## {flag} {s['section']}")
        if not s["ok"]:
            print(f"- {s['error']}\n"); continue
        print("```")
        print(json.dumps(s["data"], indent=2, ensure_ascii=False, default=str)[:2200])
        print("```\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
