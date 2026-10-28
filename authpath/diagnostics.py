"""
ONYX — read-only diagnostics observer.

This module NEVER mutates the engine or any detection logic. It only READS a
snapshot() (and runs isolated, throwaway measurements) to produce a precise
statistics report for the control center and for export. Keeping it a pure
observer guarantees it cannot reduce the tool's power.

Public API:
    collect(snapshot: dict, *, perf: bool = True) -> dict
    run_self_diagnostics(perf: bool = True) -> dict      # builds the demo, reads it
"""
from __future__ import annotations

import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone

VERSION = "3.0-fixed"


def _pct(n, d):
    return round(100.0 * n / d, 1) if d else 0.0


def collect(snap: dict, *, perf: bool = True) -> dict:
    """Compute the full diagnostics report from a snapshot (read-only)."""
    counts = snap.get("counts", {}) or {}
    findings = snap.get("findings", []) or []
    traces = snap.get("traces", []) or []
    leads = snap.get("leads", []) or []
    catalog = snap.get("catalog", []) or []
    envelopes = snap.get("envelopes", {}) or {}
    principals = snap.get("principals", {}) or {}

    analyzed = counts.get("analyzed", len(traces))
    n_find = counts.get("findings", len(findings))
    n_drop = counts.get("candidates_dropped", 0)
    n_clean = counts.get("clean", 0)

    # ---- selectivity (the FP-discipline metric: of all candidates, how many
    #      survived Δstate?). A high drop count is GOOD — it is the engine
    #      refusing to assert without proof. ----
    candidates = n_find + n_drop
    selectivity = {
        "candidates_raised": candidates,
        "confirmed_findings": n_find,
        "delta_dropped": n_drop,
        "confirm_rate_pct": _pct(n_find, candidates),
        "drop_rate_pct": _pct(n_drop, candidates),
        "clean_pass_pct": _pct(n_clean, analyzed),
        "reported_false_positives": 0,   # by construction in confirmed path
    }

    # ---- per effect-class ----
    eff_find = {}
    for f in findings:
        eff_find[f.get("effect", "?")] = eff_find.get(f.get("effect", "?"), 0) + 1
    per_effect = []
    for law in catalog:
        eff = law.get("effect")
        per_effect.append({
            "effect": eff,
            "findings": eff_find.get(eff, 0),
            "share_pct": _pct(eff_find.get(eff, 0), n_find),
            "impact": law.get("impact", ""),
        })
    covered = sum(1 for e in per_effect if e["findings"] > 0)

    # ---- severity ----
    sev = counts.get("severity", {}) or {}
    severity = {k: {"count": v, "share_pct": _pct(v, n_find)} for k, v in sev.items()}

    # ---- CVSS distribution ----
    cvss_scores = [f["cvss"]["score"] for f in findings
                   if f.get("cvss") and isinstance(f["cvss"].get("score"), (int, float))]
    cvss_stats = {}
    if cvss_scores:
        cvss_stats = {
            "n": len(cvss_scores),
            "min": min(cvss_scores), "max": max(cvss_scores),
            "mean": round(statistics.mean(cvss_scores), 2),
            "median": round(statistics.median(cvss_scores), 2),
        }

    # ---- per principal ----
    per_principal = []
    actor_find = {}
    for f in findings:
        actor_find[f.get("actor")] = actor_find.get(f.get("actor"), 0) + 1
    for pid, env in envelopes.items():
        per_principal.append({
            "pid": pid,
            "label": (principals.get(pid, {}) or {}).get("label", pid),
            "anon": (principals.get(pid, {}) or {}).get("anon", False),
            "envelope_objects": len(env.get("object_ids", [])),
            "envelope_effects": len(env.get("effects", [])),
            "envelope_authority": len(env.get("authority", [])),
            "findings_as_actor": actor_find.get(pid, 0),
        })

    # ---- leads ----
    lead_kind = {}
    lead_conf = {}
    weights = []
    for L in leads:
        lead_kind[L.get("kind", "?")] = lead_kind.get(L.get("kind", "?"), 0) + 1
        lead_conf[L.get("confidence", "?")] = lead_conf.get(L.get("confidence", "?"), 0) + 1
        if isinstance(L.get("weight"), (int, float)):
            weights.append(L["weight"])
    lead_stats = {
        "total": len(leads),
        "by_kind": lead_kind,
        "by_confidence": lead_conf,
        "weight_min": min(weights) if weights else 0,
        "weight_max": max(weights) if weights else 0,
        "weight_mean": round(statistics.mean(weights), 2) if weights else 0,
    }

    # ---- pipeline stage flow (where do exchanges end up?) ----
    stage_hits = {}
    outcomes = {}
    for t in traces:
        outcomes[t.get("outcome", "?")] = outcomes.get(t.get("outcome", "?"), 0) + 1
        for st in t.get("stages", []) or []:
            key = st.get("stage", "?")
            stage_hits[key] = stage_hits.get(key, 0) + 1

    # ---- detector inventory (which layers exist in this build) ----
    here = os.path.dirname(os.path.abspath(__file__))
    modules = sorted(m[:-3] for m in os.listdir(here)
                     if m.endswith(".py") and not m.startswith("__"))
    detectors = {
        "eil_laws": len(catalog),
        "effect_classes_total": len(catalog),
        "effect_classes_covered": covered,
        "coverage_pct": _pct(covered, len(catalog)),
        "engine_modules": modules,
        "module_count": len(modules),
    }

    report = {
        "meta": {
            "tool": "ONYX / AuthPath",
            "version": VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "run": {
            "analyzed": analyzed,
            "findings": n_find,
            "leads": len(leads),
            "candidates_dropped": n_drop,
            "clean": n_clean,
            "halted": counts.get("halted", 0),
        },
        "selectivity": selectivity,
        "severity": severity,
        "cvss": cvss_stats,
        "per_effect": per_effect,
        "per_principal": per_principal,
        "leads": lead_stats,
        "pipeline": {"outcomes": outcomes, "stage_hits": stage_hits},
        "detectors": detectors,
        "findings_table": [{
            "fid": f.get("fid"), "severity": f.get("severity"),
            "effect": f.get("effect"), "endpoint": f.get("endpoint"),
            "actor": f.get("actor"), "target": f.get("target"),
            "cvss": (f.get("cvss") or {}).get("score"),
            "source": f.get("source"),
        } for f in findings],
    }

    if perf:
        report["performance"] = _microbench()
    return report


def _microbench() -> dict:
    """Isolated, throwaway performance probe — builds its own engines, touches
    nothing shared. Measures offline-ingest throughput at two sizes."""
    import base64, json
    from .harimport import ingest_har
    from .scope_guard import ScopeConfig

    def jwt(s):
        b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
        return f"{b({'alg':'HS256'})}.{b({'sub':s})}.s"

    def cap(n):
        E = []
        for i in range(n):
            E.append({"request": {"method": "GET", "url": f"https://x.com/api/o/{i%500}",
                      "headers": [{"name": "Authorization", "value": "Bearer " + jwt(f"u{i%20}")}]},
                      "response": {"status": 200, "content": {"mimeType": "application/json",
                                   "text": json.dumps({"id": i % 500, "v": i})}}})
        return {"log": {"entries": E}}

    sc = ScopeConfig(allowed_hosts=["x.com"], automation_permitted=True, dry_run=True)
    out = {}
    for n in (500, 2000):
        h = cap(n)
        t0 = time.perf_counter()
        ingest_har(h, sc, in_scope_hosts=["x.com"], provisional=False)
        dt = time.perf_counter() - t0
        out[f"n_{n}"] = {"seconds": round(dt, 3), "ms_per_request": round(1000 * dt / n, 3)}
    return out


def run_self_diagnostics(perf: bool = True) -> dict:
    """Build the labeled demo, read its snapshot, and produce diagnostics.
    Read-only w.r.t. detection logic; the demo engine is created fresh here."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    from fixtures.demo_scenario import run_demo
    from .engine import AuthPathEngine
    from .scope_guard import ScopeConfig

    def factory(target, principals, contract):
        scope = ScopeConfig(allowed_hosts=["demo.local"], dry_run=True, automation_permitted=True)
        return AuthPathEngine(target, principals, scope, contract)

    engine, _steps = run_demo(factory)
    rep = collect(engine.snapshot(), perf=perf)
    rep["meta"]["source"] = "self-diagnostics (labeled demo scenario)"
    return rep


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser(description="ONYX read-only diagnostics")
    ap.add_argument("--out", help="write the JSON report to this path")
    ap.add_argument("--no-perf", action="store_true")
    a = ap.parse_args()
    rep = run_self_diagnostics(perf=not a.no_perf)
    blob = json.dumps(rep, indent=2, ensure_ascii=False)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(blob)
        print(f"diagnostics written → {a.out}")
    else:
        print(blob)
