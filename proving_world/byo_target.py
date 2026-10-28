#!/usr/bin/env python3
"""
BRING-YOUR-OWN-TARGET — the independence closer.
================================================================================
The proving world is anti-circular by construction (AST-guarded, sealed, randomized),
but ONYX's author still wrote it. This runner removes the author from the loop
entirely: it points ONYX at a LIVE target that someone ELSE wrote — the OWASP crAPI
reference app, or your own vulnerable app — over real HTTP, drives the full active
loop, and prints the same zero-false-positive scorecard against a ground truth YOU
control.

You (a third party) become the independent verifier. ONYX's author never sees your
target.

USAGE (against a crAPI you spin up — see docs/THIRD_PARTY_VERIFICATION.md):
    python3 byo_target.py \
        --base-url http://localhost:8888 \
        --principals principals.json \
        --plan crapi_plan.json \
        --oracle crapi_oracle.json

  principals.json : {"A": {"Authorization": "Bearer <A jwt>"}, "B": {...}, "C": {...}}
  plan.json       : the observe/attack request plan (a sample crAPI plan ships alongside)
  oracle.json     : YOUR ground truth — {"BOLA GET /identity/api/v2/vehicle/{id}/location": true, ...}

ONYX confirms only by Δstate; nothing here is tuned to your target. If ONYX flags a
safe endpoint, that is a real false positive and it will show in YOUR scorecard.
"""
from __future__ import annotations
import argparse, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from authpath.models import HTTPRequest, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.transport import HTTPTarget


def load(p):
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def build_engine(base_url, principals, allowed_host, strict=True):
    scope = ScopeConfig(allowed_hosts=[allowed_host], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    target = HTTPTarget(base_url, scope=scope)
    P = {pid: Principal(pid, pid, auth=hdrs) for pid, hdrs in principals.items()}
    eng = AuthPathEngine(target, P, scope, contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(eng, f, True)
    # all detection laws ON for a real run (they default OFF for byte-identical calibration)
    eng.confirmer.strict_leak = strict
    eng.embedded_owner_exposure = True
    eng.field_exposure = True
    eng.xprincipal_write = True
    eng.xprincipal_delete = True
    eng.confirmer.stability_k = 7          # chaos-hardened re-verification on a real network
    return eng, target, P


def score_run(eng, target, P, plan, oracle, allowed_host, base_url="(injected target)",
              independent=False):
    """Drive a prepared engine over a plan and score against the oracle. Shared by the
    live path and the smoke test. `independent=True` should be set ONLY when the target
    was authored by a third party (a live crAPI, your own app) — not the in-repo world."""
    def ex(step):
        req = HTTPRequest(step["method"], step["path"], query=step.get("query", {}),
                          body=step.get("body"), host=allowed_host)
        resp = target.send(req, P[step["pid"]])
        return Exchange(request=req, response=resp, principal=P[step["pid"]])

    for step in plan.get("observe", []):
        eng.observe(ex(step))
    for step in plan.get("attack", []):
        eng.analyze(ex(step))
    eng.drain_deferred()

    flagged = {f.classification.endpoint for f in eng.findings}
    tp = fp = fn = tn = 0
    rows = []
    for endpoint, is_vuln in oracle.items():
        if endpoint.startswith("_"):
            continue
        found = endpoint in flagged
        v = ("TP" if is_vuln and found else "FN" if is_vuln else "FP" if found else "TN")
        tp += v == "TP"; fp += v == "FP"; fn += v == "FN"; tn += v == "TN"
        rows.append((endpoint, is_vuln, found, v))

    print("=" * 70)
    header = ("ONYX on a THIRD-PARTY target its author did not write"
             if independent else "ONYX scorecard (target: in-repo / self-authored)")
    print(f"{header}: {base_url}")
    print("=" * 70)
    for endpoint, is_vuln, found, v in rows:
        print(f"  [{v}] oracle_vuln={str(is_vuln):5} onyx_flagged={str(found):5}  {endpoint}")
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    print("-" * 70)
    print(f"  precision={prec:.3f}   recall={rec:.3f}   false positives={fp}")
    print("=" * 70)
    if fp == 0 and independent:
        print("ZERO false positives on a target ONYX's author did not write.")
    elif fp == 0:
        print("ZERO false positives. (Self-authored target — for true independence use "
              "--independent against a live crAPI or your own app.)")
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": prec, "recall": rec}


def run(base_url, principals, plan, oracle, allowed_host):
    eng, target, P = build_engine(base_url, principals, allowed_host)
    return score_run(eng, target, P, plan, oracle, allowed_host, base_url, independent=True)


def main():
    ap = argparse.ArgumentParser(description="Run ONYX against your own live target.")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--principals", required=True)
    ap.add_argument("--plan", required=True)
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--host", default=None, help="allowed host (defaults to base-url host)")
    a = ap.parse_args()
    from urllib.parse import urlparse
    host = a.host or urlparse(a.base_url).hostname
    run(a.base_url, load(a.principals), load(a.plan), load(a.oracle), host)


if __name__ == "__main__":
    main()
