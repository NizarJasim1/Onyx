#!/usr/bin/env python3
"""
sequences.py — Phase 4 of the six-phase roadmap: STATEFUL MULTI-STEP BUSINESS FLOWS.

The strongest bugs on mature targets live several steps deep: a workflow gate skipped, a coupon
re-applied, a state reached out of order — none visible in a single request/response. This
module drives an ORDERED sequence to reach a deep state, then lets the UNTOUCHED engine judge
the result by Δstate.

IT RESOLVES THE HANDOFF'S STATE_GATE LIMITATION — HONESTLY.
  The earlier session found "the engine won't auto-confirm a state-gate skip." Measured here,
  that was never an engine defect: the engine's StateGateLaw + confirmer DO confirm a skip when
  they are given what they need — the illegal transition PLUS an authenticated READ-BACK proving
  the object PERSISTS in the privileged terminal state with its predecessor predicate still
  unsatisfied. A single request never supplied that; a SEQUENCE does. So a gate skip is confirmed
  ONLY when the read-back proves the bypass persisted (a real Δstate breach); when the server
  enforces the gate, the read-back satisfies the predicate (or the state doesn't persist) and
  NOTHING is confirmed. Zero-FP is preserved because the verdict is still the engine's Δstate.

ARCHITECTURAL WALL (unchanged): this module only ORDERS steps. Setup steps merely prepare live
server state; the CRITICAL transition is confirmed through serve.run_engagement → the engine's
laws → its read-back confirmer. No new accept logic; engine byte-identical.
"""
from __future__ import annotations
import json, argparse, sys, os
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onyx_recon as OR


def _client(scope, researcher, verify=True):
    return OR.Client(scope, researcher=researcher, verify=verify)


def run_sequence(base_url, principals, setup_steps, critical, *,
                 scope=None, researcher="", state_gates=None, verify=True):
    """Drive an ordered flow, then confirm the CRITICAL step via the proven engine.

    setup_steps: [{principal, method, path, body?}]  — sent in order to prepare live state
                 (pure preparation; NOT analyzed). Their responses are returned for chaining.
    critical   : {method, path (with {id}), effect, body?, ids:{pid:[...]}} — the illegal
                 transition the engine drives + confirms by Δstate read-back.
    Returns (findings, setup_responses).
    """
    from authpath import serve
    from authpath.models import Principal
    from authpath.transport import HTTPTarget
    from authpath.scope_guard import ScopeConfig

    host = urlparse(base_url).hostname
    scope = scope or [host]
    base = base_url.rstrip("/")
    cli = _client(scope, researcher, verify)

    # 1) SETUP — bring the server to the pre-critical state (state prep only)
    setup_responses = []
    for s in setup_steps:
        tok = principals.get(s["principal"])
        try:
            r = cli.req((s.get("method") or "POST").upper(), base + s["path"],
                        token=tok, json=s.get("body"))
            try: body = r.json()
            except Exception: body = None
            setup_responses.append({"status": r.status_code, "body": body})
        except Exception as e:
            setup_responses.append({"status": 0, "error": repr(e)})

    # 2) CRITICAL — the illegal transition, confirmed by the proven engine + read-back
    target = HTTPTarget(base, scope=ScopeConfig(
        allowed_hosts=[host], automation_permitted=True, target_provenance="third_party",
        dry_run=False, researcher_id=researcher, attribution_in_ua=bool(researcher)))
    princ = {pid: Principal(pid, pid, auth={"Authorization": f"Bearer {tok}"})
             for pid, tok in principals.items()}
    eff = (critical.get("effect") or "STATE_GATE").upper().replace("-", "_")
    crit_params = list((critical.get("body") if isinstance(critical.get("body"), dict) else {}).keys()) or ["status"]
    entry = {f"{critical['method'].upper()} {critical['path']}":
             {"effect": eff, "critical_params": crit_params}}
    if state_gates:
        entry[f"{critical['method'].upper()} {critical['path']}"]["state_gates"] = state_gates
    ep = {"method": critical["method"].upper(), "path": critical["path"], "effect": eff,
          "ids": critical.get("ids") or {}, "body": (json.dumps(critical["body"])
          if isinstance(critical.get("body"), dict) else critical.get("body"))}
    eng, _ = serve.run_engagement(target, princ, host, dry_run=False,
                                  test_resources=sorted({str(i) for v in ep["ids"].values() for i in v}),
                                  endpoints=[ep], contract=entry, researcher=researcher,
                                  engagement_id="sequence")
    return list(eng.findings), setup_responses


def _norm(f):
    ep = getattr(f, "resource_ref", None)
    return {"effect": str(getattr(f, "effect", "")), "impact": str(getattr(f, "impact", "")),
            "severity": getattr(f, "severity", "") or getattr(f, "cvss_label", ""),
            "state_proof": str(getattr(f, "state_proof", "")),
            "title": getattr(f, "title", "")}


def run(base_url, principals, flows, *, scope=None, researcher="", verify=True):
    """Run a list of business flows. Each flow = {name, setup:[...], critical:{...}, state_gates?}.
    Returns {confirmed:[...], flows_run:n}. `flows` is supplied by the operator or synthesized by
    a caller from L2 state-machine / payment invariants."""
    confirmed = []
    for fl in flows:
        try:
            findings, _ = run_sequence(base_url, principals, fl.get("setup", []), fl["critical"],
                                       scope=scope, researcher=researcher,
                                       state_gates=fl.get("state_gates"), verify=verify)
        except Exception as e:
            confirmed.append({"flow": fl.get("name"), "error": repr(e)})
            continue
        for f in findings:
            rec = _norm(f); rec["flow"] = fl.get("name")
            confirmed.append(rec)
    return {"confirmed": [c for c in confirmed if c.get("effect")], "flows_run": len(flows),
            "errors": [c for c in confirmed if c.get("error")]}


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX sequence engine — confirm multi-step workflow/payment bypasses via the proven engine (zero new accept logic).")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--flows", required=True, help="JSON file: list of flow specs")
    ap.add_argument("--scope"); ap.add_argument("--principal", action="append", default=[], help="PID:TOKEN")
    ap.add_argument("--researcher", default="")
    args = ap.parse_args(argv)
    if not args.authorized:
        sys.exit("Refusing to run: pass --authorized (you affirm scope + permission).")
    principals = {}
    for spec in args.principal:
        pid, tok = spec.split(":", 1); principals[pid.strip()] = tok.strip()
    flows = json.load(open(args.flows))
    scope = [h.strip() for h in args.scope.split(",")] if args.scope else None
    res = run(args.base_url, principals, flows, scope=scope, researcher=args.researcher)
    print(f"flows={res['flows_run']}  CONFIRMED={len(res['confirmed'])}  errors={len(res['errors'])}")
    for c in res["confirmed"]:
        print(f"  [CONFIRMED] {c['flow']}: {c['effect']} — {c['title']}")
        print(f"     {c['state_proof']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
