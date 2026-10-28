#!/usr/bin/env python3
"""
P0 runner (OPERATOR-RUN) — drives ONYX against a live OWASP crAPI and emits a
scorer-ready findings.json + run_manifest.json.
=================================================================================

The sandbox that built this has no network, so the LIVE run is done by the operator.
Everything here is written and structurally checkable offline: `python runner.py
--check` builds every probe from the sealed oracle without sending a packet, proving
the runner is wired to the ground truth. `python runner.py --run --base-url URL`
performs the real provisioning + observe/attack run.

Integrity rules honoured:
- Credentials are provisioned from real signup/login and never fabricated (D6).
- target_provenance is 'third_party' (crAPI's authors are not ONYX's).
- The runner never edits the oracle; it only produces findings to be scored against
  the sealed ground truth.

NOTE (VALIDATE): the crAPI auth/endpoint paths below match the current OWASP crAPI;
if your deployment differs, adjust CRAPI_AUTH only — the rest is generic.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from authpath.models import HTTPRequest, Principal          # noqa: E402
from authpath.scope_guard import ScopeConfig                # noqa: E402

CRAPI_AUTH = {
    "signup": "POST /identity/api/auth/signup",
    "login":  "POST /identity/api/auth/login",
    "token_field": "token",
}


def _split(endpoint: str):
    method, path = endpoint.split(" ", 1)
    query = {}
    if "?" in path:
        path, qs = path.split("?", 1)
        for kv in qs.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                query[k] = v
    return method.strip(), path.strip(), query


def load_oracle() -> dict:
    with open(os.path.join(HERE, "oracle.json"), encoding="utf-8") as fh:
        return json.load(fh)


def build_probes(oracle: dict) -> list[dict]:
    """Offline: turn every oracle row into a concrete probe descriptor (no network).
    A vuln probe is cross-principal (attacker != owner); a clean probe is self-access.
    Concrete ids are placeholders the operator fills from provisioning."""
    probes = []
    for v in oracle["known_vulns"]:
        m, p, q = _split(v["endpoint"])
        probes.append({"kind": "attack", "case_id": v["id"], "effect": v["effect"],
                       "endpoint": v["endpoint"], "method": m, "path": p, "query": q,
                       "actor": v.get("attacker", "B"),
                       "owner": (v.get("victim_resource", "A")).split(".", 1)[0]})
    for c in oracle["known_clean"]:
        m, p, q = _split(c["endpoint"])
        probes.append({"kind": "self", "case_id": c["id"], "effect": c["effect"],
                       "endpoint": c["endpoint"], "method": m, "path": p, "query": q,
                       "actor": c.get("actor", "A"),
                       "owner": (c.get("resource", "A")).split(".", 1)[0]})
    return probes


# --------------------------- operator-only live path --------------------------- #

def provision_user(base_url, email, password, name="P0 User"):
    """Real signup + login -> JWT. Operator-run (needs network). Never fabricates."""
    import requests
    m, sp, _ = _split(CRAPI_AUTH["signup"])
    requests.post(base_url.rstrip("/") + sp,
                  json={"name": name, "email": email, "password": password,
                        "number": "4156895423"}, timeout=15)
    m, lp, _ = _split(CRAPI_AUTH["login"])
    r = requests.post(base_url.rstrip("/") + lp,
                      json={"email": email, "password": password}, timeout=15)
    r.raise_for_status()
    return r.json()[CRAPI_AUTH["token_field"]]


def run(base_url: str, out_dir: str, creds: dict) -> dict:
    """Operator-run live measurement. Provisions A and B, drives observe (self) then
    attack (cross-principal) probes through ONYX, and writes findings + manifest."""
    from authpath.engine import AuthPathEngine
    from authpath.transport import HTTPTarget, make_exchange

    oracle = load_oracle()
    scope = ScopeConfig(allowed_hosts=[base_url.split("//", 1)[-1].split("/", 1)[0]],
                        automation_permitted=True, target_provenance="third_party")
    target = HTTPTarget(base_url, scope=scope)

    tokens = {pid: provision_user(base_url, creds[pid]["email"], creds[pid]["password"])
              for pid in ("A", "B")}
    principals = {pid: Principal(pid, f"crAPI user {pid}",
                                 auth={"Authorization": f"Bearer {tokens[pid]}"})
                  for pid in ("A", "B")}

    engine = AuthPathEngine(target, principals, contract={})
    probes = build_probes(oracle)

    # observe (self) first to establish provenance, then attack (cross-principal)
    for ph in ("self", "attack"):
        for pr in [p for p in probes if p["kind"] == ph]:
            req = HTTPRequest(pr["method"], pr["path"], query=pr["query"])
            ex = make_exchange(target, req, principals[pr["actor"]])
            engine.observe(ex) if ph == "self" else engine.analyze(ex)

    findings = []
    for f in engine.findings:
        # attribute each finding to the attack-probe case it corresponds to (by effect)
        match = next((p for p in probes if p["effect"] == f.effect.value
                      and p["kind"] == "attack"), None)
        findings.append({
            "fid": f.fid, "case_id": match["case_id"] if match else "",
            "effect": f.effect.value,
            "endpoint": match["endpoint"] if match else "",
            "actor_pid": f.actor_pid,
        })

    os.makedirs(out_dir, exist_ok=True)
    fpath = os.path.join(out_dir, "findings.json")
    mpath = os.path.join(out_dir, "run_manifest.json")
    json.dump(findings, open(fpath, "w"), indent=2)
    json.dump({"target": base_url, "target_provenance": "third_party",
               "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "n_probes": len(probes)}, open(mpath, "w"), indent=2)
    return {"findings": fpath, "manifest": mpath, "n_findings": len(findings)}


def main():
    ap = argparse.ArgumentParser(description="P0 live runner (operator-run)")
    ap.add_argument("--check", action="store_true",
                    help="offline: build probes from the sealed oracle, send nothing")
    ap.add_argument("--run", action="store_true", help="perform the live run (network)")
    ap.add_argument("--base-url", default="http://localhost:8888")
    ap.add_argument("--out", default=HERE)
    args = ap.parse_args()

    if args.check or not args.run:
        probes = build_probes(load_oracle())
        print(f"[check] built {len(probes)} probes from the sealed oracle (no network):")
        for p in probes:
            print(f"  - {p['kind']:6s} {p['case_id']:32s} {p['endpoint']}")
        print("\nrun live with:  python p0/runner.py --run --base-url <crAPI-url>")
        return
    creds = {"A": {"email": "p0a@example.com", "password": "Passw0rd!A"},
             "B": {"email": "p0b@example.com", "password": "Passw0rd!B"}}
    res = run(args.base_url, args.out, creds)
    print("wrote", res)


if __name__ == "__main__":
    main()
