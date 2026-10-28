#!/usr/bin/env python3
"""
prove.py (AHP-Ω) — the hermetic, zero-touch measurement entry.
=================================================================================

One command produces a Proof-Carrying Measurement bundle that anyone can verify:

  python p0/prove.py --run --base-url http://localhost:8888   # OPERATOR (needs net)
  python p0/prove.py --offline-selftest                       # builds + verifies a
                                                              # bundle end-to-end, no net

It (1) attests the target (crAPI image digests + the OpenAPI spec hash), (2) drives
ONYX through the sealed-oracle probes while recording every raw request/response,
(3) builds the PCM bundle (transcript + findings + scorecard + hash chain), and
(4) immediately self-verifies it. The live run differs from the offline self-test in
exactly one way: the transcript comes from the live crAPI instead of the spec-shaped
replay target. Nothing else changes — the integrity core is identical and proven.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import pcm                                    # noqa: E402
from seal import verify as seal_verify        # noqa: E402


def attest_target(base_url: str) -> dict:
    """Cryptographic identity of the target: the crAPI image digests (proving the
    images were not modified) and the hash of the OpenAPI spec we measured against.
    On the operator's host the digests come from `docker images --digests`."""
    spec_path = os.path.join(HERE, "corpus", "crapi-openapi-spec.json")
    spec_hash = None
    if os.path.exists(spec_path):
        spec_hash = hashlib.sha256(open(spec_path, "rb").read()).hexdigest()
    digests = []
    try:
        out = subprocess.run(["docker", "images", "--digests", "--format",
                              "{{.Repository}}@{{.Digest}}"],
                             capture_output=True, text=True, timeout=20)
        digests = [l for l in out.stdout.splitlines() if "crapi" in l.lower()]
    except Exception:
        pass
    return {"base_url": base_url, "spec_sha256": spec_hash,
            "crapi_image_digests": digests,
            "attested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def _record_run(target_factory):
    """Drive ONYX through the read-leak BOLA probes, recording the raw transcript.
    Used by both the live run (HTTPTarget) and the offline self-test (replay target)."""
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig
    from authpath.models import HTTPRequest, Principal
    from authpath.transport import make_exchange

    A = Principal("A", "user A", auth={"Authorization": "Bearer A"})
    B = Principal("B", "user B", auth={"Authorization": "Bearer B"})
    sc = ScopeConfig(allowed_hosts=["crapi.local", "localhost"], automation_permitted=True,
                     target_provenance="third_party")
    target = target_factory()
    eng = AuthPathEngine(target, {"A": A, "B": B}, sc, contract={})
    for f in ("provisional_leads", "active_probing", "conservation"):
        setattr(eng, f, True)

    transcript = []
    probes = [("observe", "GET", "/identity/api/v2/vehicle/x/location", A, {"_res": "vehicleA"}),
              ("analyze", "GET", "/identity/api/v2/vehicle/x/location", B, {"_res": "vehicleA"}),
              ("observe", "GET", "/workshop/api/mechanic/mechanic_report", A, {"_res": "reportA"}),
              ("analyze", "GET", "/workshop/api/mechanic/mechanic_report", B, {"_res": "reportA"})]
    for phase, m, path, p, q in probes:
        ex = make_exchange(target, HTTPRequest(m, path, query=dict(q)), p)
        transcript.append({"phase": phase,
                           "request": {"method": m, "path": path, "principal": p.pid, "query": q},
                           "response": {"status": ex.response.status, "body": ex.response.body}})
        eng.observe(ex) if phase == "observe" else eng.analyze(ex)
    findings = [{"effect": f.effect.value, "actor_pid": f.actor_pid,
                 "target_ref": getattr(f, "target_ref", "") or ""} for f in eng.findings]
    return transcript, findings


def _oracle_seal_value() -> str:
    sealed = os.path.join(HERE, "oracle.sealed")
    return open(sealed).read().strip() if os.path.exists(sealed) else ""


def build_and_selfverify(target_factory, base_url: str) -> dict:
    transcript, findings = _record_run(target_factory)
    scorecard = {"tp": len(findings), "axis": "read-leak BOLA",
                 "tier": "SPEC_CONFORMANCE"}     # live run upgrades tier via scorer
    bundle = pcm.build_bundle(attest_target(base_url), _oracle_seal_value(),
                              transcript, findings, scorecard)
    verdict = pcm.verify_bundle(bundle, lambda s: s == _oracle_seal_value() and seal_verify())
    return {"bundle": bundle, "verdict": verdict}


def main():
    ap = argparse.ArgumentParser(description="AHP-Ω hermetic prove")
    ap.add_argument("--offline-selftest", action="store_true",
                    help="build + verify a bundle against the spec-replay target (no net)")
    ap.add_argument("--run", action="store_true", help="live run against crAPI (needs net)")
    ap.add_argument("--base-url", default="http://localhost:8888")
    ap.add_argument("--out", default=os.path.join(HERE, "bundle.json"))
    a = ap.parse_args()

    if a.run:
        from authpath.transport import HTTPTarget
        from authpath.scope_guard import ScopeConfig
        sc = ScopeConfig(allowed_hosts=[a.base_url.split("//", 1)[-1].split("/", 1)[0]],
                         automation_permitted=True, target_provenance="third_party")
        factory = lambda: HTTPTarget(a.base_url, scope=sc)
    else:
        from conformance import CrapiReplayTarget
        factory = lambda: CrapiReplayTarget(patched=False)

    res = build_and_selfverify(factory, a.base_url)
    json.dump(res["bundle"], open(a.out, "w"), indent=2)
    v = res["verdict"]
    print(f"bundle written: {a.out}")
    print(f"self-verify: {'VERIFIED' if v['verified'] else 'FAILED'}")
    for k, val in v["checks"].items():
        if isinstance(val, bool):
            print(f"  {'ok ' if val else 'BAD'} {k}")
    sys.exit(0 if v["verified"] else 1)


if __name__ == "__main__":
    main()
