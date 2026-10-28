#!/usr/bin/env python3
"""
live_hunt.py — the ONE command that turns an authorized target into paid reports.
================================================================================
This is the turnkey version of live_run_template.py with the plumbing already
wired: the real HTTP adapter (authpath.transport.HTTPTarget — it already exists,
no 30-line adapter to write), a scope guard that refuses any host you did not
authorize, an auto-built observe/attack plan from your endpoint list, and the
bounty-report packager. You fill FOUR blanks and run:

    pip install requests
    python3 external_targets/live_hunt.py

Output:
  * a SEALED, tamper-evident scorecard (tier T1 only if you truthfully assert the
    target is independently authored AND live-networked), printed to the console;
  * a folder of submission-grade Markdown reports (one per confirmed finding + an
    INDEX) under ./onyx_submission/ — ready to paste into HackerOne/Bugcrowd.

HONEST CONSTRAINTS (do not skip):
  * Only run against a target you are AUTHORIZED to test (your own crAPI on
    localhost, or a program whose scope + safe-harbor explicitly permits it).
  * Use TEST accounts you created. Only touch object ids you own or that are
    explicitly in scope. TEST_RESOURCES gates every mutate/delete.
  * This sandbox has NO network egress — run this on YOUR laptop, not here.
"""
from __future__ import annotations
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)

# ============================ FILL THESE FOUR BLANKS ========================= #
BASE_URL = "http://127.0.0.1:8888"        # (1) your authorized target's base URL

PRINCIPALS = {                            # (2) TWO+ test accounts YOU created.
    # pid: Bearer token (or full auth header value). Two principals in different
    # tenants is the minimum to prove cross-account access.
    "A": "PASTE_TOKEN_FOR_TEST_ACCOUNT_A",
    "B": "PASTE_TOKEN_FOR_TEST_ACCOUNT_B",
}
TENANT_DOMAINS = {"A": "T1", "B": "T2"}   # (3) which tenant each account belongs to

# (4) The endpoints to probe. For each, list the object ids to try. ONYX will have
# principal B try A's ids (and vice-versa) and confirm any cross-account Δstate.
# Keep every id here IN SCOPE and owned by your own test accounts.
ENDPOINTS = [
    # (method, path_template, {pid: [ids owned by that pid]})
    ("GET",    "/api/orders/{id}",            {"A": ["1001"], "B": ["2002"]}),
    ("GET",    "/identity/api/v2/vehicle/{id}/location", {"A": ["42"], "B": ["43"]}),
    # ("PUT",  "/api/orders/{id}",            {"A": ["1001"], "B": ["2002"]}),  # writes: see TEST_RESOURCES
]
TEST_RESOURCES = {"1001", "2002", "42", "43"}   # ids ONYX may mutate/delete (yours only)
PROGRAM   = "crAPI (self-hosted, authorized)"    # label shown on reports
RESEARCHER = "your-handle"                        # your bounty handle (goes in reports + UA)
# ============================================================================ #


def _build_target(scope):
    from authpath.transport import HTTPTarget
    return HTTPTarget(BASE_URL, scope=scope)


def _principals():
    from authpath.models import Principal
    P = {}
    for pid, tok in PRINCIPALS.items():
        auth = {"Authorization": tok if tok.lower().startswith("bearer ")
                else f"Bearer {tok}"}
        P[pid] = Principal(pid, pid, auth=auth)
    return P


def _plan(principals):
    """Auto-build observe + cross-principal attack plans from ENDPOINTS.
    observe: each principal reads its OWN ids (baseline).
    attack : each principal tries the OTHER principals' ids (the BOLA probe)."""
    from authpath.models import HTTPRequest
    from urllib.parse import urlparse
    host = urlparse(BASE_URL).netloc.split(":")[0]

    def mk(method, path):
        return HTTPRequest(method=method, path=path, host=host)

    observe, attack = [], []
    for method, tmpl, owned in ENDPOINTS:
        # baseline: owners read their own objects
        for pid, ids in owned.items():
            for oid in ids:
                observe.append((pid, mk(method, tmpl.replace("{id}", str(oid)))))
        # probe: every principal tries every OTHER principal's ids
        for actor in principals:
            for owner, ids in owned.items():
                if owner == actor:
                    continue
                for oid in ids:
                    attack.append((actor, mk(method, tmpl.replace("{id}", str(oid)))))
    return observe, attack


def main():
    try:
        import requests  # noqa: F401
    except ImportError:
        sys.exit("Install the live extra first:  pip install requests")

    if "PASTE_TOKEN" in "".join(PRINCIPALS.values()):
        sys.exit("Fill in PRINCIPALS with real test-account tokens first "
                 "(blanks 1–4 at the top of this file).")

    from byo_runner import TargetConfig, run_target
    from authpath.scope_guard import ScopeConfig
    from authpath.policy import IsolationInvariant
    from authpath.roe import EngagementContract
    from urllib.parse import urlparse

    host = urlparse(BASE_URL).netloc.split(":")[0]
    scope = ScopeConfig(allowed_hosts=[host], automation_permitted=True,
                        target_provenance="third_party", dry_run=False,
                        researcher_id=RESEARCHER, attribution_in_ua=True)
    target = _build_target(scope)
    principals = _principals()
    hyp = IsolationInvariant("tenant-isolation", dict(TENANT_DOMAINS)).to_hypothesis()
    contract = EngagementContract(engagement_id="LIVE-1",
                                  test_principals=set(PRINCIPALS),
                                  allowed_paths=["/*"],
                                  test_resources=set(map(str, TEST_RESOURCES)))

    cfg = TargetConfig(
        name="live-target", client=target, principals=principals,
        independently_authored=True,   # TRUE only if you did NOT write this target
        live_networked=True,           # TRUE only for a real network round-trip
        policy_hypothesis=hyp, contract=contract)

    observe, attack = _plan(principals)
    print(f"[*] observe probes: {len(observe)}   cross-principal attack probes: {len(attack)}")
    summary = run_target(cfg, observe_plan=observe, attack_plan=attack)

    print("\n================ SEALED SCORECARD ================")
    print("TIER            :", summary["tier"])
    print("confirmed finds :", summary["n_findings"])
    print("tamper-evident  :", summary["tamper_evident"])
    print("chain hash      :", summary.get("chain_hash", "")[:32], "…")

    findings = summary.get("_findings", [])
    if findings:
        from bounty_report import write_pack
        out_dir = os.path.join(os.getcwd(), "onyx_submission")
        paths = write_pack(findings, out_dir, program=PROGRAM,
                           researcher=RESEARCHER, scorecard=summary)
        print(f"\n[+] {len(findings)} submission-ready report(s) written to {out_dir}/")
        for p in paths:
            print("    -", os.path.basename(p))
        print("\nSubmit INDEX.md's top finding first (highest CVSS). Every report is "
              "backed by a Δstate proof — that is what stops a triager downgrade.")
    else:
        print("\nNo confirmed findings. That is a CLEAN, honest result — not a failure. "
              "If you expected findings, widen ENDPOINTS or check your tokens/scope.")


if __name__ == "__main__":
    main()
