#!/usr/bin/env python3
"""
LIVE T1 RUN — turnkey template (the ONLY thing that converts this project from
"verifiable" to "proven"). Fill in the four blanks for a target you are AUTHORIZED to test
(crAPI on your laptop, a VDP program's scope, your own multi-tenant app) and run:

    python3 external_targets/live_run_template.py

It wires every capability (policy #1/#7 tenant hypothesis, liveness #3, consequence #4,
stealth #6, ROE #9, giant flags) and emits a SEALED scorecard. The scorecard is stamped T1
ONLY if you truthfully set independently_authored=True and live_networked=True — which is
honest only for a real live target you did not author.

This sandbox has NO network egress, so THIS cannot be run here. That is not a code gap — it
is the binding constraint the whole project now rests on. No amount of new detectors relieves
it; one live run does.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ------------------------------------------------------------------ FILL THESE IN ----------
BASE_URL = "http://127.0.0.1:8888"          # <-- your authorized target's base URL
PRINCIPALS = {
    # pid: {"Authorization": "Bearer <token for a TEST account you control>"}
    "A": {"Authorization": "Bearer <tokenA>"},
    "B": {"Authorization": "Bearer <tokenB>"},
}
TENANT_DOMAINS = {"A": "T1", "B": "T2"}      # <-- declare each test principal's tenant (#1/#7)
ENGAGEMENT_PATHS = ["/*"]                    # <-- restrict to the paths you're authorized on
TEST_RESOURCES = set()                        # <-- ids of resources you may mutate/delete
# -------------------------------------------------------------------------------------------


def build_config():
    """Assemble a byo_runner TargetConfig from the blanks above. Requires a real HTTP client
    with a .send(request, principal) method against BASE_URL (a ~30-line requests/httpx
    adapter you add for your target). Left unimplemented here on purpose — it needs egress."""
    from byo_runner import TargetConfig
    from authpath.policy import PolicyHypothesis, IsolationInvariant
    from authpath.roe import EngagementContract
    from authpath.session import SessionManager
    from authpath.consequence import ConsequenceOracle
    from authpath.stealth import StealthProfile
    from authpath.models import Principal

    hyp = IsolationInvariant("tenant-isolation", dict(TENANT_DOMAINS)).to_hypothesis()
    contract = EngagementContract(engagement_id="LIVE-1",
                                  test_principals=set(PRINCIPALS),
                                  allowed_paths=list(ENGAGEMENT_PATHS),
                                  test_resources=set(TEST_RESOURCES))
    principals = {pid: Principal(pid, pid, auth=dict(auth)) for pid, auth in PRINCIPALS.items()}

    client = None   # <-- YOU add: an object with .send(HTTPRequest, Principal) hitting BASE_URL
    if client is None:
        raise SystemExit(
            "\nThis template needs (1) a real HTTP client adapter for your target and "
            "(2) network egress.\nNeither exists in the build sandbox — that is the point: "
            "the live run is yours to perform.\nAdd a ~30-line requests adapter, set the "
            "blanks above, run against a target you are authorized to test, and you will get "
            "the first honest T1 scorecard.\n")

    return TargetConfig(
        name="live-target",
        client=client,
        principals=principals,
        independently_authored=True,     # honest ONLY for a target you did not author
        live_networked=True,             # honest ONLY for a real network round-trip
        policy_hypothesis=hyp,
        session_manager=SessionManager(liveness_prober=lambda pid: True),  # supply a real probe
        consequence_oracle=ConsequenceOracle(),   # supply a real login/capability prober
        stealth=StealthProfile(cache_bust="header"),
        contract=contract,
    )


if __name__ == "__main__":
    cfg = build_config()   # raises with instructions until you fill the blanks + add egress
    from byo_runner import run_target
    # observe_plan / attack_plan: (pid, HTTPRequest) pairs — your recon + cross-principal probes
    summary = run_target(cfg, observe_plan=[], attack_plan=[])
    print("TIER:", summary["tier"])
    print("findings:", summary["n_findings"], "tamper_evident:", summary["tamper_evident"])
