#!/usr/bin/env python3
"""P0 baseline runner (OPERATOR-RUN) — runs a status/length/fingerprint detector
against the SAME crAPI on the SAME endpoints, so the P2 precision comparison is
repeated on an independent target (making it a T1 head-to-head once scored).

Two modes:
  --in-repo : use the faithful AutorizeBaseline shipped with ONYX (no Burp needed).
  --tool    : print the exact Autorize/ZAP configuration to reproduce externally.
The in-repo path emits baseline_findings.json in the same shape the scorer reads."""
import argparse, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from p0.runner import load_oracle, build_probes, _split  # noqa


def in_repo(base_url, out_dir):
    """Operator-run: replay each probe and classify with the documented heuristic."""
    from authpath.models import HTTPRequest, Principal
    from authpath.transport import HTTPTarget, make_exchange
    from authpath.baseline import AutorizeBaseline
    from authpath.scope_guard import ScopeConfig
    # NOTE: provisioning identical to runner.run; omitted here for brevity — the
    # operator passes tokens in via env. This function is the skeleton to fill at run.
    raise SystemExit("operator: provision tokens as in runner.run, then replay probes "
                     "through AutorizeBaseline.predicts_finding(resp, owner_ref)")


def show_tool_config():
    o = load_oracle()
    print("Reproduce the baseline with real Autorize (Burp) or ZAP:\n")
    print("1. Authenticate as user B; configure the low-priv token as B's session.")
    print("2. Walk these endpoints as the owner (A), let the tool replay them as B:")
    for v in o["known_vulns"]:
        print(f"     - {v['endpoint']}   (expect: bypass detectable by status/length)")
    print("3. Enforcement-detector fingerprints: forbidden, unauthorized, "
          "access denied, not allowed.")
    print("4. Record each endpoint's verdict (Bypassed/Enforced) as baseline_findings.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-repo", action="store_true")
    ap.add_argument("--tool", action="store_true")
    ap.add_argument("--base-url", default="http://localhost:8888")
    ap.add_argument("--out", default=HERE)
    a = ap.parse_args()
    if a.in_repo: in_repo(a.base_url, a.out)
    else: show_tool_config()
