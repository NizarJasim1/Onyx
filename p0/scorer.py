#!/usr/bin/env python3
"""P0 scorer — turns a live run's findings.json into recall/precision against the
SEALED oracle, and awards an evidence tier under strict integrity gates.

T1 (independent) is awarded ONLY IF:
  (a) the oracle/protocol seal verifies (ground truth was locked before the run), AND
  (b) the run's target_provenance is 'third_party' (the target's authors are not
      ONYX's authors).
If either fails, the result is downgraded to T2 — the rig cannot claim independence
it did not earn. This is the P0xP8 contract in code."""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _case_key(endpoint: str, effect: str) -> tuple:
    # normalise an endpoint to its (method, path-template, effect) identity so a
    # finding and an oracle row match regardless of the concrete id substituted in.
    e = " ".join(endpoint.split())
    return (e.strip(), effect.strip())


def score(oracle_path: str, findings_path: str, run_manifest_path: str,
          seal_verify) -> dict:
    oracle = _load(oracle_path)
    findings = _load(findings_path)
    manifest = _load(run_manifest_path)

    vulns = oracle["known_vulns"]
    clean = oracle["known_clean"]
    vuln_ids = {v["id"] for v in vulns}
    clean_ids = {c["id"] for c in clean}

    # The runner tags every finding with the case_id of the probe that produced it
    # (it drives one labelled probe at a time, so attribution is exact). This avoids
    # any cross-principal inference, which is wrong for excessive-data-exposure cases
    # where the violation occurs on the actor's OWN resource. A finding on a known
    # vuln case is a true positive; a finding on a known-clean case is a false alarm.
    found_vuln_ids, false_alarms, unmatched = set(), [], []
    for f in findings:
        cid = str(f.get("case_id", "")).strip()
        if cid in vuln_ids:
            found_vuln_ids.add(cid)
        elif cid in clean_ids:
            false_alarms.append(f.get("fid", "?"))      # fired on a known-clean case
        else:
            unmatched.append(f.get("fid", "?"))         # outside the locked oracle

    n_vuln = len(vulns)
    tp = len(found_vuln_ids)
    fn = n_vuln - tp
    fp = len(false_alarms)
    recall = tp / n_vuln if n_vuln else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0

    # --- integrity gates for the evidence tier ---
    seal_ok = bool(seal_verify())
    third_party = manifest.get("target_provenance") == "third_party"
    if seal_ok and third_party:
        tier = "T1_INDEPENDENT"
    else:
        tier = "T2_SELF_MEASURED"
    reasons = []
    if not seal_ok:
        reasons.append("oracle seal did not verify (ground truth may have changed) "
                       "-> cannot claim independence")
    if not third_party:
        reasons.append("target_provenance is not third_party -> not an independent target")

    return {
        "evidence_tier": tier,
        "tier_downgrade_reasons": reasons,
        "seal_verified": seal_ok,
        "target_provenance": manifest.get("target_provenance"),
        "recall": round(recall, 3),
        "precision": round(precision, 3),
        "tp": tp, "fn": fn, "fp": fp,
        "found_vuln_ids": sorted(found_vuln_ids),
        "missed_vuln_ids": sorted({v["id"] for v in vulns} - found_vuln_ids),
        "false_alarm_fids": false_alarms,
        "unmatched_fids_outside_oracle": unmatched,
        "ceded_classes": [c["class"] for c in oracle.get("ceded", [])],
    }


def format_scorecard(r: dict) -> str:
    lines = [
        f"P0 SCORECARD  [{r['evidence_tier']}]",
        f"  seal_verified={r['seal_verified']}  target_provenance={r['target_provenance']}",
        f"  recall={r['recall']}  precision={r['precision']}  "
        f"(tp={r['tp']} fn={r['fn']} fp={r['fp']})",
    ]
    if r["missed_vuln_ids"]:
        lines.append(f"  missed: {', '.join(r['missed_vuln_ids'])}")
    if r["false_alarm_fids"]:
        lines.append(f"  false alarms on known-clean: {', '.join(r['false_alarm_fids'])}")
    if r["tier_downgrade_reasons"]:
        lines.append("  TIER DOWNGRADED:")
        for why in r["tier_downgrade_reasons"]:
            lines.append(f"    - {why}")
    lines.append(f"  honestly ceded (not measured): {', '.join(r['ceded_classes'])}")
    return "\n".join(lines)


if __name__ == "__main__":
    from seal import verify as seal_verify
    o = os.path.join(HERE, "oracle.json")
    f = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "findings.json")
    m = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "run_manifest.json")
    print(format_scorecard(score(o, f, m, seal_verify)))
