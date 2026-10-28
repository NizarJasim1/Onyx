"""P0 — offline proof that the scorer is correct and game-proof WITHOUT a live run.
Five synthetic findings.json scenarios exercise every branch of the recall/precision
math and the T1 integrity gate."""
import os, sys, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
P0 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "p0")
sys.path.insert(0, P0)
import scorer as S

ORACLE = os.path.join(P0, "oracle.json")

def _oracle(): 
    with open(ORACLE) as fh: return json.load(fh)

def _finding(v):
    return {"fid": v["id"]+"-F", "case_id": v["id"], "effect": v["effect"],
            "endpoint": v["endpoint"]}

def _write(tmp, findings, provenance="third_party"):
    fp = os.path.join(tmp, "findings.json"); mp = os.path.join(tmp, "manifest.json")
    json.dump(findings, open(fp,"w")); json.dump({"target_provenance": provenance}, open(mp,"w"))
    return fp, mp

def test_perfect_run_is_t1():
    o=_oracle()
    findings=[_finding(v) for v in o["known_vulns"]]   # all vulns, cross-principal
    with tempfile.TemporaryDirectory() as t:
        fp,mp=_write(t, findings)
        r=S.score(ORACLE, fp, mp, lambda: True)
    assert r["recall"]==1.0 and r["precision"]==1.0 and r["fp"]==0
    assert r["evidence_tier"]=="T1_INDEPENDENT" and r["tier_downgrade_reasons"]==[]

def test_missed_one_lowers_recall():
    o=_oracle()
    findings=[_finding(v) for v in o["known_vulns"][:-1]]  # drop one
    with tempfile.TemporaryDirectory() as t:
        fp,mp=_write(t, findings)
        r=S.score(ORACLE, fp, mp, lambda: True)
    assert r["recall"]<1.0 and r["fn"]==1 and o["known_vulns"][-1]["id"] in r["missed_vuln_ids"]

def test_false_alarm_on_clean_lowers_precision():
    o=_oracle()
    findings=[_finding(v) for v in o["known_vulns"]]
    # add a finding on a known-clean SELF access (actor==owner) -> false positive
    c=o["known_clean"][0]
    findings.append({"fid":"FP1","case_id":c["id"],"effect":c["effect"],
                     "endpoint":c["endpoint"]})
    with tempfile.TemporaryDirectory() as t:
        fp,mp=_write(t, findings)
        r=S.score(ORACLE, fp, mp, lambda: True)
    assert r["precision"]<1.0 and r["fp"]==1 and "FP1" in r["false_alarm_fids"]

def test_broken_seal_downgrades_to_t2():
    o=_oracle()
    findings=[_finding(v) for v in o["known_vulns"]]
    with tempfile.TemporaryDirectory() as t:
        fp,mp=_write(t, findings)
        r=S.score(ORACLE, fp, mp, lambda: False)        # seal does NOT verify
    assert r["evidence_tier"]=="T2_SELF_MEASURED"
    assert any("seal" in why for why in r["tier_downgrade_reasons"])

def test_self_target_downgrades_to_t2():
    o=_oracle()
    findings=[_finding(v) for v in o["known_vulns"]]
    with tempfile.TemporaryDirectory() as t:
        fp,mp=_write(t, findings, provenance="self")     # not third-party
        r=S.score(ORACLE, fp, mp, lambda: True)
    assert r["evidence_tier"]=="T2_SELF_MEASURED"
    assert any("third_party" in why for why in r["tier_downgrade_reasons"])

def test_real_seal_verifies():
    # the committed oracle.sealed must match the current oracle+protocol
    from seal import verify
    assert verify(), "the committed seal must verify against the current oracle+protocol"

if __name__ == "__main__":
    fns=[(n,f) for n,f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    print("\nP0 scorer offline (session 4)\n"+"-"*50); p=0; fail=0
    for n,f in fns:
        try: f(); p+=1; print(f"  [PASS] {n}")
        except Exception as e: fail+=1; print(f"  [FAIL] {n}: {e!r}")
    print("-"*50); print(f"  {p}/{len(fns)} passed\n"); sys.exit(1 if fail else 0)


def test_runner_builds_a_probe_for_every_oracle_case():
    import runner
    o = runner.load_oracle()
    probes = runner.build_probes(o)
    ids = {p["case_id"] for p in probes}
    for v in o["known_vulns"]:
        assert v["id"] in ids, f"runner missing attack probe for {v['id']}"
    for c in o["known_clean"]:
        assert c["id"] in ids, f"runner missing self probe for {c['id']}"
    # every oracle case (vuln + clean) must have exactly one probe built for it
    assert len(probes) == len(o["known_vulns"]) + len(o["known_clean"])
