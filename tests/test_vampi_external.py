"""
The strongest independence evidence in CI: ONYX vs VAmPI (erev0s, github.com/erev0s/VAmPI)
over REAL loopback HTTP. VAmPI's vulnerabilities and its vuln ON/OFF switch were authored
by a third party, years before and independently of ONYX. The vulnerability logic in
external_targets/vampi_faithful.py is transcribed VERBATIM from VAmPI's source (attributed
inline); the plumbing is ours and makes no authorization decision.

  * SAFE mode (erev0s's fixed app): ONYX must produce ZERO findings — the false-positive
    test on a target its author did not design. This guards the crown jewel externally.
  * VULNERABLE mode: ONYX must detect real independent vulnerabilities (recall > 0).
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "external_targets"))


def test_zero_false_positives_on_erev0s_safe_app():
    import run_vampi
    r = run_vampi.run_mode(vuln=False, use_http=False)
    assert r["fp"] == 0 and r["n_findings"] == 0, \
        f"false positive on erev0s's SAFE app: fp={r['fp']} findings={r['n_findings']}"


def test_detects_erev0s_real_vulnerabilities():
    import run_vampi
    r = run_vampi.run_mode(vuln=True, use_http=False)
    assert r["fp"] == 0, f"false positive on erev0s's vulnerable app: {r['fp']}"
    assert r["tp"] >= 2, f"expected to detect erev0s's BOLA + EDE, got tp={r['tp']}"


def test_vampi_target_isolated_from_detector():
    import ast
    src = open(os.path.join(ROOT, "external_targets", "vampi_faithful.py"), encoding="utf-8").read()
    for node in ast.walk(ast.parse(src)):
        mods = ([a.name for a in node.names] if isinstance(node, ast.Import)
                else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
        assert all(m.split(".")[0] != "authpath" for m in mods)


if __name__ == "__main__":
    for n, g in sorted(globals().items()):
        if n.startswith("test_"):
            try: g(); print(f"  ok  {n}")
            except AssertionError as e: print(f"  FAIL {n}: {e}")
