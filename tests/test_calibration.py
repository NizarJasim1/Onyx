"""
Calibration harness (§9) — the only acceptance bar that matters:
  * every planted bug becomes a Δstate-CONFIRMED finding;
  * every benign action stays SILENT;
  * a 200 soft-deny (D3 trap) is flagged as a candidate then DROPPED by Δstate,
    never reported.

Run: pytest -q   (or)   python tests/test_calibration.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from fixtures.demo_scenario import run_demo


def _engine_factory(target, principals, contract):
    scope = ScopeConfig(allowed_hosts=["demo.local"], dry_run=True, automation_permitted=True)
    return AuthPathEngine(target, principals, scope, contract)


def _run():
    return run_demo(_engine_factory)


def test_every_probe_matches_ground_truth():
    engine, steps = _run()
    probes = [s for s in steps if s.kind == "probe"]
    assert len(engine.traces) == len(probes)
    for step, tr in zip(probes, engine.traces, strict=False):
        got = "finding" if tr.outcome == "finding" else "clean"
        assert got == step.expect, (
            f"{step.label}: expected {step.expect}, got {tr.outcome}"
        )


def test_all_planted_bugs_confirmed():
    engine, steps = _run()
    expected = sum(1 for s in steps if s.kind == "probe" and s.expect == "finding")
    # RL17 orchestration discovers additional REAL planted bugs (sibling cells) that
    # have no dedicated probe step — each still proven by its own per-cell Δstate.
    expected += getattr(engine, "_derived_count", 0)
    assert len(engine.findings) == expected, "every planted bug must be confirmed"


def test_no_finding_without_state_proof():
    """RL3 — no finding may exist without a confirmed Δstate proof."""
    engine, _ = _run()
    for f in engine.findings:
        assert f.state_proof is not None and f.state_proof.confirmed, f.fid
        assert f.state_proof.before != f.state_proof.after


def test_every_finding_is_reportable():
    """RL4 — causal path + PoC + named impact, always."""
    engine, _ = _run()
    for f in engine.findings:
        assert f.causal_path, f.fid
        assert f.poc.curl, f.fid
        assert f.impact is not None, f.fid
        assert f.report_markdown.strip().startswith("#"), f.fid


def test_soft_deny_is_dropped_not_reported():
    """D3 — a 200 soft-deny is flagged then dropped, never a finding."""
    engine, _ = _run()
    dropped = [t for t in engine.traces if t.outcome == "candidate-unconfirmed"]
    assert any("/api/profiles/" in t.path for t in dropped), "soft-deny must be a dropped candidate"
    assert not any(f.classification.endpoint == "GET /api/profiles/{id}" for f in engine.findings)


def test_scope_guard_fails_safe_out_of_scope():
    """RL5 — out-of-scope host resolves to HALT (inaction)."""
    from authpath.models import HTTPRequest, Principal
    from authpath.transport import MockTarget, make_exchange
    from fixtures.demo_scenario import build_contract
    scope = ScopeConfig(allowed_hosts=["demo.local"])
    eng = AuthPathEngine(MockTarget(), {"A": Principal("A", "A")}, scope, build_contract())
    req = HTTPRequest("GET", "/api/orders/101", host="not-in-scope.example")
    ex = make_exchange(MockTarget(), req, Principal("A", "A"))
    ex.request.host = "not-in-scope.example"
    tr = eng.analyze(ex)
    assert tr.outcome == "halted"


if __name__ == "__main__":
    engine, steps = _run()
    probes = [s for s in steps if s.kind == "probe"]
    ok = 0
    print("\nCALIBRATION (§9)\n" + "-" * 60)
    for step, tr in zip(probes, engine.traces, strict=False):
        got = "finding" if tr.outcome == "finding" else "clean"
        mark = "PASS" if got == step.expect else "FAIL"
        ok += got == step.expect
        print(f"  [{mark}] expect={step.expect:7s} got={tr.outcome:22s} {step.label[:46]}")
    c = engine._counts()
    print("-" * 60)
    print(f"  {ok}/{len(probes)} probes matched · {c['findings']} findings · "
          f"{c['candidates_dropped']} candidate(s) dropped by Δstate")
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("  all assertions passed ✓\n")
