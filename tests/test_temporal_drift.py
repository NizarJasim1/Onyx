"""Temporal STRUCTURAL drift: after a privilege-narrowing (role-downgrade) event
that leaves the credential VALID, a retained privileged branch fires a lead —
and this is strictly disjoint from the value-based revocation law.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from fixtures import demo_scenario as ds


def _snap():
    SC = ScopeConfig(allowed_hosts=["demo.local"], automation_permitted=True)
    return ds.run_demo(lambda t, p, c: AuthPathEngine(t, p, SC, contract=c))[0].snapshot()


def test_role_downgrade_structural_drift_fires():
    snap = _snap()
    td = [l for l in snap["leads"] if l["kind"] == "TEMPORAL_STRUCTURAL_DRIFT"]
    assert td, "a privileged branch retained after a role downgrade must fire a drift lead"
    ev = td[0]["evidence"]
    assert ev["narrowing_kind"] == "role_downgrade"
    assert any("internal" in p for p in td[0]["paths"])


def test_drift_is_disjoint_from_revocation():
    """The revoked-credential case is owned by the value-based TemporalDriftLaw
    (a finding); the drift lead must NOT also fire there — the two are disjoint.
    Alice's token is revoked in the demo, so no drift lead may name principal A."""
    snap = _snap()
    drift_principals = {l["principal"] for l in snap["leads"]
                        if l["kind"] == "TEMPORAL_STRUCTURAL_DRIFT"}
    assert "A" not in drift_principals          # A is revoked -> handled as a finding, not a drift lead


if __name__ == "__main__":
    print("\ntemporal-structural-drift tests\n" + "-" * 60)
    passed = 0
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        fn()
        passed += 1
        print(f"  [PASS] {name}")
    print("-" * 60)
    print(f"  {passed}/{len(tests)} tests passed \u2713\n")
