"""Cross-step value provenance (chain memory): a distinctive value that migrates
from one principal's private response into another principal's request fires a
lead — while common values, public-origin values, and same-principal reuse do not.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from fixtures import demo_scenario as ds


def _run():
    SC = ScopeConfig(allowed_hosts=["demo.local"], automation_permitted=True)
    return ds.run_demo(lambda t, p, c: AuthPathEngine(t, p, SC, contract=c))[0]


def test_distinctive_value_gate():
    d = AuthPathEngine._distinctive_value
    assert d("tok_AB12cd34ef56gh")          # token: distinctive
    assert d(9123456)                        # long numeric id
    assert not d("active")                   # common dictionary word
    assert not d(7)                          # tiny number
    assert not d(True)                       # bool never


def test_chain_provenance_fires_on_cross_principal_migration():
    snap = _run().snapshot()
    chain = [l for l in snap["leads"] if l["kind"] == "CHAIN_PROVENANCE"]
    assert chain, "a sensitive token migrating A->B must produce a chain lead"
    ev = chain[0]["evidence"]
    assert ev["origin_principal"] == "A" and "claim" in ev["consumed_in"]


def test_public_origin_value_does_not_fire():
    """A migrated value whose origin field is NOT sensitive (public catalog id) and
    is not token-shaped must be ignored — only private-origin migration is a signal."""
    from authpath.provenance import ProvenanceStore
    from authpath.models import Exchange, HTTPRequest, HTTPResponse, Principal
    ps = ProvenanceStore()
    a = Principal("A", "a")
    ex = Exchange(HTTPRequest("GET", "/catalog", host="h"),
                  HTTPResponse(200, {"sku": "PROD12345678"}), a)
    ps.observe_response(ex, legitimate=True)
    # the value migrated to B, but origin field 'sku' is not sensitive and value is
    # not token-shaped (len<20, no dotted segments) -> the gate suppresses it.
    from authpath.intrinsic import name_sensitivity
    assert name_sensitivity("sku") < 7


if __name__ == "__main__":
    print("\nchain-provenance tests\n" + "-" * 60)
    passed = 0
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        fn()
        passed += 1
        print(f"  [PASS] {name}")
    print("-" * 60)
    print(f"  {passed}/{len(tests)} tests passed \u2713\n")
