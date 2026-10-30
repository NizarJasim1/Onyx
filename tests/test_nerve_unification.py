"""
FORGE step 5 — unification regression.

Pins the architectural claim that RL15-18 are special cases of the nerve's single
conserved law, and proves it is not mere prose: the nerve's own decision-conflict
signal — via the SAME audited identity unification the engines use — surfaces the
RL15 (representation) and RL16 (time) inconsistencies as candidates. Descriptive
only; no engine touched, no conviction added.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.equivalence import EquivalenceLedger
from authpath.surface_map import identify
from authpath.nerve_unification import covered_axes, engine_for_axis
from authpath.models import HTTPRequest, HTTPResponse


def _G(method, path, body, status):
    return HTTPRequest(method, path), HTTPResponse(status, body)


def test_nerve_reuses_the_engines_identity_unification():
    # singular/plural must unify to the SAME resource key the engines rely on
    assert str(identify(HTTPRequest("GET", "/api/orders/42"))) == "order:42"
    assert str(identify(HTTPRequest("GET", "/api/order/42"))) == "order:42"


def test_nerve_subsumes_rl16_time_inconsistency():
    L = EquivalenceLedger()
    L.record_access(*_G("GET", "/api/orders/42", {"id": "42", "owner_id": "u-9"}, 200), "u-1")
    L.record_access(*_G("GET", "/api/orders/42", {"error": "forbidden"}, 403), "u-1")
    pairs = L.decision_conflict_pairs()
    assert len(pairs) == 1 and pairs[0]["resource"] == "order:42"


def test_nerve_subsumes_rl15_representation_inconsistency():
    L = EquivalenceLedger()
    L.record_access(*_G("GET", "/api/orders/42", {"id": "42", "owner_id": "u-9"}, 200), "u-1")
    L.record_access(*_G("GET", "/api/order/42", {"error": "forbidden"}, 403), "u-1")
    pairs = L.decision_conflict_pairs()       # two doors unify to one key → one conflict
    assert len(pairs) == 1 and pairs[0]["resource"] == "order:42"


def test_registry_covers_all_five_axes():
    axes = covered_axes()
    assert axes == {"representation / door", "time", "sibling / combinatorial",
                    "hierarchy / composition", "identity / ownership"}
    assert engine_for_axis("identity / ownership").startswith("nerve")
    assert "RL15" in engine_for_axis("representation / door")
    assert "RL18" in engine_for_axis("hierarchy / composition")


def test_unification_is_inert_no_conviction_symbols():
    import authpath.nerve_unification as U
    src = open(U.__file__).read()
    for banned in ("self.findings", "confirm(", "Finding(", "report_markdown"):
        assert banned not in src
