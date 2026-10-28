"""
GAP-6 (high-recall generation/ranking) + GAP-11 (portfolio EV + CVE dedup).

Both are OFF the confirmation path (RL2): they only choose where/what/what-order to
probe. These tests pin the ranking/allocation/dedup logic and that the optional external
scorer re-orders but is bounded and fail-safe.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.recall import CandidateLead, RecallPlanner
from authpath.portfolio import Asset, DedupIndex, PortfolioPlanner, _normalize_endpoint


# --- GAP-6: recall ranking ----------------------------------------------------- #
def test_strong_lead_outranks_weak_lead():
    refs = [
        {"endpoint": "/api/orders/{id}", "param": "id", "effect_hint": "OBJECT_ACCESS",
         "tier": "js"},                                           # weak
        {"endpoint": "/api/sso/assert", "param": "email", "effect_hint": "IDENTITY_SPOOF",
         "tier": "observed", "id_bearing": True, "ownership_pointer_hit": True,
         "cross_principal_swappable": True},                      # strong
    ]
    ranked = RecallPlanner().generate(refs)
    assert ranked[0].endpoint == "/api/sso/assert"
    assert ranked[0].score > ranked[1].score


def test_external_scorer_is_bounded_and_monotonic():
    lead = CandidateLead(endpoint="/x", param="id", effect_hint="OBJECT_ACCESS", tier="observed")
    low = RecallPlanner(external_scorer=lambda l: 0.0).score(lead)
    high = RecallPlanner(external_scorer=lambda l: 1.0).score(lead)
    base = RecallPlanner().score(lead)
    assert low < base < high                       # offline signal re-orders within bounds
    assert high <= base * 1.5 + 1e-9               # never dominates (bounded x1.5)


def test_external_scorer_exception_is_ignored():
    def _boom(_l):
        raise RuntimeError("offline scorer died")
    lead = CandidateLead(endpoint="/x", param="id", tier="observed")
    # must not raise, and must equal the pure deterministic score
    assert RecallPlanner(external_scorer=_boom).score(lead) == RecallPlanner().score(lead)


def test_family_confirmations_boost_recall():
    lead = CandidateLead(endpoint="/x", param="id", effect_hint="AUTHORITY", tier="observed")
    plain = RecallPlanner().score(lead)
    boosted = RecallPlanner(family_confirmations={"AUTHORITY": 3}).score(lead)
    assert boosted > plain                         # bugs cluster -> probe that family sooner


# --- GAP-11: portfolio EV allocation ------------------------------------------- #
def test_allocation_orders_by_expected_value():
    assets = [
        Asset("low", est_value=1.0, p_success=0.05, est_cost=2.0),
        Asset("high", est_value=5.0, p_success=0.4, est_cost=1.0),
        Asset("mid", est_value=2.0, p_success=0.2, est_cost=1.0),
    ]
    allocs = PortfolioPlanner().allocate(assets, budget=10.0)
    order = [a.asset.aid for a in allocs]
    assert order[0] == "high" and order[-1] == "low"


def test_allocation_respects_budget():
    assets = [Asset(f"a{i}", est_value=1.0, p_success=0.3, est_cost=3.0) for i in range(5)]
    allocs = PortfolioPlanner().allocate(assets, budget=7.0)
    assert sum(a.budget for a in allocs) <= 7.0 + 1e-9
    assert len(allocs) == 3                        # 3+3+1, then exhausted


def test_prior_yield_raises_priority():
    a_plain = Asset("p", est_value=2.0, p_success=0.2, est_cost=1.0, prior_yield=0)
    a_paid = Asset("q", est_value=2.0, p_success=0.2, est_cost=1.0, prior_yield=4)
    pp = PortfolioPlanner()
    assert pp.ev(a_paid) > pp.ev(a_plain)


# --- GAP-11: known-CVE dedup --------------------------------------------------- #
def test_endpoint_id_normalization_groups_instances():
    assert _normalize_endpoint("/api/orders/123") == _normalize_endpoint("/api/orders/456")
    assert _normalize_endpoint("/api/orders/123") == "/api/orders/{id}"


def test_dedup_marks_known_and_keeps_novel():
    idx = DedupIndex()
    idx.add_known("OBJECT_ACCESS", "/api/orders/1", "id")
    assert idx.is_known("OBJECT_ACCESS", "/api/orders/999", "id")   # normalized match
    assert not idx.is_known("OWNERSHIP", "/api/orders/1", "id")     # different effect => novel
    leads = [
        CandidateLead(endpoint="/api/orders/5", param="id", effect_hint="OBJECT_ACCESS"),  # known
        CandidateLead(endpoint="/api/invoices/5", param="id", effect_hint="OBJECT_ACCESS"),  # novel
    ]
    novel = idx.filter_novel(leads)
    assert len(novel) == 1 and novel[0].endpoint == "/api/invoices/5"
