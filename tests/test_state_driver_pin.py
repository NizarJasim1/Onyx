"""
GAP-8 (law<->state driving planner) + GAP L1-8 (ownership pinning for dynamic objects).

One seam: reaching AND pinning the state a law needs. The driver composes consent-gated
primitives into an executable reach plan (or an honest 'unreachable' naming the missing
facts); the pin keeps a multi-step drive from confirming against a boundary that drifted.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.state_driver import (
    LawStatePlanner, Primitive, required_facts_from_prior_state,
)
from authpath.state_pin import DriveStabilityGuard, OwnershipLedger, Pin


# --- GAP-8: driving to a deep, context-dependent state ------------------------- #
def _refund_primitives():
    return [
        Primitive("create_order", frozenset(), frozenset({"order_created"}),
                  creates_objects=("order-1",)),
        Primitive("pay_partial", frozenset({"order_created"}), frozenset({"paid_partial"})),
        Primitive("open_refund", frozenset({"paid_partial"}), frozenset({"refund_window_open"})),
    ]


def test_driver_reaches_deep_state_in_order():
    plan = LawStatePlanner().plan(
        current_facts=set(),
        required_facts={"order_created", "paid_partial", "refund_window_open"},
        primitives=_refund_primitives(), law_name="RefundAuthzLaw")
    assert plan.reachable is True
    assert plan.steps == ["create_order", "pay_partial", "open_refund"]
    assert "order-1" in plan.created_objects      # dynamic object to be pinned (GAP L1-8)


def test_driver_refuses_non_consented_primitive_rl5():
    prims = [
        Primitive("create_order", frozenset(), frozenset({"order_created"})),
        # the step that would reach the state is NOT consent-gated -> must be refused
        Primitive("force_refund_state", frozenset({"order_created"}),
                  frozenset({"refund_window_open"}), consent_gated=False),
    ]
    plan = LawStatePlanner().plan(set(), {"refund_window_open"}, prims)
    assert plan.reachable is False
    assert "force_refund_state" in plan.reason and "RL5" in plan.reason


def test_driver_honest_unreachable_names_missing_facts():
    prims = [Primitive("create_order", frozenset(), frozenset({"order_created"}))]
    plan = LawStatePlanner().plan(set(), {"order_created", "refund_window_open"}, prims)
    assert plan.reachable is False
    assert "refund_window_open" in plan.reason     # the bounded, named residual


def test_prior_state_adapter_builds_facts():
    reqs = [{"field": "paid", "equals": True}, {"field": "status", "equals": "shipped"}]
    facts = required_facts_from_prior_state(reqs)
    assert facts == {"paid=True", "status=shipped"}


def test_driver_already_satisfied_is_trivially_reachable():
    plan = LawStatePlanner().plan({"ready"}, {"ready"}, [])
    assert plan.reachable is True and plan.steps == []


# --- GAP L1-8: ownership pinning keeps a multi-step drive sound ---------------- #
def test_pin_consistent_and_drift():
    led = OwnershipLedger()
    p = led.pin("order-1", "A")
    assert isinstance(p, Pin)
    assert OwnershipLedger.consistent(p, "A") is True      # same owner -> sound
    assert OwnershipLedger.consistent(p, "B") is False     # drifted -> must abstain


def test_stability_guard_flags_drift():
    led = OwnershipLedger()
    p1 = led.pin("order-1", "A")
    p2 = led.pin("order-2", "A")
    ok, drifted = DriveStabilityGuard().stable([(p1, "A"), (p2, "A")])
    assert ok is True and drifted == []
    ok2, drifted2 = DriveStabilityGuard().stable([(p1, "A"), (p2, "C")])  # order-2 drifted
    assert ok2 is False and drifted2 == ["order-2"]
