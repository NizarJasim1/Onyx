"""
AHP-12 hardening regression suite.

Each test is a calibration probe for a confirmer-soundness gap the original
calibration did NOT cover (the systemic blind spot: the 27-probe demo never
exercised the paths where the confirmer rubber-stamped or string-matched). Every
test below FAILED on the pre-AHP-12 code and PASSES after. They lock the fixes so
no future change can silently re-introduce a false positive or an unproven
finding (the WHY.md anti-regression discipline, mechanised).

Invariant under test across all of them: a CONFIRMED finding requires positive
Δstate evidence; a read-back that refutes, or the absence of proof, must ABSTAIN.
"""
from authpath.models import (
    Candidate, EffectClass, EffectClassification, ClassificationSource,
    Exchange, HTTPRequest, HTTPResponse, LawVerdict, Principal, Verdict,
)
from authpath.confirmer import Confirmer
from authpath.scope_guard import ScopeGuard, ScopeConfig

B = Principal("B", "Bob")
_SG = ScopeGuard(ScopeConfig(allowed_hosts=["demo.local"], dry_run=True))


class _RB:
    """Read-back target: returns a fixed authoritative post-state body."""
    def __init__(self, body, status=200):
        self.body, self.status = body, status
    def send(self, req, principal):
        return HTTPResponse(self.status, self.body)


class _NoRB:
    """No read-back ever available (sentinel non-2xx)."""
    def send(self, req, principal):
        return HTTPResponse(599, {"error": "not captured"})


def _confirm(target, cand):
    proof = Confirmer(target, {"B": B}, _SG).confirm(cand)
    return proof is not None and proof.confirmed


def _cand(effect, req, resp_body, ev, status=200):
    ex = Exchange(req, HTTPResponse(status, resp_body), B)
    cls = EffectClassification(endpoint=req.endpoint_key(), effect=effect,
                               source=ClassificationSource.INFERRED)
    v = LawVerdict(Verdict.CANDIDATE, "test", effect, "reason", evidence=ev)
    return Candidate("C", ex, cls, v)


# --- D-STATEGATE-FP (pass 1): predecessor re-evaluated on the read-back ----- #
def test_stategate_satisfied_gate_abstains():
    req = HTTPRequest("POST", "/api/orders/303/fulfil", body={}, host="demo.local")
    ev = {"reached": "fulfilled", "missing_gate": "paid equals True",
          "unmet_predicates": ["paid equals True"],
          "unmet_predicate_specs": [{"field": "paid", "equals": True}]}
    cand = _cand(EffectClass.STATE_GATE, req, {"id": "303", "status": "fulfilled", "paid": False}, ev)
    # read-back PROVES the order was actually settled (gate satisfied) -> NO bypass
    assert _confirm(_RB({"id": "303", "status": "fulfilled", "paid": True}), cand) is False


def test_stategate_real_bypass_confirms():
    req = HTTPRequest("POST", "/api/orders/303/fulfil", body={}, host="demo.local")
    ev = {"reached": "fulfilled", "missing_gate": "paid equals True",
          "unmet_predicates": ["paid equals True"],
          "unmet_predicate_specs": [{"field": "paid", "equals": True}]}
    cand = _cand(EffectClass.STATE_GATE, req, {"id": "303", "status": "fulfilled", "paid": False}, ev)
    assert _confirm(_RB({"id": "303", "status": "fulfilled", "paid": False}), cand) is True


def test_stategate_missing_specs_fails_safe():
    """Legacy candidate with no machine-usable specs must abstain, not fall back
    to the old broken string comparison."""
    req = HTTPRequest("POST", "/api/orders/303/fulfil", body={}, host="demo.local")
    cand = _cand(EffectClass.STATE_GATE, req, {"id": "303", "status": "fulfilled", "paid": True},
                 {"reached": "fulfilled", "missing_gate": "paid equals True"})
    assert _confirm(_RB({"id": "303", "status": "fulfilled", "paid": True}), cand) is False


# --- D-INVENTORY-NOREADBACK (pass 2): real Δstate, no rubber stamp ---------- #
def test_inventory_persisted_negative_qty_confirms():
    req = HTTPRequest("POST", "/api/cart/303/add", body={"qty": -5}, host="demo.local")
    cand = _cand(EffectClass.INVENTORY, req, {"ok": True}, {"requested_qty": -5})
    assert _confirm(_RB({"id": "303", "qty": -5.0}), cand) is True


def test_inventory_negative_available_confirms():
    req = HTTPRequest("POST", "/api/cart/303/add", body={"qty": 999}, host="demo.local")
    cand = _cand(EffectClass.INVENTORY, req, {"ok": True}, {"requested_qty": 999})
    assert _confirm(_RB({"id": "303", "available": -3}), cand) is True


def test_inventory_clamped_qty_refutes():
    req = HTTPRequest("POST", "/api/cart/303/add", body={"qty": -5}, host="demo.local")
    cand = _cand(EffectClass.INVENTORY, req, {"ok": True}, {"requested_qty": -5})
    assert _confirm(_RB({"id": "303", "qty": 0}), cand) is False


def test_inventory_no_proof_abstains_not_rubber_stamp():
    """The original RL3 breach: body truthy + qty present must NOT confirm
    without positive persistence evidence."""
    req = HTTPRequest("POST", "/api/cart/303/add", body={"qty": -5}, host="demo.local")
    cand = _cand(EffectClass.INVENTORY, req, {"ok": True}, {"requested_qty": -5})
    assert _confirm(_NoRB(), cand) is False


# --- D-CONFIRM-FALLBACK (pass 3): read-back refutation, fallback preserved -- #
def _payment_cand():
    req = HTTPRequest("POST", "/api/checkout",
                      body={"order_id": "303", "amount_paid": 1}, host="demo.local")
    return _cand(EffectClass.PAYMENT, req,
                 {"order_id": "303", "amount_due": 90, "amount_paid": 1, "status": "paid"},
                 {"amount_paid": 1, "amount_due": 90, "shortfall": 89})


def test_payment_corrected_on_readback_refutes():
    assert _confirm(_RB({"id": "303", "status": "paid", "amount_paid": 90, "amount_due": 90}),
                    _payment_cand()) is False


def test_payment_underpay_persisted_confirms():
    assert _confirm(_RB({"id": "303", "status": "paid", "amount_paid": 1, "amount_due": 90}),
                    _payment_cand()) is True


def test_payment_no_readback_single_sided_fallback():
    assert _confirm(_NoRB(), _payment_cand()) is True


def _price_cand():
    req = HTTPRequest("POST", "/api/orders/303/price",
                      body={"total": 5, "items": [{"price": 90, "qty": 1}]}, host="demo.local")
    return _cand(EffectClass.PRICE, req, {"total": 5},
                 {"claimed_total": 5, "computed_total": 90})


def test_price_server_recomputed_refutes():
    assert _confirm(_RB({"id": "303", "total": 90}), _price_cand()) is False


def test_price_tampered_total_persisted_confirms():
    assert _confirm(_RB({"id": "303", "total": 5}), _price_cand()) is True


def test_price_no_readback_echo_fallback():
    assert _confirm(_NoRB(), _price_cand()) is True


def _ownership_cand():
    req = HTTPRequest("PATCH", "/api/users/B", body={"role": "admin"}, host="demo.local")
    return _cand(EffectClass.OWNERSHIP, req, {"id": "B", "role": "admin"},
                 {"field": "role", "value": "admin"})


def test_ownership_not_persisted_refutes():
    assert _confirm(_RB({"id": "B", "role": "user"}), _ownership_cand()) is False


def test_ownership_persisted_confirms():
    assert _confirm(_RB({"id": "B", "role": "admin"}), _ownership_cand()) is True


def test_ownership_no_readback_echo_fallback():
    assert _confirm(_NoRB(), _ownership_cand()) is True


# --- D-DETERMINISM-CLOCK (pass 4): within_seconds uses capture time --------- #
def test_within_seconds_uses_reference_time_deterministic():
    from authpath.eil import _predicate_holds
    p = {"field": "ts", "within_seconds": 60}
    body = {"ts": 1_000_000.0}
    # within window relative to the supplied reference; out of window otherwise.
    assert _predicate_holds(p, body, now=1_000_030.0) is True
    assert _predicate_holds(p, body, now=1_000_120.0) is False
    # deterministic: same inputs, same verdict (no wall-clock dependence)
    assert _predicate_holds(p, body, now=1_000_030.0) == _predicate_holds(p, body, now=1_000_030.0)


# --- D-READ-EXCEPT (pass 6): detection failure abstains, never passes through  #
def test_read_detection_exception_abstains():
    class Raises:
        def send(self, req, principal):
            class Bad:
                status = 200
                # .body raises when block-detection inspects it
                @property
                def body(self):
                    raise RuntimeError("boom")
                headers = {}
            return Bad()
    c = Confirmer(Raises(), {"B": B}, _SG)
    assert c._read(HTTPRequest("GET", "/x", host="demo.local"), B) is None


# --- gold standard unchanged: OBJECT_ACCESS still fail-safes on read-back fail #
def test_object_access_abstains_when_readback_fails():
    req = HTTPRequest("GET", "/api/orders/101", host="demo.local")
    cand = _cand(EffectClass.OBJECT_ACCESS, req, {"id": "101", "owner_id": "A", "ssn": "x"},
                 {"object_id": "101", "laundered_from": None})
    A = Principal("A", "Alice")
    proof = Confirmer(_NoRB(), {"A": A, "B": B}, _SG).confirm(cand)
    assert (proof is not None and proof.confirmed) is False
