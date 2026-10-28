"""
Envelope-precision regression suite (D-ENVELOPE-OVERBROAD).

The IDOR law and envelope conflated "the actor SAW an id" with "the actor is
AUTHORISED for the object". An id glimpsed as a LIST ELEMENT was recorded as a
legitimate hold, silently clearing any attack that pivots from a listing
(list -> item PII leak). Fixed at both sites: provenance now separates HELD
(addressed + received) from merely SEEN; the envelope absorbs only TOP-LEVEL
self-ids, not list/nested element ids.

Guards: (1) the pivot now confirms; (2) NO new false positive — a legitimate
self-hold and an incidental-but-not-cross-principal id are still clean; (3) the
held/seen distinction is correct.
"""
from authpath.models import Principal, HTTPRequest, HTTPResponse, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.economy import BudgetLedger
from authpath.transport import make_exchange
from authpath.provenance import ProvenanceStore

A = Principal("A", "Alice")
B = Principal("B", "Bob")


class _Items:
    """Collection lists ids only; item endpoint returns full PII owned by B."""
    def send(self, req, p):
        path = req.path
        if path == "/api/orders":
            return HTTPResponse(200, {"orders": [{"id": "701"}, {"id": "702"}]})
        if path.startswith("/api/orders/"):
            oid = path.rsplit("/", 1)[1]
            owner = "A" if oid == "500" else "B"
            return HTTPResponse(200, {"id": oid, "owner_id": owner, "ssn": f"SSN-{oid}"})
        return HTTPResponse(404, {"error": "absent"})


def _engine(target):
    return AuthPathEngine(target, {"A": A, "B": B},
                          ScopeConfig(allowed_hosts=["h"], dry_run=False),
                          contract={}, ledger=BudgetLedger.unbounded())


# --- (1) the pivot now CONFIRMS -------------------------------------------- #
def test_list_to_item_pivot_confirms():
    t = _Items()
    eng = _engine(t)
    # A glimpses B's ids in a list it may read; B legitimately holds them.
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/orders", host="h"), A))
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/orders/701", host="h"), B))
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/orders/702", host="h"), B))
    # A fetches an item it only saw in the listing -> IDOR
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/orders/701", host="h"), A))
    assert tr.outcome == "finding"


# --- (2) NO new false positive --------------------------------------------- #
def test_authoritative_self_hold_still_clean():
    """A fetches its OWN object (addressed by id) twice -> still no finding."""
    t = _Items()
    eng = _engine(t)
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/orders/500", host="h"), A))  # A's own
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/orders/500", host="h"), A))
    assert tr.outcome != "finding"


def test_incidental_id_not_laundered_is_clean():
    """An id A saw but that belongs to NO other principal must not fire (no FP)."""
    pv = ProvenanceStore()
    exA = Exchange(HTTPRequest("GET", "/api/orders", host="h"),
                   HTTPResponse(200, {"orders": [{"id": "900"}]}), A)
    pv.observe_response(exA, legitimate=True)
    assert pv.seen_by_principal("900", "A") is True
    assert pv.held_object_by_principal("900", "A") is False    # glimpsed, not held
    assert pv.first_seen_for_other_principal("900", "A") is None  # nobody else -> not laundered


# --- (3) held vs seen semantics -------------------------------------------- #
def test_addressed_id_is_held():
    pv = ProvenanceStore()
    ex = Exchange(HTTPRequest("GET", "/api/orders/701", host="h"),
                  HTTPResponse(200, {"id": "701", "owner_id": "B"}), B)
    pv.observe_response(ex, legitimate=True)
    assert pv.held_object_by_principal("701", "B") is True     # addressed + received


def test_list_element_id_is_seen_not_held():
    pv = ProvenanceStore()
    ex = Exchange(HTTPRequest("GET", "/api/orders", host="h"),
                  HTTPResponse(200, {"orders": [{"id": "701"}, {"id": "702"}]}), A)
    pv.observe_response(ex, legitimate=True)
    assert pv.seen_by_principal("701", "A") is True
    assert pv.held_object_by_principal("701", "A") is False    # list element, not held


def test_nested_related_id_not_held_in_envelope():
    """Reading your own order must NOT absorb a nested related id as a held object."""
    from authpath.envelope import EnvelopeEngine
    from authpath.models import EffectClass
    ee = EnvelopeEngine()
    ex = Exchange(HTTPRequest("GET", "/api/orders/500", host="h"),
                  HTTPResponse(200, {"id": "500", "items": [{"pid": "888"}]}), A)
    ee.observe(ex, EffectClass.OBJECT_ACCESS)
    env = ee.envelope_for("A")
    assert env.holds_object("500")        # the addressed object
    assert not env.holds_object("888")    # a nested element id is NOT held
