"""
FORGE — target-attested identity ledger regression suite (nerve build, step 1).

Locks the first operational piece of the nerve: ONYX never DECIDES who a credential
belongs to — it quotes the identity the TARGET declares at a self endpoint. These
guarantees encode the four false-positive scenarios the design must survive, plus
the RL1 abstain behaviour.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.attestation import (AttestationLedger, register_identity_fields,
                                   _CUSTOM_IDENTITY_FIELDS)
from authpath.models import HTTPRequest, HTTPResponse


def _me(path, body, status=200):
    return HTTPRequest("GET", path), HTTPResponse(status, body)


def test_multidevice_same_principal_unified():
    """FP-2: one person, two credentials (devices) → the target declares the same
    identity → ONYX unifies them. The volatile `session` field must NOT split them."""
    L = AttestationLedger()
    L.record_self_response("phone", *_me("/api/me", {"id": "u-100", "email": "a@x.com", "session": "s1"}))
    L.record_self_response("laptop", *_me("/api/me", {"id": "u-100", "email": "a@x.com", "session": "s2"}))
    assert L.same_principal("phone", "laptop") is True
    assert L._self_pointer == "id"


def test_distinct_principals_separated():
    L = AttestationLedger()
    L.record_self_response("a", *_me("/api/me", {"id": "u-1", "email": "alice@x.com", "session": "z9"}))
    L.record_self_response("b", *_me("/api/me", {"id": "u-2", "email": "bob@x.com", "session": "z8"}))
    assert L.same_principal("a", "b") is False


def test_shared_credential_one_identity():
    """FP-1: a shared proxy credential yields ONE declared identity (the target's word)."""
    L = AttestationLedger()
    L.record_self_response("shared", *_me("/userinfo", {"id": "u-200"}))
    assert L.identity_of("shared") == "u-200"


def test_non_self_endpoint_is_not_testimony():
    """A resource endpoint (/orders) is not the target testifying about the caller."""
    L = AttestationLedger()
    L.record_self_response("x", *_me("/api/orders/55", {"id": "order-55", "total": 99}))
    assert L.identity_of("x") is None


def test_abstains_without_testimony():
    L = AttestationLedger()
    assert L.same_principal("p", "q") is None      # no testimony ⇒ unknown ⇒ abstain


def test_opaque_token_needs_no_parsing():
    """Identity comes from the RESPONSE, so opaque/reference tokens work (RFC 9068)."""
    L = AttestationLedger()
    L.record_self_response("opaque_aGVsbG8", *_me("/api/account", {"id": "acc-9", "name": "Carol"}))
    assert L.identity_of("opaque_aGVsbG8") == "acc-9"


def test_bespoke_identity_field_abstains_then_extensible():
    L = AttestationLedger()
    L.record_self_response("z", *_me("/api/me", {"memberRef": "mr-7", "session": "q1"}))
    assert L.identity_of("z") is None              # unknown field ⇒ abstain, not guess
    try:
        register_identity_fields(["memberRef"])
        L2 = AttestationLedger()
        L2.record_self_response("z", *_me("/api/me", {"memberRef": "mr-7", "session": "q1"}))
        assert L2.identity_of("z") == "mr-7"
    finally:
        _CUSTOM_IDENTITY_FIELDS.discard("memberref")


def test_unstable_field_never_becomes_identity():
    """A field that changes across a credential's own self reads is not an identity."""
    L = AttestationLedger()
    L.record_self_response("c", *_me("/api/me", {"id": "u-5", "csrf": "t1"}))
    L.record_self_response("c", *_me("/api/me", {"id": "u-5", "csrf": "t2"}))  # csrf flips
    L.record_self_response("d", *_me("/api/me", {"id": "u-6", "csrf": "t9"}))
    assert L._self_pointer == "id"                 # csrf excluded (unstable + not id-named)
    assert L.same_principal("c", "d") is False
