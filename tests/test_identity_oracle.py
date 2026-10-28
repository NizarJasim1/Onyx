"""
GAP-1 — whoami-differential identity oracle tests.

The decisive pair is the vulnerable vs patched target. On the nOAuth-class target
(identity keyed on a mutable ``email`` claim) the oracle CONFIRMS a spoof. On the
patched target (identity keyed on an immutable ``sub``) it ABSTAINS — zero false
positive. That negative control is what makes the CONFIRMED meaningful: the test
could have failed (a careless oracle would fire on both).
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import EffectClass, StateProof
from authpath.identity import ClaimTrustModel, IdentityOracle, IdentitySpoofProbe
from authpath.oracle_registry import VerdictKind, build_default_registry


def _cand(effect, evidence=None):
    return SimpleNamespace(
        verdict=SimpleNamespace(effect=effect, evidence=evidence or {}),
        classification=SimpleNamespace(effect=effect),
    )


class _StubConfirmer:
    def __init__(self, proof=None):
        self._proof = proof
    def confirm(self, cand):
        return self._proof


# --- two synthetic targets, black-box: auth dict in -> reported identity out ----- #
def _whoami_vulnerable(auth):
    """nOAuth-class: the target trusts whatever ``email`` the token carries as the
    identity key. A tester-settable claim => spoofable."""
    return auth.get("email")

def _whoami_patched(auth):
    """Fixed: identity is the server-bound immutable ``sub``; the ``email`` in the
    token is ignored for identity. Not spoofable."""
    return auth.get("bound_sub")


VICTIM_EMAIL = "victim@corp.com"

def _spoof_probe(whoami_fn):
    # attacker authenticates as themselves but sets the trusted claim to the victim's
    # KNOWN value. bound_sub stays the attacker's (the server binds it, not the token).
    spoofed_auth = {"bound_sub": "attacker-sub", "email": VICTIM_EMAIL}
    return IdentitySpoofProbe(
        attacker_pid="A", victim_pid="B", victim_identity_value=VICTIM_EMAIL,
        trusted_claim="email", spoofed_auth=spoofed_auth, whoami_fn=whoami_fn,
    )


def test_identity_spoof_confirmed_on_vulnerable_target():
    probe = _spoof_probe(_whoami_vulnerable)
    reg = build_default_registry(_StubConfirmer(), identity_oracle=IdentityOracle())
    v = reg.confirm(_cand(EffectClass.IDENTITY_SPOOF), ctx={"identity_probe": probe})
    assert v.kind is VerdictKind.CONFIRMED
    assert v.observed_out_of_band and v.expected_value_known_in_advance and v.boundary_owned_both_sides
    sp = v.as_state_proof()
    assert isinstance(sp, StateProof) and sp.read_as == "B"


def test_identity_spoof_abstains_on_patched_target_zero_fp():
    """THE zero-FP negative control. Same attack, patched target => NO finding."""
    probe = _spoof_probe(_whoami_patched)
    reg = build_default_registry(_StubConfirmer(), identity_oracle=IdentityOracle())
    v = reg.confirm(_cand(EffectClass.IDENTITY_SPOOF), ctx={"identity_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN
    assert v.as_state_proof() is None


def test_probe_can_ride_on_candidate_evidence():
    """The probe may be attached to the candidate's verdict.evidence instead of ctx —
    the path the engine uses when it carries the lead on the candidate itself."""
    probe = _spoof_probe(_whoami_vulnerable)
    reg = build_default_registry(_StubConfirmer(), identity_oracle=IdentityOracle())
    cand = _cand(EffectClass.IDENTITY_SPOOF, evidence={"identity_probe": probe})
    v = reg.confirm(cand)
    assert v.kind is VerdictKind.CONFIRMED


def test_whoami_error_abstains():
    def _boom(auth):
        raise RuntimeError("target 500")
    probe = _spoof_probe(_boom)
    reg = build_default_registry(_StubConfirmer(), identity_oracle=IdentityOracle())
    v = reg.confirm(_cand(EffectClass.IDENTITY_SPOOF), ctx={"identity_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN


def test_missing_probe_abstains():
    reg = build_default_registry(_StubConfirmer(), identity_oracle=IdentityOracle())
    v = reg.confirm(_cand(EffectClass.IDENTITY_SPOOF))
    assert v.kind is VerdictKind.ABSTAIN


def test_identity_oracle_does_not_disturb_legacy_classes():
    """Adding the identity oracle must not change any object-level verdict — additive
    only. With the stub confirmer abstaining, an OBJECT_ACCESS candidate still abstains."""
    reg = build_default_registry(_StubConfirmer(None), identity_oracle=IdentityOracle())
    assert reg.confirm(_cand(EffectClass.OBJECT_ACCESS)).kind is VerdictKind.ABSTAIN
    proof = StateProof(confirmed=True, method="rb", before=0, after=1, read_as="A")
    reg2 = build_default_registry(_StubConfirmer(proof), identity_oracle=IdentityOracle())
    assert reg2.confirm(_cand(EffectClass.OBJECT_ACCESS)).kind is VerdictKind.CONFIRMED


# --- RL1: the identity key is LEARNED from the wire, not assumed ----------------- #
def test_claim_trust_model_learns_identity_key_from_wire():
    m = ClaimTrustModel()
    # the target echoes these claims for each principal's own authenticated whoami
    m.observe("A", {"sub": "sub-a", "email": "a@corp.com", "role": "user"},
              settable_inputs={"email_input": "a@corp.com"})
    m.observe("B", {"sub": "sub-b", "email": "b@corp.com", "role": "user"},
              settable_inputs={"email_input": "b@corp.com"})
    keys = m.identity_key_claims()
    assert "sub" in keys and "email" in keys        # both vary per principal
    assert "role" not in keys                        # constant => not identity-bearing
    # email was reflected from a tester input => tester-settable (the nOAuth risk)
    assert m.tester_settable("email") is True
