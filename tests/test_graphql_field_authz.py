"""
GAP-3 (nested/aliased field extraction) + GAP-9 (valueless structural confirmation as
the default basis).

Decisive controls: a field the backend's OWN contract denies, yet present in the
response, CONFIRMS — valuelessly, no victim data read. A field present but NOT denied
(backend allows it), or denied but absent (filtering worked), ABSTAINS. And the registry
must enforce the structural-contract basis just as strictly as value-match.
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import EffectClass, StateProof
from authpath.graphql_fields import (
    GraphQLFieldAuthzOracle, GraphQLFieldProbe, parse_field_leaves,
)
from authpath.oracle_registry import (
    Oracle, OracleRegistry, OracleVerdict, VerdictKind, build_default_registry,
)


def _cand(effect, evidence=None):
    return SimpleNamespace(
        verdict=SimpleNamespace(effect=effect, evidence=evidence or {}),
        classification=SimpleNamespace(effect=effect),
    )


class _StubConfirmer:
    def confirm(self, cand):
        return None


def _reg():
    return build_default_registry(_StubConfirmer(), extra_oracles=[GraphQLFieldAuthzOracle()])


# --- GAP-3: the parser now sees nested + aliased leaves ------------------------- #
def test_parser_extracts_nested_and_aliased_leaves():
    q = "query { me { id secret: ssn orders(first: 5) { internal_notes } } }"
    leaves = parse_field_leaves(q)
    assert "me.id" in leaves
    assert "me.secret" in leaves                 # alias resolved to response key
    assert "me.orders.internal_notes" in leaves  # nested, args skipped
    assert "me.ssn" not in leaves                # the alias is the response key, not the raw name


def test_parser_handles_fragments_and_comments():
    q = "{ a # comment\n ... on User { b } alias3: c }"
    leaves = parse_field_leaves(q)
    assert "a" in leaves and "b" in leaves and "alias3" in leaves


# --- GAP-9: valueless (structural-contract) confirmation ------------------------ #
def test_field_overexposure_confirmed_valuelessly():
    probe = GraphQLFieldProbe(
        attacker_pid="A",
        requested_leaves=["me.id", "me.ssn"],
        contract_denied_paths=["me.ssn"],          # backend's OWN contract denies ssn for A
        present_populated_paths=["me.id", "me.ssn"],  # yet ssn came back populated
    )
    v = _reg().confirm(_cand(EffectClass.GRAPHQL_FIELD_AUTHZ), ctx={"gql_field_probe": probe})
    assert v.kind is VerdictKind.CONFIRMED
    assert v.confirmation_basis == "structural-contract"
    assert v.contract_anchored and v.attacker_owned
    # confirmed WITHOUT needing the victim value or a second owned principal:
    assert v.expected_value_known_in_advance is False
    assert v.boundary_owned_both_sides is False


def test_field_present_but_not_denied_abstains():
    probe = GraphQLFieldProbe(
        attacker_pid="A", requested_leaves=["me.id"],
        contract_denied_paths=[],                  # backend allows everything requested
        present_populated_paths=["me.id"],
    )
    v = _reg().confirm(_cand(EffectClass.GRAPHQL_FIELD_AUTHZ), ctx={"gql_field_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN


def test_field_denied_and_absent_abstains_zero_fp():
    """The backend denied the field AND filtered it out — filtering worked, no finding."""
    probe = GraphQLFieldProbe(
        attacker_pid="A", requested_leaves=["me.ssn"],
        contract_denied_paths=["me.ssn"],
        present_populated_paths=[],                # ssn was NOT returned
    )
    v = _reg().confirm(_cand(EffectClass.GRAPHQL_FIELD_AUTHZ), ctx={"gql_field_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN


def test_owned_value_leak_escalates_note_still_structural():
    probe = GraphQLFieldProbe(
        attacker_pid="A", requested_leaves=["me.ssn"],
        contract_denied_paths=["me.ssn"], present_populated_paths=["me.ssn"],
        owned_value_leaked=True,
    )
    v = _reg().confirm(_cand(EffectClass.GRAPHQL_FIELD_AUTHZ), ctx={"gql_field_probe": probe})
    assert v.kind is VerdictKind.CONFIRMED
    assert "severity raised" in v.as_state_proof().method


# --- the registry enforces the structural basis just as strictly --------------- #
def test_registry_downgrades_structural_confirm_without_contract_anchor():
    """could-have-failed: a structural CONFIRMED that is NOT anchored to the target's
    own contract must be downgraded to ABSTAIN."""
    class _Rogue(Oracle):
        name = "rogue-structural"
        effects = frozenset({EffectClass.GRAPHQL_FIELD_AUTHZ})
        def confirm(self, cand, ctx=None):
            p = StateProof(confirmed=True, method="m", before=0, after=1, read_as="contract")
            return OracleVerdict(kind=VerdictKind.CONFIRMED, effect=EffectClass.GRAPHQL_FIELD_AUTHZ,
                                 oracle_name=self.name, proof=p, observed_out_of_band=True,
                                 confirmation_basis="structural-contract",
                                 contract_anchored=False,      # <-- the missing anchor
                                 attacker_owned=True)
    reg = OracleRegistry().register(_Rogue())
    v = reg.confirm(_cand(EffectClass.GRAPHQL_FIELD_AUTHZ))
    assert v.kind is VerdictKind.ABSTAIN
    assert "own disclosed contract" in v.reason


def test_graphql_field_in_coverage_map():
    cov = _reg().coverage()
    assert EffectClass.GRAPHQL_FIELD_AUTHZ.value in cov["covered"]
    assert "graphql-field-authz" in cov["covered"][EffectClass.GRAPHQL_FIELD_AUTHZ.value]
