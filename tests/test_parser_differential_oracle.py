"""
GAP-4 — parser-differential ("SAML roulette") oracle tests.

The two negative controls are the whole point: (1) parsers disagree but the target
acts as the ATTACKER => ABSTAIN (a disagreement alone is not a bug); (2) parsers AGREE
=> ABSTAIN. A finding stands only when a real identity differential is proven harmful
by an out-of-band whoami returning the pre-known victim.
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import EffectClass
from authpath.parser_differential import ParserDifferentialOracle, ParserDifferentialProbe
from authpath.oracle_registry import VerdictKind, build_default_registry


def _cand(effect, evidence=None):
    return SimpleNamespace(
        verdict=SimpleNamespace(effect=effect, evidence=evidence or {}),
        classification=SimpleNamespace(effect=effect),
    )


class _StubConfirmer:
    def confirm(self, cand):
        return None


def _reg():
    return build_default_registry(_StubConfirmer(), extra_oracles=[ParserDifferentialOracle()])


VICTIM = "victim@corp.com"
ATTACKER = "attacker@corp.com"

# Two parsers of the SAME token bytes. The strict one reads the signed subject; the
# lenient (authz-layer) one reads a smuggled second assertion.
def _parse_signed(_bytes):   return ATTACKER
def _parse_authz(_bytes):    return VICTIM


def test_parser_differential_confirmed_when_target_acts_as_victim():
    probe = ParserDifferentialProbe(
        token_bytes="<saml>...</saml>", parse_a=_parse_signed, parse_b=_parse_authz,
        attacker_pid="A", victim_pid="B", victim_identity_value=VICTIM,
        whoami_fn=lambda b: VICTIM,                      # target acts as the victim
    )
    v = _reg().confirm(_cand(EffectClass.PARSER_DIFFERENTIAL), ctx={"parser_probe": probe})
    assert v.kind is VerdictKind.CONFIRMED
    assert v.as_state_proof().read_as == "B"


def test_parser_differential_abstains_when_target_acts_as_attacker_zero_fp():
    """Negative control #1: the parsers disagree, but the SIGNED identity wins — no
    bypass, so no finding."""
    probe = ParserDifferentialProbe(
        token_bytes="<saml>...</saml>", parse_a=_parse_signed, parse_b=_parse_authz,
        attacker_pid="A", victim_pid="B", victim_identity_value=VICTIM,
        whoami_fn=lambda b: ATTACKER,                    # target acts as the attacker
    )
    v = _reg().confirm(_cand(EffectClass.PARSER_DIFFERENTIAL), ctx={"parser_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN
    assert "acted as the attacker" in v.reason


def test_parser_differential_abstains_when_parsers_agree():
    """Negative control #2: no differential at all."""
    probe = ParserDifferentialProbe(
        token_bytes="<saml>...</saml>", parse_a=_parse_signed, parse_b=_parse_signed,
        attacker_pid="A", victim_pid="B", victim_identity_value=VICTIM,
        whoami_fn=lambda b: VICTIM,
    )
    v = _reg().confirm(_cand(EffectClass.PARSER_DIFFERENTIAL), ctx={"parser_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN
    assert "no differential" in v.reason


def test_parser_differential_parse_error_abstains():
    def _boom(_b):
        raise ValueError("malformed")
    probe = ParserDifferentialProbe(
        token_bytes="x", parse_a=_boom, parse_b=_parse_authz,
        attacker_pid="A", victim_pid="B", victim_identity_value=VICTIM,
        whoami_fn=lambda b: VICTIM,
    )
    v = _reg().confirm(_cand(EffectClass.PARSER_DIFFERENTIAL), ctx={"parser_probe": probe})
    assert v.kind is VerdictKind.ABSTAIN


def test_parser_differential_missing_probe_abstains():
    v = _reg().confirm(_cand(EffectClass.PARSER_DIFFERENTIAL))
    assert v.kind is VerdictKind.ABSTAIN


def test_parser_differential_in_coverage_map():
    cov = _reg().coverage()
    assert EffectClass.PARSER_DIFFERENTIAL.value in cov["covered"]
    assert "parser-differential" in cov["covered"][EffectClass.PARSER_DIFFERENTIAL.value]
