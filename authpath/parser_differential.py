"""
authpath/parser_differential.py — parser-differential authentication oracle
(GAP-4 closure, "SAML roulette").

THE SHAPE
=========
One set of bytes (a SAML assertion, a JWT, a nested XML/JSON token) is read by TWO
components that disagree: the component that CHECKS the signature sees subject X, the
component that makes the AUTHORIZATION decision reads subject Y. The attacker signs as
themselves (X) but the target acts as the victim (Y). The gap analysis (GAP-4) calls
this "same input, two interpretations, the decision rides the wrong one" — a class no
tool does deterministically.

WHY THIS IS NOT FALSE-POSITIVE BAIT
===================================
A parser disagreement ALONE is not a vulnerability — plenty of parsers differ on
whitespace or ordering with no security effect. Flagging on disagreement would wreck
precision. So this oracle treats the differential only as a LEAD, and confirms with the
identity layer's out-of-band primitive (GAP-1): the finding stands ONLY when

    * the two parsers really extract DIFFERENT identities from the same bytes, AND
    * an INDEPENDENT authenticated whoami proves the target acts as the VICTIM whose
      value the tester knew in advance, AND
    * attacker != victim, both tester-owned.

If the parsers disagree but the target still acts as the ATTACKER (the signed subject
wins), the oracle ABSTAINS. That is the negative control: the disagreement is harmless
until it actually flips the acted-upon identity, proven out of band. Registered through
the registry (GAP-5), it inherits the structural zero-FP guard.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .models import Candidate, EffectClass, StateProof
from .oracle_registry import Oracle, OracleVerdict, VerdictKind


@dataclass
class ParserDifferentialProbe:
    """One same-bytes lead, tester-owned principals.

    ``parse_a`` / ``parse_b`` are two independent extractors of the asserted identity
    from the SAME ``token_bytes`` (e.g. a strict signature-checking parser vs the authz
    layer's lenient parser). ``whoami_fn(token_bytes) -> identity`` is the out-of-band
    authenticated read of who the TARGET actually acts as when given those bytes."""
    token_bytes: str
    parse_a: Callable[[str], Any]
    parse_b: Callable[[str], Any]
    attacker_pid: str
    victim_pid: str
    victim_identity_value: str
    whoami_fn: Callable[[str], Any]


class ParserDifferentialOracle(Oracle):
    """Confirms a parser-differential auth bypass: a real identity disagreement between
    two parsers of the same bytes, proven harmful by an out-of-band whoami that returns
    the pre-known victim."""
    name = "parser-differential"
    effects = frozenset({EffectClass.PARSER_DIFFERENTIAL})

    def confirm(self, cand: Candidate, ctx: Optional[dict] = None) -> OracleVerdict:
        probe = (ctx or {}).get("parser_probe")
        if probe is None:
            ev = getattr(getattr(cand, "verdict", None), "evidence", None) or {}
            probe = ev.get("parser_probe")
        if probe is None:
            return OracleVerdict(kind=VerdictKind.ABSTAIN, effect=EffectClass.PARSER_DIFFERENTIAL,
                                 oracle_name=self.name, reason="no parser probe attached")

        owned_both = (probe.attacker_pid != probe.victim_pid
                      and bool(probe.attacker_pid) and bool(probe.victim_pid))
        value_known = probe.victim_identity_value not in (None, "")

        try:
            id_a = probe.parse_a(probe.token_bytes)
            id_b = probe.parse_b(probe.token_bytes)
        except Exception as e:
            return OracleVerdict(kind=VerdictKind.ABSTAIN, effect=EffectClass.PARSER_DIFFERENTIAL,
                                 oracle_name=self.name, reason=f"parse failed: {e!r}")

        differential = str(id_a) != str(id_b)
        if not differential:
            return OracleVerdict(kind=VerdictKind.ABSTAIN, effect=EffectClass.PARSER_DIFFERENTIAL,
                                 oracle_name=self.name,
                                 reason="both parsers agree — no differential, no finding")

        # The differential is only a LEAD; the out-of-band whoami is the proof.
        try:
            acted_as = probe.whoami_fn(probe.token_bytes)
        except Exception as e:
            return OracleVerdict(kind=VerdictKind.ABSTAIN, effect=EffectClass.PARSER_DIFFERENTIAL,
                                 oracle_name=self.name, reason=f"whoami read failed: {e!r}")

        spoofed = str(acted_as) == str(probe.victim_identity_value)
        if differential and spoofed and owned_both and value_known:
            proof = StateProof(
                confirmed=True,
                method=(f"same bytes parsed two ways (A={id_a!r}, B={id_b!r}); target "
                        f"acted as the VICTIM {probe.victim_identity_value!r} on an "
                        f"out-of-band whoami"),
                before=f"signed/attacker identity {id_a!r}",
                after=f"acted-upon identity {acted_as!r} (victim {probe.victim_pid})",
                read_as=probe.victim_pid,
                detail="parser-differential authentication bypass (SAML-roulette class)",
            )
            return OracleVerdict(
                kind=VerdictKind.CONFIRMED, effect=EffectClass.PARSER_DIFFERENTIAL,
                oracle_name=self.name, proof=proof,
                reason="parser differential confirmed harmful by out-of-band whoami",
                observed_out_of_band=True,
                expected_value_known_in_advance=value_known,
                boundary_owned_both_sides=owned_both,
            )
        return OracleVerdict(
            kind=VerdictKind.ABSTAIN, effect=EffectClass.PARSER_DIFFERENTIAL, oracle_name=self.name,
            reason=("parsers disagree but the target acted as the attacker — the signed "
                    "identity won, no bypass (no finding)" if not spoofed
                    else "preconditions not met"))
