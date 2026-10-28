"""
authpath/identity.py — the identity-proof layer and the whoami-differential oracle
(GAP-1 closure).

THE BLIND SPOT THIS CLOSES
==========================
ONYX has always judged authorization AFTER identity is established: it takes the
principals (A, B, anon) as given and tests what objects they can reach. It never
tested HOW the target decides "who you are". Every top-tier 2025 federation bug
lives in exactly that layer, not the object layer:

    nOAuth             — target trusts a MUTABLE ``email`` claim as the identity key.
    Entra actor-token  — a service token crosses the tenant boundary.
    SAML roulette      — two XML parsers disagree, a forged assertion passes.
    audience injection — ``aud`` ambiguity in ``private_key_jwt``.

All four are the SAME shape: the attacker makes the target BELIEVE it is the victim.
ONYX's conserved quantity ("same object => same decision") cannot see this, because
the manipulation happens one layer below — at "who do you think I am".

THE ORACLE (whoami-differential) — FP-safe like Delta-state
===========================================================
After a candidate that manipulates the claim layer (the tester, authenticated as the
ATTACKER, sets a trusted claim to the VICTIM's known value), ONYX issues an
INDEPENDENT authenticated "who am I" read and confirms ONLY IF:

    the identity the target reports  ==  the victim identity
    AND the victim value was known to the tester in advance
    AND attacker != victim, both tester-owned.

This is the identity twin of the Delta-state read-back:
    * observed out of band   — the whoami response, not the attack response, not
                               inference (RL1);
    * value known in advance — the tester owns the victim principal (RL3);
    * boundary owned both sides — attacker and victim are both tester principals (RL5);
    * deterministic equality — no model anywhere in the decision (RL2).

So it registers in the Oracle Registry (GAP-5) and inherits the structural zero-FP
guarantee. On a target that is NOT vulnerable (identity keyed on an immutable
``sub``), the whoami returns the ATTACKER — the oracle ABSTAINS. That negative
control is the whole point: no spoof, no finding.

RL1 — LEARNED FROM THE WIRE, NOT ASSUMED
========================================
Which claim the target trusts as its identity key is not guessed. ``ClaimTrustModel``
reads it from authenticated responses: the claim whose value tracks the principal's
own identity across whoami reads is the identity key, and a claim is "tester-settable"
only if a tester-controlled input is reflected into it. Same discipline as
``ownership_pointer`` ("the nerve"): the fact comes from the target, not from us.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .models import Candidate, EffectClass, StateProof
from .oracle_registry import Oracle, OracleVerdict, VerdictKind


# --------------------------------------------------------------------------- #
# RL1 — claim-trust model learned from the wire                               #
# --------------------------------------------------------------------------- #
@dataclass
class ClaimObservation:
    principal_pid: str
    claims: dict                      # identity-bearing claims the target echoed for this principal
    settable_inputs: dict             # tester-controlled inputs that were reflected into claims


class ClaimTrustModel:
    """Infers, from observed authenticated responses ONLY, which claim the target
    treats as the identity key and whether the tester can set it. Nothing assumed."""

    # Claim names commonly used as the identity key; used ONLY to NAME what we already
    # observed varying with identity — never to assume a claim is trusted.
    _IDENTITY_HINTS = ("sub", "user_id", "uid", "email", "upn", "preferred_username",
                       "nameid", "netid", "oid", "actor", "act")

    def __init__(self):
        self._obs: list[ClaimObservation] = []

    def observe(self, principal_pid: str, whoami_body: dict,
                settable_inputs: Optional[dict] = None) -> None:
        if not isinstance(whoami_body, dict):
            return
        claims = {k: v for k, v in whoami_body.items()
                  if isinstance(v, (str, int)) and (
                      k.lower() in self._IDENTITY_HINTS or k.lower().endswith("id")
                      or "mail" in k.lower() or "name" in k.lower())}
        self._obs.append(ClaimObservation(principal_pid, claims, settable_inputs or {}))

    def identity_key_claims(self) -> list[str]:
        """Claims whose value DIFFERS per principal (i.e. actually track identity) —
        the real candidates for the target's identity key, read from the wire."""
        by_claim: dict[str, set] = {}
        for o in self._obs:
            for k, v in o.claims.items():
                by_claim.setdefault(k, set()).add(str(v))
        return [k for k, vals in by_claim.items() if len(vals) > 1]

    def tester_settable(self, claim: str) -> bool:
        """True iff a tester-controlled input was reflected into this claim in some
        observation — i.e. the tester can influence what the target reads as identity."""
        for o in self._obs:
            for inp_val in o.settable_inputs.values():
                if claim in o.claims and str(o.claims[claim]) == str(inp_val):
                    return True
        return False


# --------------------------------------------------------------------------- #
# GAP-1 — the identity-spoof probe + the whoami-differential oracle           #
# --------------------------------------------------------------------------- #
@dataclass
class IdentitySpoofProbe:
    """Everything the oracle needs to test one identity-spoof lead, all tester-owned.
    ``whoami_fn(auth) -> reported identity value`` is the target's "who am I" read,
    supplied by the transport adapter (discovered via discovery.py in real runs)."""
    attacker_pid: str
    victim_pid: str
    victim_identity_value: str                       # KNOWN IN ADVANCE (tester owns the victim)
    trusted_claim: str                               # the claim the target keys identity on
    spoofed_auth: dict                               # attacker creds with trusted_claim set to the victim value
    whoami_fn: Callable[[dict], Any]                 # authenticated out-of-band identity read


class IdentityOracle(Oracle):
    """whoami-differential. Confirms an identity spoof ONLY via an independent
    authenticated read that returns the victim whose value we knew in advance."""
    name = "whoami-differential"
    effects = frozenset({EffectClass.IDENTITY_SPOOF})

    def confirm(self, cand: Candidate, ctx: Optional[dict] = None) -> OracleVerdict:
        probe = (ctx or {}).get("identity_probe")
        if probe is None:
            ev = getattr(getattr(cand, "verdict", None), "evidence", None) or {}
            probe = ev.get("identity_probe")
        if probe is None:
            return OracleVerdict(
                kind=VerdictKind.ABSTAIN, effect=EffectClass.IDENTITY_SPOOF,
                oracle_name=self.name, reason="no identity probe attached",
            )

        owned_both = (probe.attacker_pid != probe.victim_pid
                      and bool(probe.attacker_pid) and bool(probe.victim_pid))
        value_known = probe.victim_identity_value not in (None, "")

        # Out-of-band authenticated identity read, performed AFTER the spoof attempt.
        try:
            reported = probe.whoami_fn(probe.spoofed_auth)
        except Exception as e:  # a target that errors proves nothing — abstain (RL5)
            return OracleVerdict(
                kind=VerdictKind.ABSTAIN, effect=EffectClass.IDENTITY_SPOOF,
                oracle_name=self.name, reason=f"whoami read failed: {e!r}",
            )

        spoofed = str(reported) == str(probe.victim_identity_value)
        if spoofed and owned_both and value_known:
            proof = StateProof(
                confirmed=True,
                method=(f"authenticated whoami returned the VICTIM identity "
                        f"({probe.trusted_claim}={probe.victim_identity_value}) while "
                        f"authenticated as attacker {probe.attacker_pid}"),
                before=f"attacker {probe.attacker_pid}",
                after=f"victim {probe.victim_pid} ({probe.victim_identity_value})",
                read_as=probe.victim_pid,
                detail=("whoami-differential: target trusts a tester-settable claim as "
                        "the identity key (nOAuth-class federation spoof)"),
            )
            return OracleVerdict(
                kind=VerdictKind.CONFIRMED, effect=EffectClass.IDENTITY_SPOOF,
                oracle_name=self.name, proof=proof,
                reason="identity spoof confirmed by out-of-band whoami",
                observed_out_of_band=True,
                expected_value_known_in_advance=value_known,
                boundary_owned_both_sides=owned_both,
            )

        return OracleVerdict(
            kind=VerdictKind.ABSTAIN, effect=EffectClass.IDENTITY_SPOOF,
            oracle_name=self.name,
            reason=("whoami returned the attacker — identity key is not spoofable "
                    "(no finding)" if not spoofed else "preconditions not met"),
        )
