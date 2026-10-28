"""
Consequence oracle (deficiency #4 — invisible-Δstate blindness).
================================================================================
ONYX confirms a finding only when an authenticated read-back proves the effect. A whole
class of high-severity effects has NO direct read-back: a changed credential (visible only
after re-authentication), a raised capability (no data changes, but a new action becomes
reachable), an effect visible only to another principal, and so on. The strict
confirm-by-Δstate rule — the source of zero-FP — is also the source of this blind spot.

The fix (root, not patch): generalise confirmation from "read back the EFFECT directly"
to "read back a CONSEQUENCE the effect NECESSARILY entails, through a channel ONYX
controls." Necessity — not probability — is what keeps this FP-safe: if the consequence
can only hold when the effect happened, observing it proves the effect. No inference, no
ML, so RL1/RL2 and the zero-FP crown jewel are preserved.

Concrete consequences implemented:
  * CREDENTIAL TAKEOVER (the file's own flagship miss — VAmPI password change): the actor
    set victim Q's credential to an attacker-chosen UNIQUE value V. Consequence: an auth
    attempt AS Q with V now succeeds. A random nonce V cannot authenticate unless the write
    took effect, so success is proof — no "before" baseline needed.
  * CAPABILITY ACQUISITION (privilege escalation with no visible data): a specific action
    that was DENIED to the actor before is ALLOWED after, with a genuine Δstate. The
    before/after denial flip is the consequence that the escalation entails.

The oracle is supplied by the operator (it knows the login / capability flow of the target),
exactly like the auth headers — never fabricated by ONYX. When no oracle is provided, ONYX
behaves exactly as before (abstain on invisible effects). This module makes no
authorization decision; it only reports whether a necessary consequence is observed.
"""
from __future__ import annotations
from typing import Optional, Callable


class ConsequenceOracle:
    """Operator-supplied probes for consequences ONYX cannot read back directly. Every
    probe returns a hard boolean/None from a REAL interaction with the target; ONYX judges
    only the Δstate it reports."""

    def __init__(self,
                 auth_prober: Optional[Callable[[str, str], bool]] = None,
                 capability_prober: Optional[Callable[[str, str], bool]] = None,
                 actions: Optional[list] = None):
        self._auth = auth_prober
        self._capability = capability_prober
        # action keys to baseline-probe for the capability-acquisition consequence
        self.actions = list(actions or [])

    # ---- credential takeover -------------------------------------------------------
    def can_probe_credential(self) -> bool:
        return self._auth is not None

    def credential_takeover_confirmed(self, victim: str, credential: str) -> Optional[bool]:
        """True iff authenticating AS `victim` with the attacker-chosen `credential` now
        succeeds. `credential` must be attacker-unique so success cannot be coincidental —
        that uniqueness is the deterministic anchor that keeps this FP-safe."""
        if self._auth is None:
            return None
        try:
            return bool(self._auth(victim, credential))
        except Exception:
            return None

    # ---- capability acquisition ----------------------------------------------------
    def can_probe_capability(self) -> bool:
        return self._capability is not None

    def capability_gained(self, actor: str, action_key: str) -> Optional[bool]:
        if self._capability is None:
            return None
        try:
            return bool(self._capability(actor, action_key))
        except Exception:
            return None
