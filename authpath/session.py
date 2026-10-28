"""
Session & liveness manager (deficiency #3 — static identity vs a live auth protocol).
================================================================================
ONYX modelled a principal as a fixed set of headers valid for the whole run. Real
valuable surfaces sit behind OAuth2/OIDC with 5-15 minute tokens, refresh rotation, and
device-bound credentials. Two failures follow:

  * SAFETY-CRITICAL (401 conflation): a bare 401/deny from a DEAD token is indistinguishable
    from a real authorization denial. Treated as a normal deny, a dead-token negative
    masquerades as "access denied = safe" -> a SILENT false negative, and a Δstate
    read-back that fails for authN reasons could corrupt the verdict (threatening zero-FP).
  * A long cross-principal run against a short token simply dies mid-way.

Root fix (not parsing the 401): a NEGATIVE result (a denial / no-leak / "safe") is trusted
ONLY when an independent LIVENESS PROBE proves the principal's credential was live at that
moment. A liveness probe is an authenticated self-read that MUST succeed iff the credential
is live. Dead credential -> the negative is authN-contaminated -> ABSTAIN (never "safe").
This makes 401-conflation impossible BY CONSTRUCTION and is deterministic (a hard pass/fail,
no inference) — so RL1/RL2 and zero-FP are preserved and, in fact, strengthened.

Liveness can be RESTORED, not just detected: an operator-supplied re-auth callback refreshes
a principal's credential when a probe fails, keeping N sessions live across a long run.

Wall: a per-request signature keyed inside an enclave (Entra PoP/TPM, Google JS PoW, mTLS)
cannot be forged by any external tool. Declared attestation-closed -> abstain (or ride a
real client the operator provides). This module makes no authorization decision; it only
answers "is this principal live right now?" and keeps it live where it legitimately can.
"""
from __future__ import annotations
from typing import Optional, Callable, Dict


class SessionManager:
    """Per-principal liveness tracking with optional re-auth. Everything is operator-
    supplied (probers / re-auth), like the auth headers — never fabricated by ONYX."""

    def __init__(self,
                 liveness_prober: Optional[Callable[[str], bool]] = None,
                 reauth: Optional[Callable[[str], Optional[dict]]] = None,
                 attestation_closed: Optional[set] = None):
        # liveness_prober(principal_id) -> True iff an authenticated self-read succeeds now
        self._probe = liveness_prober
        # reauth(principal_id) -> fresh auth headers dict (or truthy) on success, else None
        self._reauth = reauth
        # principals whose surface is device-bound-attested -> permanently un-liveable here
        self.attestation_closed = set(attestation_closed or ())
        self._dead: Dict[str, bool] = {}

    def can_gate(self) -> bool:
        return self._probe is not None

    def is_attestation_closed(self, principal_id: str) -> bool:
        return str(principal_id) in self.attestation_closed

    def ensure_live(self, principal, apply_auth: Optional[Callable[[object, dict], None]] = None) -> str:
        """Classify the principal's credential state right now. Returns:
          * "live"    — an authenticated self-read succeeds WITHOUT re-auth. A negative
                        (401/403) taken with a live credential is a REAL authZ denial ->
                        the caller may trust it.
          * "revived" — the probe failed but a re-auth restored liveness. The response the
                        caller is holding was produced by the DEAD credential, so it is
                        stale -> the caller must ABSTAIN on it and re-issue with fresh creds.
          * "dead"    — not live and not restorable (or attestation-closed). ABSTAIN.
        Deterministic; no 401 parsing."""
        pid = str(getattr(principal, "pid", principal))
        if self.is_attestation_closed(pid):
            return "dead"
        if self._probe is None:
            return "live"                                # no gate configured -> unchanged
        try:
            if self._probe(pid):
                self._dead[pid] = False
                return "live"
        except Exception:
            pass
        if self._reauth is not None:
            try:
                fresh = self._reauth(pid)
                if fresh:
                    if isinstance(fresh, dict) and apply_auth is not None:
                        apply_auth(principal, fresh)
                    if self._probe(pid):
                        self._dead[pid] = False
                        return "revived"
            except Exception:
                pass
        self._dead[pid] = True
        return "dead"

    def is_dead(self, principal_id: str) -> bool:
        return bool(self._dead.get(str(principal_id)))
