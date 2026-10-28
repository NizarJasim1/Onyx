"""
⑲ Idempotency-key replay drift (Gap G7) — pure logic.

Replaying an idempotency key across a re-pointed reference can re-apply an effect to
a drifted object. Confirm ONLY via an attributed read-back (G14 nonce) as the victim,
never from the replay response. Correct idempotency (same response, no new persisted
effect) is NOT a bug => abstain.

FP gate: ID-0 requires a real idempotency key => else abstain; ID-1 confirm via
attributed read-back, not the replay response; ID-2 no new persisted attributed
effect => abstain (correct idempotency); ID-3 default-OFF.
"""
from __future__ import annotations
from typing import Optional

_IDEMPOTENCY_HEADERS = ("idempotency-key", "x-idempotency-key", "idempotency-id",
                        "x-idempotency-id", "idempotence-key")


def extract_idempotency_key(headers) -> Optional[tuple]:
    if not headers:
        return None
    for k, v in headers.items():
        if k.lower() in _IDEMPOTENCY_HEADERS and v:
            return (k, v)
    return None


def replay_drift_confirmed(*, original_headers, seeker, planted, readback_as_victim,
                           cross_principal_ok):
    """Confirm an idempotency-replay drift ONLY when the planted nonce appears in the
    victim's read-back (a re-applied cross-object effect) AND cross_principal_ok.
    Returns an AttributionResult, or None when there is no idempotency key (ID-0)."""
    if extract_idempotency_key(original_headers) is None:
        return None                                     # ID-0
    from .nonce_provenance import attributed_stick_check
    return attributed_stick_check(seeker=seeker, planted=planted,
                                  readback_body=readback_as_victim,
                                  cross_principal_ok=cross_principal_ok)   # ID-1/ID-2
