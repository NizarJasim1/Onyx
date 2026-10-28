"""
Autorize-equivalent baseline (P2) — a faithful reimplementation of the DOCUMENTED
detection algorithm, used ONLY to compare against, never in ONYX's detection path.
=================================================================================

This is NOT the Burp extension; it is the published Autorize *algorithm* (PortSwigger
BApp Store / project README): replay a request under a different identity and decide
whether authorization was enforced from the **status code, an enforcement
fingerprint in the body, and the content-length relative to the original** response.
Autorize itself warns that a "Bypassed!" result is a *candidate*, not a confirmed
vulnerability, and that without a well-configured enforcement detector it produces
false positives.

To keep the comparison honest (no strawman) this baseline is given FULL strength:
- a realistic, pre-configured enforcement-fingerprint list (what an expert tester
  would set),
- the owner's original (high-privilege) response as the length reference,
- the exact three-signal logic Autorize documents.

A dedicated test (`test_baseline.py`) asserts this baseline actually CATCHES the
true positives (non-zero recall on real BOLA) before any precision number is read —
so a low precision can never be an artefact of a crippled baseline.
"""

from __future__ import annotations

from typing import Optional


# An expert-configured enforcement-detector fingerprint set (full strength).
ENFORCEMENT_FINGERPRINTS = (
    "forbidden", "unauthorized", "not authorized", "access denied",
    "permission denied", "not allowed", "must be an admin", "insufficient",
    "you do not have", "no permission",
)

# Status codes that, on their own, indicate enforcement.
_ENFORCED_STATUS = {401, 403, 407}

# Content-length ratio beyond which the attacker response is treated as "different"
# from the owner reference (Autorize's length-diff discriminator).
_LEN_RATIO = 0.5


def _body_text(resp) -> str:
    b = getattr(resp, "body", None)
    if b is None:
        return ""
    if isinstance(b, str):
        return b.lower()
    return str(b).lower()


def _content_length(resp) -> int:
    return len(_body_text(resp))


class AutorizeBaseline:
    """The documented Autorize enforcement detector, at full strength. `predict`
    returns 'bypassed' (Autorize would flag this as a possible vuln) or 'enforced'
    (Autorize would mark it green)."""

    def __init__(self, fingerprints=ENFORCEMENT_FINGERPRINTS):
        self.fingerprints = tuple(f.lower() for f in fingerprints)

    def predict(self, attack_resp, owner_ref: Optional[object] = None) -> str:
        status = int(getattr(attack_resp, "status", 0) or 0)

        # Signal 1 — an enforcement status code.
        if status in _ENFORCED_STATUS:
            return "enforced"

        # Signal 2 — an enforcement fingerprint in the response body.
        text = _body_text(attack_resp)
        if any(fp in text for fp in self.fingerprints):
            return "enforced"

        # Signal 3 — content-length materially different from the owner's original
        # (Autorize's length discriminator). Only usable when a reference exists.
        if owner_ref is not None:
            a, o = _content_length(attack_resp), _content_length(owner_ref)
            if o > 0 and (a == 0 or abs(a - o) / max(o, 1) > _LEN_RATIO):
                return "enforced"

        # No enforcement signal on a non-error response -> Autorize: "Bypassed!".
        # (This is precisely where a benign 200 / soft-deny becomes a false positive.)
        if 200 <= status < 400:
            return "bypassed"
        return "enforced"   # other errors (404/5xx) are not an access bypass

    def predicts_finding(self, attack_resp, owner_ref=None) -> bool:
        return self.predict(attack_resp, owner_ref) == "bypassed"
