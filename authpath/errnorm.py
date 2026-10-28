"""
PROBLEM 3 — error-semantics normalisation.

Large targets deliberately DECOUPLE the HTTP status code from semantic meaning:
a forbidden-but-existing object may return 404 (to hide existence), an error may
arrive as 200 with an {"error": ...} body, and gateways emit opaque strings like
"Missing Authentication Token" for route-not-matched. ONYX previously judged a
read-back "successful" on any 2xx — which a 200-with-error-body turns into a FALSE
POSITIVE risk.

This module maps (status, body, headers) to ONE canonical Outcome so the confirmer
reasons over MEANING, not raw codes. The cardinal rule: **uncertainty NEVER becomes
AUTHORIZED**. AUTHORIZED is granted only on positive evidence of real object data;
everything ambiguous collapses toward DENIED / ERROR (fail-safe, RL5). It REUSES the
existing block/auth-expiry detectors so there is one source of truth, and it cannot
invent a finding — the Δstate field-equality proof still gates every verdict.
"""
from __future__ import annotations

from enum import Enum


class Outcome(str, Enum):
    AUTHORIZED = "AUTHORIZED"               # genuinely received the object (real data)
    DENIED_AUTHZ = "DENIED_AUTHZ"           # exists but forbidden (incl. 404-as-403)
    NOT_FOUND = "NOT_FOUND"                 # genuinely absent
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED" # missing/expired creds
    CHALLENGE = "CHALLENGE"                 # WAF / bot interstitial
    ERROR = "ERROR"                         # server error / ambiguous


# opaque gateway / framework strings that mean "denied" or "route not matched"
_DENY_MARKERS = (
    "forbidden", "not authorized", "unauthorized", "access denied", "denied",
    "permission denied", "insufficient", "not allowed", "missing authentication token",
    "you don't have permission", "no access", "operation not permitted",
)
_NOTFOUND_MARKERS = ("not found", "does not exist", "no such", "unknown id", "404")


def _flatten_text(obj, depth=0) -> str:
    """Recursively collect message-like strings from nested error structures
    (e.g. GraphQL {"errors":[{"message":"denied"}]}). Bounded depth."""
    if depth > 6:
        return ""
    if isinstance(obj, str):
        return obj.lower()
    if isinstance(obj, dict):
        keys = ("error", "errors", "message", "detail", "title", "code",
                "status", "reason", "description")
        return " ".join(_flatten_text(obj.get(k), depth + 1) for k in keys if k in obj)
    if isinstance(obj, list):
        return " ".join(_flatten_text(x, depth + 1) for x in obj[:20])
    return ""


def _body_text(body) -> str:
    # only inspect typical message/error fields, NOT arbitrary data values, so a
    # legitimate payload whose data merely contains "error" isn't misread.
    # underscores/hyphens -> spaces so snake_case/kebab-case codes ("no_access",
    # "permission-denied") match the markers uniformly.
    return _flatten_text(body).replace("_", " ").replace("-", " ")


_STATUS_KEYS = ("error", "errors", "message", "detail", "code", "status",
                "reason", "title", "type", "timestamp", "path", "ok", "success")


def _has_error_signal(body) -> bool:
    """Any explicit error indicator. The CARDINAL guard: if this is true, the
    response can NEVER be AUTHORIZED, no matter the HTTP status."""
    if not isinstance(body, dict):
        return False
    if body.get("error") or body.get("errors"):
        return True
    if body.get("ok") is False or body.get("success") is False:  # Slack-style 200-error
        return True
    return False


def _is_error_envelope(body) -> bool:
    """Structural error-envelope test: an error signal with no real data payload."""
    if not isinstance(body, dict):
        return False
    if _has_error_signal(body):
        payload_keys = [k for k in body if k not in _STATUS_KEYS]
        return len(payload_keys) == 0
    has_msg = ("message" in body or "detail" in body) and ("code" in body or "status" in body)
    if has_msg:
        payload_keys = [k for k in body if k not in _STATUS_KEYS]
        return len(payload_keys) == 0
    return False


def is_object_payload(body, expected_fields=None) -> bool:
    """Positive evidence that a real object was returned (required for AUTHORIZED).
    An explicit error signal disqualifies AUTHORIZED outright (the cardinal guard)."""
    if not isinstance(body, dict) or not body:
        return False
    if _has_error_signal(body):
        return False                       # ok:false / error:... can never be AUTHORIZED
    if _is_error_envelope(body):
        return False
    if expected_fields:
        return any(f in body for f in expected_fields)
    data_keys = [k for k in body if k not in _STATUS_KEYS]
    return len(data_keys) > 0


def classify_outcome(status: int, body, headers: dict | None = None,
                     expected_fields=None) -> Outcome:
    """Map a raw response to a canonical Outcome. ONE source of truth: reuses the
    block + auth-expiry detectors. Uncertainty never becomes AUTHORIZED."""
    # 1) WAF / bot challenge wins first (must never be read as data)
    try:
        from .transport import detect_block, detect_auth_expiry
        if detect_block(status, body, headers or {}):
            return Outcome.CHALLENGE
        if detect_auth_expiry(status, body):
            return Outcome.NOT_AUTHENTICATED
    except Exception:
        pass

    text = _body_text(body)

    # 2) explicit auth codes
    if status == 401:
        return Outcome.NOT_AUTHENTICATED
    if status == 403:
        return Outcome.DENIED_AUTHZ
    if status in (419, 440):
        return Outcome.NOT_AUTHENTICATED

    # 3) 404 — genuinely absent vs masked deny (disambiguated by caller via context)
    if status == 404:
        # a deny marker inside a 404 body hints at a masked authz denial
        if any(m in text for m in _DENY_MARKERS):
            return Outcome.DENIED_AUTHZ
        return Outcome.NOT_FOUND

    # 4) 2xx — the dangerous case: status says OK, body may say otherwise
    if 200 <= status < 300:
        if _is_error_envelope(body):
            # 200-with-error-body: classify by what the error says, never AUTHORIZED
            if any(m in text for m in _DENY_MARKERS):
                return Outcome.DENIED_AUTHZ
            if any(m in text for m in _NOTFOUND_MARKERS):
                return Outcome.NOT_FOUND
            return Outcome.ERROR
        if is_object_payload(body, expected_fields):
            return Outcome.AUTHORIZED       # positive evidence of real object data
        # 2xx with empty/again-ambiguous body -> NOT a confirmed object read
        return Outcome.ERROR

    # 5) 5xx / everything else -> ambiguous server-side
    if status >= 500:
        return Outcome.ERROR
    return Outcome.ERROR


def disambiguate_attacker_404(attacker_outcome: Outcome,
                              owner_outcome: Outcome) -> Outcome:
    """Context rule (TRAP 1): if the OWNER can read the object (AUTHORIZED) but the
    attacker got NOT_FOUND, the object EXISTS and the attacker's 404 is a masked
    authorization denial — relabel it DENIED_AUTHZ for accurate lead/diagnostic
    signal. This NEVER creates a finding (the attacker still saw no data)."""
    if attacker_outcome is Outcome.NOT_FOUND and owner_outcome is Outcome.AUTHORIZED:
        return Outcome.DENIED_AUTHZ
    return attacker_outcome
