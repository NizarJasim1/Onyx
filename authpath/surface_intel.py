"""
TRACK 1 — strategic surface intelligence (read-only).

Five first-principles deep-dive sessions established a durable principle: cryptographic
protections (DPoP, mTLS, device attestation) secure the AUTHENTICATION layer; they are
blind to the AUTHORIZATION-semantics layer that ONYX hunts. The consequences for where
ONYX can win:

  * an UNBOUND bearer-token API surface (RFC 6750; ~70%+ of web APIs) is a perfect
    ONYX arena — the token is portable, there is no behavioural signal on the API
    channel, and BOLA lives in the semantic layer no edge defence can see;
  * a surface that binds the token (DPoP/mTLS) or attests every request
    (per-request Play Integrity / App Attest) is structurally out of replay reach —
    ONYX cannot sign a proof for a key it does not control.

This module is a READ-ONLY diagnostic. It classifies a target on that axis and emits
an HONEST verdict + recommended action so the operator points ONYX where it can win
and does not burn effort on an attested surface. It NEVER changes a finding verdict —
it is imported nowhere in the decision path. A verdict of ARENA means the semantic
layer is REACHABLE; it explicitly does NOT claim a vulnerability exists.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class Reach(str, Enum):
    ARENA = "ARENA"               # semantic authz layer reachable — ONYX's strong ground
    PARTIAL = "PARTIAL"           # reachable but with friction (some binding/challenge)
    OUT_OF_REACH = "OUT_OF_REACH" # token bound / per-request attested — not replay-reachable


@dataclass
class SurfaceVerdict:
    reach: Reach
    token_binding: str            # "bearer" | "dpop" | "mtls" | "attested" | "unknown"
    channel: str                  # "api" | "browser"
    reasons: list = field(default_factory=list)
    recommendation: str = ""
    caveat: str = ("ARENA means the semantic-authorization layer is REACHABLE; it does "
                   "NOT claim a vulnerability exists. Confirmation is still by Δstate.")


# positive binding signals (only these flip a surface to bound — conservative)
_DPOP_MARKERS = ("dpop",)
_MTLS_MARKERS = ("mtls", "mutual tls", "certificate required", "client certificate",
                 "ssl_client", "x-client-cert")
_ATTEST_MARKERS = ("play integrity", "app attest", "attestation", "devicecheck",
                   "integrity token", "x-attestation")


def _hay(headers: dict | None, body) -> str:
    parts = []
    for k, v in (headers or {}).items():
        parts.append(f"{k}: {v}")
    if isinstance(body, dict):
        parts.append(" ".join(f"{k}={v}" for k, v in body.items()))
    elif isinstance(body, str):
        parts.append(body)
    return " ".join(parts).lower()


def _jwt_is_bound(token: str) -> bool:
    """A DPoP/PoP-bound JWT carries a cnf/jkt confirmation claim."""
    try:
        import base64 as b64, json
        parts = token.split(".")
        if len(parts) < 2:
            return False
        pad = "=" * (-len(parts[1]) % 4)
        payload = json.loads(b64.urlsafe_b64decode(parts[1] + pad))
        return "cnf" in payload and ("jkt" in payload.get("cnf", {}) or payload.get("cnf"))
    except Exception:
        return False


def classify_surface(*, request_headers: dict | None = None,
                     response_headers: dict | None = None,
                     response_body=None,
                     content_type: str = "",
                     probe_portable: bool | None = None) -> SurfaceVerdict:
    """Classify a surface from capture/probe signals. CONSERVATIVE: only a POSITIVE
    binding signal flips it to bound; otherwise bearer/ARENA is the prior (70%+)."""
    reasons = []
    req_hay = _hay(request_headers, None)
    resp_hay = _hay(response_headers, response_body)

    # --- token binding -------------------------------------------------- #
    binding = "bearer"
    authz = ""
    for k, v in (request_headers or {}).items():
        if k.lower() == "authorization":
            authz = str(v)
    if any(m in req_hay or m in resp_hay for m in _DPOP_MARKERS) or authz.lower().startswith("dpop"):
        binding = "dpop"; reasons.append("DPoP marker present (token is key-bound)")
    elif any(m in resp_hay for m in _MTLS_MARKERS):
        binding = "mtls"; reasons.append("mTLS / client-certificate requirement detected")
    elif any(m in resp_hay or m in req_hay for m in _ATTEST_MARKERS):
        binding = "attested"; reasons.append("device-attestation marker (per-request integrity)")
    elif authz.lower().startswith("bearer"):
        tok = authz.split(None, 1)[1] if " " in authz else ""
        if _jwt_is_bound(tok):
            binding = "dpop"; reasons.append("access token carries a cnf/jkt binding claim")
        else:
            reasons.append("bearer token, no binding signal (portable)")
    else:
        binding = "unknown"; reasons.append("no explicit auth signal; assuming portable bearer (prior)")

    # --- channel -------------------------------------------------------- #
    ct = (content_type or "").lower()
    if not ct and isinstance(response_body, dict):
        ct = "application/json"
    if "html" in ct or "text/html" in resp_hay:
        channel = "browser"; reasons.append("HTML channel — behavioural signal surface")
    else:
        channel = "api"; reasons.append("API/JSON channel — no behavioural signal (RFC-6750-style)")

    # --- portability override (strongest signal if measured) ------------ #
    if probe_portable is False:
        reasons.append("captured token was REJECTED outside the original context (bound)")
        if binding == "bearer":
            binding = "dpop"
    elif probe_portable is True:
        reasons.append("captured token WORKED from outside the browser (portable)")

    # --- verdict -------------------------------------------------------- #
    if binding in ("dpop", "mtls", "attested"):
        reach = Reach.OUT_OF_REACH
        rec = (f"Token is {binding}-bound. ONYX cannot replay-sign each request "
               f"(the private key is not ours). Honest limit: this core is out of "
               f"reach for token-acquisition. Target unbound bearer surfaces instead.")
    elif channel == "browser":
        reach = Reach.PARTIAL
        rec = ("HTML/behavioural surface. Acquire a session via your own browser "
               "(human login), then point ONYX at the JSON/API endpoints behind it.")
    else:
        reach = Reach.ARENA
        rec = ("Unbound bearer API surface — ONYX's strong ground. Run discovery + the "
               "N-principal/id-format/action/nested-ref matrices; Δstate confirms.")

    return SurfaceVerdict(reach=reach, token_binding=binding, channel=channel,
                          reasons=reasons, recommendation=rec)


def report(verdict: SurfaceVerdict) -> dict:
    return {
        "reach": verdict.reach.value,
        "token_binding": verdict.token_binding,
        "channel": verdict.channel,
        "reasons": verdict.reasons,
        "recommendation": verdict.recommendation,
        "caveat": verdict.caveat,
    }
