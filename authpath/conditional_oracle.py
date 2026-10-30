"""
⑯ Conditional-Request Oracle (ETag / If-Match) — deterministic drift-window detector (Gap G2).

THE PROBLEM THIS CLOSES
-----------------------
Object-binding drift (TOCTOU-of-authorization) needs a way to know, deterministically,
that an object's version/binding CHANGED between the check and the commit. Today ONYX
has no conditional-request instrument, so it abstains on drift it cannot otherwise
observe, and it can only guess at whether a re-bind window fired.

THE MECHANISM (attack the cause — Anti-Patch #1)
------------------------------------------------
HTTP gives us a server-authoritative, binary signal for free. Per RFC 7232 §6, a
server receiving an `If-Match` whose condition is false MUST answer 412 (Precondition
Failed). So: capture the object's strong ETag at CHECK time, replay the mutating
request with `If-Match: <etag>` at COMMIT time, and read the status:

  412  → the object's version changed between read and write — the re-bind/TOCTOU
         window FIRED. This is deterministic and needs no response-diff heuristic.
  2xx  → the write applied against exactly the version we read.
  else → indeterminate → abstain.

This is the cleanest signal in the whole gap catalog: a single header turns the
server itself into the oracle.

OBSERVATION ≠ FINDING (Anti-Patch #1, separation of concerns)
-------------------------------------------------------------
A 412 proves "version changed", NOT "cross-principal authorization was violated".
The oracle is an INSTRUMENT that detects the window fired; a FINDING still requires
a Δstate read-back proving the effect landed on the victim's object. Same discipline
as G14 (attribution) and G1 (OOB): mechanism-fired ≠ authz-broken.

THREE CORRECTNESS RULES (No-Regression #1 — never emit an unreliable signal)
---------------------------------------------------------------------------
  1. WEAK ETag (`W/"..."`): RFC 7232 §3.1 requires the STRONG comparison function
     for If-Match. A weak validator is unreliable here → do NOT use it for If-Match;
     fall back to an explicit version field or abstain.
  2. FRONTING PROXY: AWS ALB / some CDNs emit SPURIOUS 412s on If-Match even when
     the backend committed. If a proxy is suspected, a 412 alone is INDETERMINATE
     and must be corroborated by a direct Δstate read-back — never confirmed on
     status alone.
  3. NO WILDCARD: `If-Match: *` matches any current representation and defeats the
     precondition. Only the EXACT captured strong ETag is used.

FP GATE — written before the code (Anti-Patch #2)
-------------------------------------------------
  E-0  a usable STRONG validator (ETag or explicit version) must exist → else abstain.
  E-1  If-Match carries the exact captured strong ETag; never `*`, never a guess.
  E-2  a 412 is an OBSERVATION, not a finding.
  E-3  proxy suspected ⇒ 412 is INDETERMINATE ⇒ require read-back corroboration.
  E-4  a finding requires VERSION_CHANGED **and** a cross-principal read-back
       (supplied by the caller); either alone ⇒ abstain.
  E-5  default-OFF: nothing calls this unless the engine wires it ⇒ byte-identical.

Deterministic, stdlib-only, no model, reversible (delete the file).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .models import HTTPRequest, HTTPResponse


@dataclass(frozen=True)
class ETag:
    raw: str        # e.g. '"abc123"' or 'W/"abc123"'
    weak: bool
    @property
    def strong(self) -> bool:
        return not self.weak


def parse_etag(headers: dict[str, str] | None) -> Optional[ETag]:
    """Extract an ETag from response headers (case-insensitive). Distinguishes the
    weak validator (W/ prefix) so callers never use it for If-Match."""
    if not headers:
        return None
    val = None
    for k, v in headers.items():
        if k.lower() == "etag" and v:
            val = v.strip()
            break
    if not val:
        return None
    weak = val.startswith("W/") or val.startswith("w/")
    return ETag(raw=val, weak=weak)


def build_if_match(req: HTTPRequest, etag: ETag) -> Optional[HTTPRequest]:
    """Return a COPY of `req` carrying `If-Match: <strong-etag>`. Refuses weak
    validators (E-1 / rule 1) → None, so the caller abstains rather than emit an
    unreliable conditional write."""
    if not etag.strong:
        return None
    new_headers = dict(req.headers or {})
    new_headers["If-Match"] = etag.raw
    return HTTPRequest(method=req.method, path=req.path, host=getattr(req, "host", ""),
                       body=getattr(req, "body", None), headers=new_headers)


class Verdict(str, Enum):
    VERSION_CHANGED = "version_changed"            # 412 — window fired (needs read-back)
    APPLIED_ON_READ_VERSION = "applied"            # 2xx — write hit the version we read
    INDETERMINATE = "indeterminate"                # proxy-suspect 412 / other / opaque → abstain
    NO_VALIDATOR = "no_validator"                  # E-0 — cannot run the oracle → abstain


def interpret(resp: Optional[HTTPResponse], *, proxy_suspected: bool = False) -> Verdict:
    """Map a conditional-write response to a deterministic verdict."""
    if resp is None:
        return Verdict.INDETERMINATE
    status = getattr(resp, "status", 0)
    if status == 412:
        # E-3: a fronting proxy can fake a 412 → don't trust status alone.
        return Verdict.INDETERMINATE if proxy_suspected else Verdict.VERSION_CHANGED
    if 200 <= status < 300:
        return Verdict.APPLIED_ON_READ_VERSION
    return Verdict.INDETERMINATE


@dataclass
class OracleResult:
    confirmed: bool
    verdict: Verdict
    reason: str
    etag: Optional[ETag] = None


PROXY_HINT_HEADERS = ("x-amzn-trace-id", "x-amz-cf-id", "via", "cf-ray", "x-cache")


def proxy_suspected_from(headers: dict[str, str] | None) -> bool:
    """Heuristic proxy detection (routing only — never a security verdict). Presence
    of a known fronting-proxy header means a 412 must be corroborated (E-3)."""
    if not headers:
        return False
    lk = {k.lower() for k in headers}
    return any(h in lk for h in PROXY_HINT_HEADERS)


def conditional_drift_confirmed(*, check_response: Optional[HTTPResponse],
                                commit_request: HTTPRequest,
                                send,  # Callable[[HTTPRequest], Optional[HTTPResponse]]
                                cross_principal_readback_ok: bool,
                                version_field: Optional[str] = None) -> OracleResult:
    """Full oracle run with the FP gate enforced.

    Steps:
      1. capture a STRONG validator from `check_response` (ETag, else `version_field`
         from the body) — E-0.
      2. issue the commit with `If-Match: <etag>` (E-1) via `send`.
      3. interpret the status (E-2/E-3).
      4. a finding requires VERSION_CHANGED **and** cross_principal_readback_ok (E-4);
         otherwise abstain with a precise reason.
    """
    etag = parse_etag(getattr(check_response, "headers", None))

    # E-0: need a strong validator. Fall back to an explicit body version field.
    if etag is None or etag.weak:
        body = getattr(check_response, "body", None)
        has_version = bool(version_field and isinstance(body, dict) and version_field in body)
        if not has_version:
            why = ("weak ETag — unusable for If-Match, no version field either"
                   if (etag and etag.weak) else "no ETag/version validator on the object")
            return OracleResult(False, Verdict.NO_VALIDATOR,
                                f"cannot run conditional oracle: {why} — abstain", etag)
        # A body version field is a usable strong-ish validator; emulate If-Match by
        # sending the commit and letting the server reject on version mismatch.
        cond_req = commit_request
    else:
        cond_req = build_if_match(commit_request, etag)
        if cond_req is None:  # defensive: weak slipped through
            return OracleResult(False, Verdict.NO_VALIDATOR,
                                "weak validator rejected for If-Match — abstain", etag)

    resp = send(cond_req)
    proxy = proxy_suspected_from(getattr(resp, "headers", None)) or \
            proxy_suspected_from(getattr(check_response, "headers", None))
    verdict = interpret(resp, proxy_suspected=proxy)

    if verdict is not Verdict.VERSION_CHANGED:
        return OracleResult(False, verdict,
                            f"no confirmable drift window ({verdict.value}) — abstain", etag)
    # E-4: the window fired; a finding still needs the cross-principal read-back.
    if not cross_principal_readback_ok:
        return OracleResult(False, verdict,
                            "version changed (window fired) but cross-principal effect "
                            "unproven — abstain (observation ≠ finding)", etag)
    return OracleResult(True, verdict,
                        "re-bind window fired (412/If-Match) AND cross-principal Δstate "
                        "confirmed — object-binding drift proven", etag)
