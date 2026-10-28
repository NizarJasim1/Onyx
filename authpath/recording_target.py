"""
RecordingTarget — transparent transcript capture for certificate wiring (ASSURANCE-2).
=====================================================================================

The certifying-algorithm layer needs the RAW transcript behind a finding. Some
findings are confirmed via the confirmer's own internal read-back probes, which the
engine's own `capture` does not see. Rather than modify the confirmer to expose those
probes (which would touch decision code), this wraps the TARGET: a transparent proxy
that records every request/response passing through it — including the confirmer's
internal probes, since the confirmer calls `self.target.send(...)`.

RED LINES — additive and decision-free:
* Zero changes to confirmer/engine/decision code. This is a NEW wrapper the caller
  opts into by wrapping their target before constructing the engine.
* Purely record-only: `send` delegates to the inner target and returns its response
  UNCHANGED; it only appends a copy of the exchange. It changes no decision, no state,
  no ordering. Wrapping the target cannot alter what ONYX confirms (provable by
  running the full suite with a wrapped target — behaviour is identical).
* Everything else is proxied to the inner target, so the wrapper is behaviourally
  transparent.

HONEST BOUNDARY: capturing an exchange does not make it certifiable. A finding
certifies only when its raw transcript exhibits the definitional violation (owner's
private value in the attacker's response, or an owner-confirmed Δstate). On a REAL
target a BOLA read returns the owner's data in the attacker's response, so it
certifies from the recording; on soft-deny mock targets (a testing artifact) the leak
is not raw-visible and the certificate layer abstains — correctly, per its coverage
boundary. RecordingTarget provides the transcript; the checker still decides honestly.
"""

from __future__ import annotations


def _as_dict_request(req):
    return {"method": getattr(req, "method", None),
            "path": getattr(req, "path", None),
            "host": getattr(req, "host", None),
            "body": getattr(req, "body", None)}


def _as_dict_response(resp):
    return {"status": getattr(resp, "status", None),
            "body": getattr(resp, "body", None)}


class RecordingTarget:
    """Wrap a target; record every exchange (incl. the confirmer's internal probes).
    Behaviourally transparent — delegates send() and proxies all other attributes."""

    def __init__(self, inner):
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "exchanges", [])

    def send(self, req, principal):
        resp = self._inner.send(req, principal)          # unchanged delegation
        try:
            self.exchanges.append({
                "principal": getattr(principal, "pid", principal),
                "request": _as_dict_request(req),
                "response": _as_dict_response(resp),
            })
        except Exception:
            pass                                          # recording must never affect behaviour
        return resp

    # Transparent proxy for everything else (host, and any other target surface).
    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_inner"), name)


def find_exchange(recording: "RecordingTarget", principal: str, resource_substr: str,
                  want_2xx: bool = True):
    """Return the last recorded exchange by `principal` whose request path contains
    `resource_substr` (optionally requiring a 2xx response), or None."""
    hit = None
    for e in recording.exchanges:
        if e["principal"] != principal:
            continue
        if resource_substr and str(resource_substr) not in str(e["request"].get("path") or ""):
            continue
        if want_2xx:
            st = e["response"].get("status") or 0
            if not (200 <= int(st) < 300):
                continue
        hit = e
    return hit


def certificate_for_finding(finding, recording: "RecordingTarget", *, sensitive_field: str,
                            kind=None, provenance: str = "unknown"):
    """Build a certificate for a finding purely from the RECORDED transcript (no
    manual exchange tracking). Returns the certificate dict, or None if the recording
    lacks the exchanges needed. Requires the certificate module."""
    from authpath import certificate as C
    res = getattr(finding, "resource_ref", "")
    attacker = getattr(finding, "actor_pid", "")
    sp = getattr(finding, "state_proof", None)
    owner = getattr(sp, "read_as", "") if sp else ""
    atk = find_exchange(recording, attacker, res, want_2xx=True)
    own = find_exchange(recording, owner, res, want_2xx=True)
    if atk is None or own is None:
        return None
    return C.certificate_from_finding(
        finding, attacker_exchange=atk, owner_view={"response": own["response"]},
        sensitive_field=sensitive_field, kind=kind or C.KIND_READ_LEAK, provenance=provenance)
