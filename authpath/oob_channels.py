"""
⑮ Out-of-Band Channels — confirm effects that never appear in the direct response (Gap G1).

THE PROBLEM THIS CLOSES
-----------------------
Every confirmation today reads the DIRECT response to the mutating request
(`Target.send -> HTTPResponse`). A whole class of second-order authorization
leaks never surfaces there — the effect lands in an EXPORTED FILE (CSV/PDF/JSON),
a WEBHOOK the server calls out to, an EMAIL/notification, or an AUDIT-LOG feed,
usually LATER and ASYNCHRONOUSLY. `authz_drift` names this exact blind spot
(wall #4: "a mutation that never surfaces on the wire is out of scope"). ONYX is
blind to it and abstains, so the entire OOB second-order class scores zero recall.

THE MECHANISM (attack the cause — Anti-Patch #1)
------------------------------------------------
The only thing that makes OOB different from direct read-back is WHERE and WHEN
the effect appears. So the whole class collapses to one abstraction — a Channel:
something you POLL (over a settling window) that yields payloads to seek nonces in.
Direct read-back is just the degenerate synchronous Channel. Everything else
(export file, OAST webhook, mailbox, audit feed) is the same shape.

WHY THIS IS SOUND ONLY ON TOP OF G14 (No-Regression #1)
-------------------------------------------------------
Without a unique minted nonce, "victim data in an export" is un-attributable — it
could be background data, another tester, or a coincidence → an FP factory. G14's
exact-match nonce is what makes OOB safe: an artifact is attributable to THIS test
only if it contains the exact token we minted. G1 reuses `NonceSeeker.seek`
verbatim; it adds no new attribution logic, only new channels to seek in.

ATTRIBUTION ≠ AUTHORIZATION (Anti-Patch #1)
-------------------------------------------
Finding our nonce in an export proves the artifact is OURS (the export we
triggered). It does NOT prove a cross-principal leak. A finding requires BOTH:
  (a) our nonce present  (this artifact is attributable to this test), AND
  (b) a DISCRIMINATING datum provably owned by the VICTIM present in the same
      artifact (the actual cross-principal leak).
Nonce-only → abstain (artifact ours but no leak proven). Victim-datum-only,
no nonce → abstain (cannot attribute to this test).

FP GATE — written before the code (Anti-Patch #2)
-------------------------------------------------
  Q-0  every poll is BOUNDED; on settling-window timeout → abstain (never infer
       a finding from absence, nor from a late partial).
  Q-1  attribution requires an exact full-entropy nonce match (inherited G14 P-1).
  Q-2  a finding requires nonce AND a distinct victim-owned datum in the SAME
       payload; either alone → abstain.
  Q-3  the victim datum must be discriminating (provably the victim's, not a shared
       default or the nonce itself) — the caller reads it from the victim envelope.
  Q-4  default-OFF: no channel is polled unless the engine wires one; with none,
       behavior is byte-identical to before.

I/O INJECTION (No-Regression #4 + stdlib-only discipline)
---------------------------------------------------------
Every channel takes an injected callable (fetch/poll/read). The engine wires the
real I/O (HTTP GET the export, poll the OAST provider, IMAP the mailbox); tests
inject fakes. No network in the module, no new dependencies, fully deterministic,
reversible (delete the file — nothing else calls it).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol, runtime_checkable

from .nonce_provenance import Nonce, NonceSeeker


@dataclass
class OOBResult:
    confirmed: bool
    channel: str
    nonce: Optional[Nonce]
    victim_datum: Optional[str]
    reason: str
    evidence: str = ""   # excerpt of the attributed payload, for the record


@runtime_checkable
class OOBChannel(Protocol):
    """Poll-once contract. `poll_once()` returns the payloads observed SINCE the
    last call (list may be empty). Payloads are anything stringifiable — file text,
    webhook bodies, email sources, audit-feed JSON."""
    name: str
    def poll_once(self) -> list[Any]: ...


# ── Concrete channels: each wraps an injected I/O callable (no network here) ── #

@dataclass
class ExportFileChannel:
    """An exported artifact (CSV/PDF-text/JSON) the tester downloads. `fetch`
    returns the file's text (or None if not ready yet — triggers another poll)."""
    fetch: Callable[[], Optional[Any]]
    name: str = "export"
    def poll_once(self) -> list[Any]:
        payload = self.fetch()
        return [payload] if payload is not None else []


@dataclass
class OASTChannel:
    """Out-of-band application security testing: a webhook/callback the server
    makes to an attacker-controlled URL. `poll` returns interaction payloads seen
    since last poll (e.g., from interactsh/Collaborator). The unique callback URL
    embeds the nonce, so any interaction is attributable."""
    poll: Callable[[], list[Any]]
    name: str = "webhook"
    def poll_once(self) -> list[Any]:
        return list(self.poll() or [])


@dataclass
class MailboxChannel:
    """A tester-controlled mailbox (plus-addressing / catch-all). `read` returns
    message bodies/sources seen since last poll."""
    read: Callable[[], list[Any]]
    name: str = "email"
    def poll_once(self) -> list[Any]:
        return list(self.read() or [])


@dataclass
class AuditFeedChannel:
    """An audit-log / activity feed read back AS THE VICTIM at a DIFFERENT endpoint
    than the mutated one. `fetch` returns the feed payload (or None)."""
    fetch: Callable[[], Optional[Any]]
    name: str = "audit"
    def poll_once(self) -> list[Any]:
        payload = self.fetch()
        return [payload] if payload is not None else []


# ── The unified settling-poll + dual-condition confirmation ── #

def _stringify(x: Any) -> str:
    import json
    if isinstance(x, str):
        return x
    try:
        return json.dumps(x, default=str, sort_keys=True)
    except Exception:
        return str(x)


def _victim_datum_present(payload: Any, victim_datum: str, nonce: Nonce) -> bool:
    """Q-2/Q-3: the victim's discriminating datum appears, and it is neither empty
    nor the nonce itself (which would be circular)."""
    vd = (victim_datum or "").strip()
    if not vd or vd == nonce.value or vd in nonce.value:
        return False
    return vd in _stringify(payload)


def confirm_oob_leak(*, channel: OOBChannel, seeker: NonceSeeker, planted: Nonce,
                     victim_datum: Optional[str], attempts: int = 5,
                     interval_s: float = 0.0,
                     sleep: Callable[[float], None] | None = None) -> OOBResult:
    """Poll `channel` up to `attempts` times over a settling window. A finding is
    returned ONLY when a single payload contains BOTH the planted nonce (Q-1) AND a
    distinct victim-owned datum (Q-2/Q-3). Timeout → abstain (Q-0).

    `interval_s`/`sleep` model the settling wait; tests pass interval_s=0 (no wait).
    """
    if sleep is None:
        import time as _t
        sleep = _t.sleep

    saw_nonce_without_leak = False
    for i in range(max(1, attempts)):
        for payload in channel.poll_once():
            hit = seeker.seek(payload, channel=channel.name)
            if hit is None:
                continue  # not our artifact — ignore (never attribute foreign data)
            # our nonce is here → artifact attributable to THIS test
            if victim_datum and _victim_datum_present(payload, victim_datum, planted):
                excerpt = _stringify(payload)
                excerpt = excerpt[:240] + ("…" if len(excerpt) > 240 else "")
                return OOBResult(True, channel.name, planted, victim_datum,
                                 f"cross-principal leak attributed by nonce in {channel.name} "
                                 f"channel AND victim datum present", excerpt)
            saw_nonce_without_leak = True
            # keep polling: a later payload in the window might carry the leak
        if i < attempts - 1:
            sleep(interval_s)

    if saw_nonce_without_leak:
        return OOBResult(False, channel.name, planted, victim_datum,
                         "artifact attributed to this test, but no cross-principal "
                         "victim datum found in it — abstain (attribution ≠ leak)")
    return OOBResult(False, channel.name, planted, victim_datum,
                     "no attributed artifact within the settling window — abstain")
