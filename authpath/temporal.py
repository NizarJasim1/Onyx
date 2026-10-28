"""
Temporal Authorization Drift (dev session — stateful angle).

The angle no single-request tool can see: authorization is not a fixed value, it
is a function of TIME. A credential that is legitimately valid at T0 must become
invalid after a REVOCATION EVENT at T1 (password change, logout, member removal,
role downgrade, invite revocation, subscription end). The vulnerability — proven
by real CVEs (CVE-2024-21635 Memos, CVE-2014-7851 oVirt, openEclass GHSA) — is
that the system mutates account state but never invalidates the OLD credential,
so a request at T2 with the stale credential still reaches private state.

Why tools miss it: Burp Autorize / nuclei are STATELESS — they compare two
sessions at one instant. They have no notion of "before vs after an event across
time". ONYX captures ordered traffic, so it can build an AUTHORITY LIFECYCLE
LEDGER and detect drift systematically across every credential + every
revocation event at once — not one hand-tested logout/replay.

RL-compliance:
  * Detection is ANALYSIS of captured, ordered traffic — never payload crafting.
  * A revocation event is recognised heuristically AND/OR declared in the
    contract (contract is authoritative, heuristic only seeds — RL2).
  * Confirmation is by Δstate (RL3): the stale credential must still reproduce
    SUBSTANTIVE private data after the event — a bare 200/length diff is never a
    finding. The recorded revocation event proves the credential *should* be dead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
# Revocation-event recognition (heuristic; contract overrides/confirms)        #
# --------------------------------------------------------------------------- #
# (method-regex, path-regex, kind). method "" means any. Conservative: these
# describe actions that, by definition, SHOULD invalidate prior credentials.
_REVOCATION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("",      re.compile(r"(?:^|/)(?:change[-_]?password|reset[-_]?password|"
                         r"update[-_]?password|new[-_]?password)(?:$|/|\?)", re.I), "password_change"),
    ("",      re.compile(r"(?:^|/)(?:logout|signout|sign[-_]?out|sessions?/(?:end|destroy))(?:$|/|\?)", re.I), "logout"),
    ("POST",  re.compile(r"(?:^|/)(?:revoke|deauthorize|disable[-_]?token)(?:$|/|\?)", re.I), "token_revoke"),
    ("DELETE", re.compile(r"(?:^|/)(?:sessions?|tokens?|api[-_]?keys?)(?:/|$)", re.I), "session_delete"),
    ("DELETE", re.compile(r"(?:^|/)(?:members?|collaborators?|users?|invites?|access)/", re.I), "member_removal"),
    ("",      re.compile(r"(?:^|/)(?:deactivate|suspend|ban|disable[-_]?account)(?:$|/|\?)", re.I), "account_disable"),
]


def looks_like_revocation(method: str, path: str) -> str | None:
    """Heuristic recognition of a revocation event from method+path. Returns the
    kind, or None. Conservative — only well-known revocation shapes match."""
    m = (method or "").upper()
    for mm, rx, kind in _REVOCATION_PATTERNS:
        if mm and mm != m:
            continue
        if rx.search(path or ""):
            return kind
    return None


def credential_of(request, principal=None) -> str | None:
    """The raw credential that identifies a session/token — what must die after a
    revocation event. Order: request Authorization, request Cookie, then the
    principal's configured auth header, then a principal-id fallback. Returns a
    stable fingerprint (not the secret) so the ledger never stores raw secrets.

    The principal fallback matters because in ONYX the auth often lives on the
    Principal (applied by the transport) rather than on each captured request."""
    headers = request.headers or {}
    for k, v in headers.items():
        if k.lower() == "authorization" and v:
            return f"auth:{str(v)[-16:]}"
    for k, v in headers.items():
        if k.lower() == "cookie" and v:
            return f"cookie:{str(v)[:48]}"
    if principal is not None:
        pauth = getattr(principal, "auth", None) or {}
        for k, v in pauth.items():
            if k.lower() == "authorization" and v:
                return f"auth:{str(v)[-16:]}"
            if k.lower() == "cookie" and v:
                return f"cookie:{str(v)[:48]}"
        if getattr(principal, "pid", None):
            return f"pid:{principal.pid}"
    return None


@dataclass
class LifecycleEvent:
    seq: int
    pid: str
    credential: str | None
    endpoint: str
    method: str
    path: str
    ok: bool
    is_revocation: bool
    revocation_kind: str | None
    # for declared events: which principal(s)/credential(s) this invalidates
    invalidates_pids: tuple = ()
    invalidates_creds: tuple = ()


@dataclass
class RevocationHit:
    """A revocation event that should have invalidated the current credential."""
    event: LifecycleEvent
    basis: str          # "contract" | "heuristic-same-principal" | "heuristic-same-credential"


class LifecycleLedger:
    """Ordered, cross-request ledger of credential lifecycle events. Bounded by
    #events, not payload size. Pure bookkeeping — no verdicts here."""

    def __init__(self, declared: list[dict] | None = None):
        self.events: list[LifecycleEvent] = []
        # contract-declared revocation events: list of
        #   {"endpoint": "POST /api/change-password",
        #    "invalidates_principals": ["A_stale"], "invalidates_credentials": [...]}
        self.declared = declared or []
        self._declared_by_endpoint = {}
        for d in self.declared:
            ep = d.get("endpoint")
            if ep:
                self._declared_by_endpoint[ep] = d

    def record(self, seq: int, request, response, pid: str, principal=None) -> LifecycleEvent:
        endpoint = request.endpoint_key()
        ok = 200 <= response.status < 300
        decl = self._declared_by_endpoint.get(endpoint)
        heur = looks_like_revocation(request.method, request.path)
        is_rev = bool(decl) or bool(heur)
        inv_pids = tuple(decl.get("invalidates_principals", [])) if decl else ()
        inv_creds = tuple(decl.get("invalidates_credentials", [])) if decl else ()
        ev = LifecycleEvent(
            seq=seq, pid=pid, credential=credential_of(request, principal),
            endpoint=endpoint, method=request.method.upper(), path=request.path,
            ok=ok, is_revocation=is_rev,
            revocation_kind=(decl.get("kind") if decl else heur),
            invalidates_pids=inv_pids, invalidates_creds=inv_creds,
        )
        self.events.append(ev)
        return ev

    def revocation_before(self, pid: str, credential: str | None,
                          seq: int) -> RevocationHit | None:
        """Find the earliest SUCCESSFUL revocation event, before `seq`, that
        should have invalidated this (pid, credential).

        Matching basis, in order of confidence:
          1. contract: event explicitly lists this pid or credential as invalidated
          2. heuristic + same credential: a revocation event carried out on the
             very same credential (e.g. password change while holding token X)
          3. heuristic + same principal: a revocation event by the same principal
        Only SUCCESSFUL (2xx) revocation events count — a failed password change
        revokes nothing."""
        best: RevocationHit | None = None
        for ev in self.events:
            if ev.seq >= seq or not ev.is_revocation or not ev.ok:
                continue
            basis = None
            if pid and pid in ev.invalidates_pids:
                basis = "contract"
            elif credential and credential in ev.invalidates_creds:
                basis = "contract"
            elif credential and ev.credential and credential == ev.credential:
                basis = "heuristic-same-credential"
            elif pid and ev.pid == pid:
                basis = "heuristic-same-principal"
            if basis is None:
                continue
            if best is None or ev.seq < best.event.seq:
                best = RevocationHit(ev, basis)
        return best
