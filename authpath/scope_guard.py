"""
⓪ Scope-Guard — §7.5 / RL5.

The highest-cost failure mode for a money-making tool is an out-of-scope action:
program ban = zero income + legal/ethical exposure.  So this gate is fail-safe to
*inaction*: any uncertainty resolves to HALT, never to "act and filter later".

It enforces TECHNICAL scope only.  Legal/policy scope (does this program permit
automated multi-principal replay?) is the tester's responsibility — declared here,
not silently assumed (Honesty Map §6).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from .models import HTTPRequest, ScopeDecision, ScopeVerdict


# Effect-classes whose replay/confirmation could be irreversible. Blocked unless
# the operator explicitly approves (dry-run by default — §7.5).
DESTRUCTIVE_METHODS = {"DELETE"}
DESTRUCTIVE_PATH_HINTS = ("delete", "remove", "cancel", "refund", "payout", "transfer")


@dataclass
class ScopeConfig:
    # Allow-list of host globs the operator is authorised to test. EMPTY = test nothing.
    allowed_hosts: list[str] = field(default_factory=list)
    # Explicit deny always wins over allow.
    denied_hosts: list[str] = field(default_factory=list)
    # Path globs to never touch (e.g. "/admin/shutdown*").
    denied_paths: list[str] = field(default_factory=list)
    # Dry-run blocks any state-changing replay from actually mutating the target.
    dry_run: bool = True
    # Operator must opt in, per run, to allow potentially-irreversible confirmations.
    allow_destructive: bool = False
    # The tester asserts (out-of-band) that the program permits automated replay.
    automation_permitted: bool = False

    # ====================================================================== #
    # TRANSPORT REALISM (obstacles 1-3). Every field below is OPT-IN and
    # defaults to the value that reproduces the ORIGINAL behaviour, so detection
    # logic and determinism are never affected. These shape only HOW/WHEN a live
    # request travels, never WHAT is sent or how a verdict is reached.
    #   · researcher_id / attribution_*  -> declare authorised testing (obstacle 2)
    #   · min_request_interval / jitter / seed -> respect rate limits (obstacle 2)
    #   · proxy                          -> one shared egress for all identities
    #   · session_warmup                 -> session-context before a probe (obstacle 3)
    # (obstacle 1, coherent header profiles, lives on Principal + HTTPTarget.)
    # ====================================================================== #
    # ---- legitimate transport governance (NOT evasion) ---------------------- #
    # Researcher attribution. When set, every live request carries an explicit
    # identifying header so an AUTHORISED program can allow-list / attribute the
    # traffic (e.g. HackerOne handle). This makes the source IP *declared*, not
    # *hidden* — the correct, in-scope way to avoid reputation blocks.
    researcher_id: str = ""
    attribution_header: str = "X-Bug-Bounty"      # program may specify another name
    extra_attribution: dict = field(default_factory=dict)
    # Deterministic rate governor: minimum seconds between live requests. 0 = off
    # (unchanged behaviour). Respects the program's rate limits and removes the
    # machine-gun burst signature WITHOUT touching any detection logic.
    min_request_interval: float = 0.0
    request_jitter: float = 0.0                   # optional +[0,jitter) seconds
    governor_seed: int = 1337                     # SEED so jitter stays reproducible
    attribution_in_ua: bool = False               # also append researcher_id to User-Agent
    # OBSTACLE-3: session-contextual warm-up. Before a live probe, replay up to N
    # of the SAME principal's own captured benign GETs (responses discarded, NO
    # engine state change) so the probe lands inside a plausible session instead of
    # as a cold, context-free hit. 0 = off (unchanged behaviour).
    session_warmup: int = 0
    # OBSTACLE-4a: declarative session-token freshness recipes. Each:
    #   {"principal":"B"|null, "when":"POST /path"|"*",
    #    "source":{"method":"GET","path":"/api/csrf"}, "extract":"csrf",
    #    "inject":{"header":"X-CSRF-Token"} | {"body":"_csrf"} | {"cookie":"csrf"}}
    # EXPLICIT only (never auto-applied); source must be GET. [] = off.
    session_refresh: list = field(default_factory=list)
    # OBSTACLE-6: transport fingerprint. "" = default `requests` (unchanged). A
    # value selects the curl_cffi impersonation backend: "auto" derives the profile
    # from the captured User-Agent (so TLS agrees with UA+headers — no drift), or an
    # explicit profile like "chrome124". Requires curl_cffi when set (loud error if
    # missing — never a silent fallback to a blocked fingerprint).
    tls_impersonate: str = ""
    tls_ua_hint: str = ""                         # captured UA used to resolve "auto"
    # PROBLEM 2: auto-generate the N-principal probe matrix from observed accesses.
    auto_matrix: bool = False
    matrix_max_pairs: int = 500
    # IP-STABILITY INVARIANT: a SINGLE shared proxy for ALL principals, never a
    # per-principal rotation. Empty = direct. Sharing one egress across every
    # identity is a *safety* property: it removes source-IP as a confound so any
    # response delta is attributable to AUTHORISATION, not to a changing IP.
    proxy: str = ""
    # RL20: who designed the target — caps the evidence tier every finding may claim.
    # Default 'self' is the humble, truthful default (a finding on your own proving
    # ground is self-measured, never independent proof). 'third_party' for crAPI/
    # VAmPI/OWASP labs, 'live_bounty' for real software.
    target_provenance: str = "self"


class ScopeGuard:
    """Pure function of (config, request). No state, no learning, no surprises."""

    def __init__(self, config: ScopeConfig):
        self.config = config

    # -- the gate ---------------------------------------------------------- #
    def check(self, req: HTTPRequest) -> ScopeDecision:
        host = (req.host or "").strip().lower()

        # Fail-safe #1: no host, no allow-list, or empty scope ⇒ do nothing.
        if not host:
            return ScopeDecision(ScopeVerdict.HALT, "request has no host — refusing to act", host)
        if not self.config.allowed_hosts:
            return ScopeDecision(ScopeVerdict.HALT, "scope is empty — nothing is in scope by default", host)

        # Explicit deny wins.
        for pat in self.config.denied_hosts:
            if fnmatch.fnmatch(host, pat.lower()):
                return ScopeDecision(ScopeVerdict.HALT, f"host matches deny-list pattern '{pat}'", host)
        for pat in self.config.denied_paths:
            if fnmatch.fnmatch(req.path, pat):
                return ScopeDecision(ScopeVerdict.HALT, f"path matches deny-list pattern '{pat}'", host)

        # Must positively match an allow pattern. No match ⇒ HALT (not "probably fine").
        if not any(fnmatch.fnmatch(host, pat.lower()) for pat in self.config.allowed_hosts):
            return ScopeDecision(ScopeVerdict.HALT, "host is not in the allow-list — uncertainty resolves to inaction", host)

        return ScopeDecision(ScopeVerdict.ALLOW, "host is in authorised scope", host)

    # -- destructive-action gate (used by the confirmer before any mutation) -- #
    def may_mutate(self, req: HTTPRequest) -> ScopeDecision:
        """Confirm-by-Δstate sometimes needs to *re-issue* a state change. This
        gate ensures we never irreversibly act without explicit operator opt-in."""
        decision = self.check(req)
        if decision.verdict is ScopeVerdict.HALT:
            return decision

        risky = (
            req.method.upper() in DESTRUCTIVE_METHODS
            or any(h in req.path.lower() for h in DESTRUCTIVE_PATH_HINTS)
        )
        if risky and not self.config.allow_destructive:
            return ScopeDecision(
                ScopeVerdict.HALT,
                "potentially irreversible action blocked by dry-run (operator approval required)",
                req.host,
            )
        # A GraphQL QUERY is a safe READ even though it travels as POST; only
        # mutations are state-changing. Exempt read-only operations from the
        # dry-run non-idempotent block so read-back confirmation works on GraphQL.
        gql_read = False
        if req.method.upper() == "POST" and req.is_graphql():
            op = req.graphql_op()
            gql_read = op is not None and op.op_type == "query"
        if (self.config.dry_run and req.method.upper() not in ("GET", "HEAD", "OPTIONS")
                and not gql_read):
            return ScopeDecision(
                ScopeVerdict.HALT,
                "dry-run active — non-idempotent replay suppressed; confirming via read-back only",
                req.host,
            )
        return ScopeDecision(ScopeVerdict.ALLOW, "mutation permitted by operator config", req.host)

    def policy_warnings(self) -> list[str]:
        """Surfaced in the dashboard so the operator is never lulled (Honesty Map)."""
        warns: list[str] = []
        if not self.config.automation_permitted:
            warns.append(
                "Program policy on automated multi-principal replay is UNCONFIRMED. "
                "Scope-Guard enforces technical scope only — verify each program's rules."
            )
        if self.config.allow_destructive:
            warns.append("Destructive confirmations are ENABLED — irreversible actions may occur.")
        if not self.config.dry_run:
            warns.append("Dry-run is OFF — state-changing replays will hit the live target.")
        return warns
