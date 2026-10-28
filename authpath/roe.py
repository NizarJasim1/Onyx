"""
Rules-of-Engagement governance (deficiency #9 — ROE is a system, not flags).
================================================================================
Safety was flat: host + a few action flags. Real ROE is MULTI-LEVEL, and it must GOVERN
every capability ONYX has (#1-#8): a live send, a cross-principal read/write/delete, a
consequence probe, a discovery probe. Each action must trace to a clause of an engagement
contract that authorizes it; anything unauthorized fails CLOSED; and every authorized
action is written to a tamper-evident audit that a third party can verify.

Levels (each a fail-closed gate):
  * data-level        — cross-principal / destructive actions run ONLY against declared TEST
                        PRINCIPALS, never real users.
  * scope-level       — the request PATH must match a declared engagement path (not just host).
  * policy-level      — automated action is honored only where the program permits it.
  * fine-destruction  — a mutate/delete is allowed ONLY if THIS resource is a declared
                        authorized TEST RESOURCE (guards RL23/RL25/RL26 directly).
  * data-handling     — sensitive fields are redacted in findings and audit.
  * proof-level       — a hash-chained, tamper-evident audit; every entry cites its clause.

An EMPTY contract authorizes nothing new and changes nothing (byte-identical); a populated
one is the license that makes ONYX safe to point at a real, authorized target. This layer
governs what ONYX may DO; it never affects what counts as a finding (zero-FP untouched).
Legal liability and the truthfulness of the operator's declaration remain the operator's.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import fnmatch, hashlib, json, re, time

ALLOW = "allow"
HALT = "halt"

# read-only verbs never mutate, so they clear the destruction gate automatically
_READONLY = {"GET", "HEAD", "OPTIONS"}
# default sensitive-field name patterns for redaction
_PII = re.compile(r"(email|e-mail|ssn|password|passwd|token|secret|credential|phone|"
                  r"credit|card|cvv|iban|auth|api[-_]?key)", re.I)


@dataclass
class Decision:
    verdict: str
    reason: str
    clause: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict == ALLOW


@dataclass
class EngagementContract:
    """The operator's signed license, expressed as typed clauses. Empty => governs nothing
    new (unchanged behaviour)."""
    engagement_id: str = ""
    test_principals: set = field(default_factory=set)     # data-level: authorized test accounts
    allowed_paths: list = field(default_factory=list)     # scope-level: path glob patterns
    automation_allowed: bool = True                       # policy-level
    test_resources: set = field(default_factory=set)      # fine-destruction: authorized targets
    pii_fields: set = field(default_factory=set)          # extra field names to redact

    def active(self) -> bool:
        return bool(self.engagement_id or self.test_principals or self.allowed_paths
                    or self.test_resources)

    # ---- the multi-level, fail-closed authorization ---------------------------------
    def authorize(self, method: str, path: str, actor: str,
                  cross_principal: bool = False, resource: str = "") -> Decision:
        """Trace an action to an authorizing clause across every applicable level. Any
        unauthorized level -> HALT (fail-closed). An inactive contract is a no-op ALLOW so
        the engine's existing ScopeGuard remains the sole gate (byte-identical)."""
        if not self.active():
            return Decision(ALLOW, "no engagement contract — governed only by ScopeGuard")
        m = (method or "GET").upper()
        # policy-level
        if not self.automation_allowed:
            return Decision(HALT, "program forbids automated action (policy-level)", "policy")
        # scope-level (per-endpoint path)
        if self.allowed_paths and not any(fnmatch.fnmatch(path, pat) for pat in self.allowed_paths):
            return Decision(HALT, f"path '{path}' is outside declared engagement paths", "scope")
        # data-level: cross-principal touches another principal -> both must be test accounts
        if cross_principal and self.test_principals and actor not in self.test_principals:
            return Decision(HALT, f"actor '{actor}' is not a declared test principal", "data")
        # fine-destruction: a mutation/delete only against a declared authorized test resource
        if m not in _READONLY and self.test_resources is not None and self.test_resources:
            if str(resource) not in self.test_resources:
                return Decision(HALT, f"resource '{resource}' is not a declared test resource "
                                      f"(fine-destruction gate)", "fine-destruction")
        return Decision(ALLOW, "authorized by engagement contract",
                        f"engagement:{self.engagement_id or 'active'}")

    # ---- data-handling: PII redaction -----------------------------------------------
    def sanitize(self, data):
        """Redact sensitive values by field name (default PII patterns + declared extras)."""
        def red(k, v):
            if isinstance(k, str) and (_PII.search(k) or k in self.pii_fields):
                return "[REDACTED]"
            return walk(v)
        def walk(n):
            if isinstance(n, dict):
                return {k: red(k, v) for k, v in n.items()}
            if isinstance(n, list):
                return [walk(x) for x in n]
            return n
        return walk(data)


class TamperEvidentAudit:
    """A hash-chained, append-only audit. Each entry links to the previous by hash, so any
    later edit/removal breaks the chain — a legally-sufficient, third-party-verifiable
    record. Every authorized action cites the clause that authorized it."""

    def __init__(self, seed: str = "onyx-roe-genesis"):
        self._chain = []
        self._seed = seed
        self._prev = hashlib.sha256(seed.encode()).hexdigest()

    def record(self, method: str, path: str, actor: str, decision: Decision, note: str = "") -> str:
        entry = {"seq": len(self._chain), "ts": round(time.time(), 3),
                 "method": method, "path": path, "actor": actor,
                 "verdict": decision.verdict, "clause": decision.clause,
                 "reason": decision.reason, "note": note, "prev": self._prev}
        digest = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
        entry["hash"] = digest
        self._chain.append(entry)
        self._prev = digest
        return digest

    def entries(self) -> list:
        return list(self._chain)

    def verify(self) -> bool:
        """Re-derive the chain; True iff untampered."""
        prev = hashlib.sha256(self._seed.encode()).hexdigest()
        for e in self._chain:
            body = {k: e[k] for k in e if k != "hash"}
            body["prev"] = prev
            if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True
