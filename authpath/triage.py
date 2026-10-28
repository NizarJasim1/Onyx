"""
Authorization-risk triage for giant surfaces (protocol [21], gap G1).
================================================================================
A Google/Microsoft-scale surface has 10^4-10^6 endpoints. ONYX's per-exchange passes and
k-sample quorum are precise but not free; run naively they would drown. The lock is not
detection quality — it is that a fixed confirmation budget must be SPENT on the highest-
authorization-risk candidates first, or the deep bugs are never reached.

The move (deterministic, RL1 — no ML): score every candidate endpoint by STRUCTURAL
authz-risk signals that are known black-box, and confirm in descending order until the
budget is exhausted. Triage changes only the ORDER and the BUDGET of what ONYX confirms —
it never changes WHAT counts as a confirmation. So the zero-FP crown jewel is untouched:
a high-ranked endpoint that is not actually vulnerable still yields no finding (the Δstate
confirmer decides), and triage can only reorder, never fabricate.

Risk signals (each a known, deterministic property of the request/endpoint):
  * object-addressed: takes an id/key in path or query  -> BOLA/IDOR surface
  * mutating verb: PUT/POST/PATCH/DELETE                 -> cross-principal write/BFLA
  * cross-tenant hint: /org|/tenant|/account/{id}        -> isolation surface
  * privilege hint: /admin|/internal|/manage|/role       -> BFLA/escalation surface
  * secondary-key: email/slug/handle/uuid in query       -> secondary-key BOLA
  * versioned/legacy: /v1|/internal|/legacy              -> version-downgrade authz gap
  * sensitive noun: user|payment|invoice|token|key|file  -> high-impact object

The score is a transparent, auditable integer sum — a reviewer can see exactly why an
endpoint ranked where it did. This is triage, not judgement: it decides ORDER, the Δstate
confirmer decides TRUTH.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import re

_ID_SEG = re.compile(r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-f]{8}-[0-9a-f]{4})$")
_MUTATING = {"PUT", "POST", "PATCH", "DELETE"}
_PRIV = re.compile(r"/(admin|internal|manage|management|role|privilege|sudo|root)(/|$)", re.I)
_TENANT = re.compile(r"/(org|orgs|tenant|tenants|account|accounts|workspace|team)(/|$)", re.I)
_VERSIONED = re.compile(r"/(v\d+|internal|legacy|beta|deprecated)(/|$)", re.I)
_SENSITIVE = re.compile(r"(user|users|payment|invoice|billing|token|secret|key|credential|"
                        r"file|document|message|email|profile|order|card|ssn|password)", re.I)
_SECONDARY = ("email", "slug", "handle", "username", "uuid", "guid", "key")


@dataclass(frozen=True)
class RiskScore:
    endpoint: str
    method: str
    score: int
    reasons: tuple = field(default_factory=tuple)


def score_endpoint(method: str, path: str, query_keys=None) -> RiskScore:
    m = (method or "GET").upper()
    reasons = []
    score = 0
    segs = [s for s in (path or "").split("/") if s]
    # object-addressed (an id/opaque key in a path segment)
    if any(_ID_SEG.match(s) for s in segs) or "{" in (path or ""):
        score += 3; reasons.append("object-addressed")
    # mutating verb -> cross-principal write / BFLA surface
    if m in _MUTATING:
        score += 3; reasons.append(f"mutating:{m}")
        if m == "DELETE":
            score += 1; reasons.append("destructive")
    # privilege / admin surface
    if _PRIV.search(path or ""):
        score += 4; reasons.append("privilege-surface")
    # cross-tenant isolation surface
    if _TENANT.search(path or ""):
        score += 3; reasons.append("cross-tenant")
    # version / legacy downgrade authz gap
    if _VERSIONED.search(path or ""):
        score += 2; reasons.append("versioned/legacy")
    # sensitive object noun
    if _SENSITIVE.search(path or ""):
        score += 2; reasons.append("sensitive-noun")
    # secondary-key addressing in the query
    for k in (query_keys or ()):
        if str(k).lower() in _SECONDARY:
            score += 3; reasons.append(f"secondary-key:{k}"); break
    return RiskScore(endpoint=f"{m} {path}", method=m, score=score, reasons=tuple(reasons))


class RiskTriage:
    """Rank a large candidate surface by authorization risk and yield the top-N within a
    confirmation budget. Deterministic and stable: equal scores break ties lexicographically
    so a run is reproducible."""

    def __init__(self):
        self._scored = []

    def add(self, method: str, path: str, query_keys=None):
        self._scored.append(score_endpoint(method, path, query_keys))
        return self

    def ranked(self):
        # highest risk first; deterministic tie-break by endpoint key
        return sorted(self._scored, key=lambda r: (-r.score, r.endpoint))

    def budget(self, n: int):
        """The top-n highest-risk candidates — where a finite confirmation budget is spent.
        Triage decides ORDER only; the Δstate confirmer still decides truth for each."""
        return self.ranked()[:max(0, n)]

    def coverage(self, n: int) -> dict:
        r = self.ranked()
        picked = r[:max(0, n)]
        return {"total": len(r), "budget": n,
                "risk_captured": sum(x.score for x in picked),
                "risk_total": sum(x.score for x in r),
                "top_reasons": [x.endpoint for x in picked[:5]]}
