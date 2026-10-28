"""
AuthPath v3 — core data models.

Pure-stdlib, deterministic, immutable-where-it-matters.  These types are the
common vocabulary every engine component speaks.  Nothing here learns, infers a
baseline, or holds an anomaly score — by construction (RL1).

Design notes keyed to the architecture/WHY docs:
  * ValueOrigin            -> Axis 1  (§4.1, proven not inferred)
  * Envelope               -> Axis 2  (§4.2, measured authority)
  * EffectClassification   -> §4.3   (the ONLY probabilistic step, fail-safe)
  * Candidate / Finding    -> §4.5/§4.6 (Δstate-confirmed, reportable)
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Effect classes & impact classes (closed vocabularies — true by definition)  #
# --------------------------------------------------------------------------- #

class EffectClass(str, Enum):
    """The kind of effect an action has. Routed to by classification (§7.2)."""
    OBJECT_ACCESS = "OBJECT_ACCESS"     # read/return of an addressable object
    OWNERSHIP = "OWNERSHIP"             # mutation of a server-authoritative field (BOPLA)
    AUTHORITY = "AUTHORITY"             # function-level privileged action (BFLA / confused deputy)
    PAYMENT = "PAYMENT"                 # settlement of value
    PRICE = "PRICE"                     # amount computed from line items
    STATE_GATE = "STATE_GATE"          # privileged state reachable only via a predecessor
    INVENTORY = "INVENTORY"            # quantity / stock movement
    COUPON = "COUPON"                  # single-use / limited redemption token
    TEMPORAL_DRIFT = "TEMPORAL_DRIFT"  # credential/authority still valid after a revocation event
    STRUCTURAL_DIVERGENCE = "STRUCTURAL_DIVERGENCE"  # privileged code path reachable by under-privileged principal (SAIE)
    FIELD_PROJECTION = "FIELD_PROJECTION"  # list view over-exposes a field the canonical detail view filters (ISI elevation)
    AUTHORITY_GRANT = "AUTHORITY_GRANT"  # edit to the authority graph itself (IAM role/permission grant — escalation)
    CROSS_SURFACE = "CROSS_SURFACE"    # same resource, two doors disagree on field exposure (RL15 — boundary leak)
    AUTH_REGRESSION = "AUTH_REGRESSION"  # a sensitive field that was withheld earlier is now exposed (RL16 — temporal drift)
    EMERGENT_BREAK = "EMERGENT_BREAK"  # a sequence of permitted ops broke a global invariant (RL18 — child didn't follow parent)
    IDENTITY_SPOOF = "IDENTITY_SPOOF"  # target believes attacker IS the victim — claim/federation layer (GAP-1, whoami-differential)
    CROSS_TENANT = "CROSS_TENANT"      # a principal in tenant A reaches an object owned by tenant B — isolation breach (GAP-2)
    PARSER_DIFFERENTIAL = "PARSER_DIFFERENTIAL"  # same bytes, two parsers, two identities — the authz layer acts on the forged one (GAP-4, SAML roulette)
    REBAC_BYPASS = "REBAC_BYPASS"      # access with NO legitimate relationship path in the observed graph — transitive authz broken (GAP-7, ReBAC)
    CONSISTENCY_WINDOW = "CONSISTENCY_WINDOW"  # a just-revoked relationship still grants access within the propagation window (GAP-10, zookie/new-enemy)
    GRAPHQL_FIELD_AUTHZ = "GRAPHQL_FIELD_AUTHZ"  # a restricted field returned inside an authorized query via alias/nested selection (GAP-3, BOPLA via alias smuggling)
    READ = "READ"                      # non-privileged read (no law beyond OBJECT_ACCESS)
    NONE = "NONE"                      # no security-relevant effect


class ImpactClass(str, Enum):
    """Each violated law names its own impact — the report writes itself (§4.6)."""
    DATA_EXPOSURE = "Data Exposure / Broken Object-Level Authorization"
    PRIVILEGE_ESCALATION = "Privilege Escalation / Broken Property-Level Authorization"
    FUNCTION_AUTHZ = "Broken Function-Level Authorization (BFLA) / Confused Deputy"
    FINANCIAL = "Financial Loss / Payment Tampering"
    PRICE_TAMPERING = "Financial Loss / Price Manipulation"
    WORKFLOW_BYPASS = "Business-Logic Bypass / State-Gate Skip"
    INVENTORY_ABUSE = "Inventory / Quantity Abuse"
    COUPON_ABUSE = "Promotion Abuse / Single-Use Replay"
    TEMPORAL_DRIFT = "Stale Authorization / Revocation Not Enforced"
    AUTHZ_PATH_DIVERGENCE = "Authorization-Path Divergence / Privileged Code Path Reachable"
    FIELD_PROJECTION_LEAK = "Inconsistent Field Projection / List-vs-Detail Over-Exposure"
    IAM_ESCALATION = "Privilege Escalation / Authority-Graph Tampering (IAM)"
    CROSS_SURFACE_LEAK = "Cross-Surface Inconsistency / One Door Over-Exposes What the Canonical View Filters"
    AUTH_REGRESSION = "Authorization Regression / A Previously-Withheld Field Is Now Exposed (Deploy Drift)"
    EMERGENT_BREAK = "Emergent Authorization Break / A Sequence of Permitted Operations Broke a Global Invariant"
    IDENTITY_SPOOF = "Identity Spoofing / Target Trusts a Settable Claim as the Identity Key (Federation Takeover)"
    CROSS_TENANT = "Tenant Isolation Breach / A Principal Reaches Another Tenant's Objects (Cross-Org Access)"
    PARSER_DIFFERENTIAL = "Parser-Differential Authentication Bypass / Two Parsers Disagree and the Forged Identity Is Trusted"
    REBAC_BYPASS = "Broken Relationship-Based Authorization / Access With No Legitimate Relationship Path (Transitive Authz)"
    CONSISTENCY_WINDOW = "Stale Relationship Decision / A Revoked Relationship Still Grants Access in the Propagation Window"
    GRAPHQL_FIELD_AUTHZ = "Broken Object Property Level Authorization / A Restricted Field Is Returned via Alias or Nested Selection (GraphQL)"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


# --------------------------------------------------------------------------- #
# Principals & HTTP exchanges                                                  #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Principal:
    """An authenticated identity provisioned by the tester (never fabricated, D6)."""
    pid: str                       # stable id, e.g. "A", "B", "anon"
    label: str                     # human label, e.g. "Alice (victim)"
    auth: dict[str, str] = field(default_factory=dict)   # SECRET identity headers (redacted)
    is_anonymous: bool = False
    # OBSTACLE-1 FIX: the full, COHERENT browser header set captured for this
    # identity (User-Agent, Accept*, Sec-CH-UA*, Sec-Fetch-*, Referer, ...). Replayed
    # verbatim so a live request carries a self-consistent browser profile instead of
    # a bare Bearer token (the classic automated-tool tell). Never fabricated — only
    # the real captured profile is reused. Non-secret, so it is NOT redacted.
    profile_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class HTTPRequest:
    method: str
    path: str                      # path only, e.g. "/api/orders/42"
    query: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] | None = None
    host: str = ""

    def segments(self) -> list[tuple[str, bool]]:
        """Return [(segment, is_object_id)]. Position-aware: a segment is an object
        id if it is numeric, a long hex/uuid, OR it follows a collection noun
        (previous segment ends in 's') and is not itself a known action word.
        This is cosmetic routing only — it touches no security verdict."""
        raw = [s for s in self.path.strip("/").split("/") if s]
        out: list[tuple[str, bool]] = []
        for i, seg in enumerate(raw):
            prev = raw[i - 1] if i > 0 else ""
            is_id = (
                seg.isdigit()
                or _looks_like_id(seg)
                or (prev.endswith("s") and len(prev) > 2
                    and seg.lower() not in ACTION_SEGMENTS
                    and seg.lower() not in SELF_ALIASES
                    and _ident_like(seg))
            )
            out.append((seg, is_id))
        return out

    def is_graphql(self) -> bool:
        """True iff this request is GraphQL-shaped. Memoised (defect #9)."""
        c = self.__dict__.get("_is_gql_cache")
        if c is None:
            from .graphql import looks_like_graphql
            c = looks_like_graphql(self.path, self.body)
            self.__dict__["_is_gql_cache"] = c
        return c

    def graphql_op(self):
        """Parsed GraphQL operation, or None if not GraphQL-shaped. Memoised."""
        if "_gql_op_cache" in self.__dict__:
            return self.__dict__["_gql_op_cache"]
        from .graphql import parse_graphql_request
        op = None if not self.is_graphql() else parse_graphql_request(self.body)
        self.__dict__["_gql_op_cache"] = op
        return op

    def resource_name(self):
        """RL7 Slice 5: parse this path as an AIP-122 composite resource name,
        returning (primary_object_id, parent_chain, all_ids). Uses the same
        position-aware id recognition as segments() (numeric / hex-uuid / a
        segment following a collection noun), then pairs each id with its
        preceding collection. The PRIMARY object is the last id; earlier ids are
        its parents (each tagged by collection). This gives laundering a primary
        id + hierarchical context for deep hyperscale paths, where object_ids()
        returns only a flat, ambiguous list. Additive — object_ids() is unchanged."""
        segs = self.segments()                       # [(segment, is_object_id)]
        pairs = []                                   # (collection, id)
        for i, (seg, is_id) in enumerate(segs):
            if is_id:
                collection = segs[i - 1][0] if i > 0 else ""
                pairs.append((collection, seg))
        if not pairs:
            return (None, [], [])
        primary_collection, primary_id = pairs[-1]
        parents = [{"collection": c, "id": v} for c, v in pairs[:-1]]
        all_ids = [v for _c, v in pairs]
        return (primary_id, parents, all_ids)

    def primary_object_id(self):
        """The addressed object's id (last id in the resource path), or None."""
        return self.resource_name()[0]

    def object_ids(self) -> list[str]:
        c = self.__dict__.get("_oids_cache")
        if c is not None:
            return c
        c = self._compute_object_ids()
        self.__dict__["_oids_cache"] = c
        return c

    def _compute_object_ids(self) -> list[str]:
        """Object-ids touched by this request, from all carriers (improvements #3, #2):
          * path segments (position-aware)
          * query params named like ids
          * identity-bearing headers (X-Customer-ID, X-Tenant-ID, ...)
          * JWT identity claims (sub, tenant_id, org_id, ...) — DECODED, NOT VERIFIED
          * GraphQL variables named like ids (improvement #2)
        Headers/JWT/variables can carry scope-bearing ids that never appear in
        the path, which is precisely how subtle IDORs hide in production APIs.
        The JWT is treated only as a CLAIM of identity — the Δstate confirmation
        still has the final word."""
        ids = [s for s, is_id in self.segments() if is_id]
        # late imports avoid circular load at module init
        from .provenance import (
            extract_query_ids, extract_identity_headers, inspect_jwt,
        )
        for _, v in extract_query_ids(self.query):
            ids.append(str(v))
        for _, v in extract_identity_headers(self.headers):
            ids.append(str(v))
        for hk, hv in (self.headers or {}).items():
            if hk.lower() == "authorization":
                jwt = inspect_jwt(hv)
                if jwt:
                    for v in jwt.identity_claims.values():
                        ids.append(str(v))
        # GraphQL variables (improvement #2): the real object-ids of a graphql
        # operation live in `variables` rather than the path. Mining them keeps
        # IDOR detection working against GraphQL endpoints with no schema change.
        gql_op = self.graphql_op()
        if gql_op is not None:
            from .graphql import extract_variable_ids
            for _, v in extract_variable_ids(gql_op.variables):
                if isinstance(v, (str, int, float)):
                    ids.append(str(v))
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, (str, int, float)):
                            ids.append(str(item))
        seen, out = set(), []
        for x in ids:
            if x not in seen:
                seen.add(x); out.append(x)
        # G2 (protocol [21], flag-gated: only when the giant-protocol carriers are enabled):
        # opaque/signed ids, batch sub-operation ids, and gRPC-transcoded ids — the carriers
        # giant surfaces use that REST/numeric detection misses. Additive; the Δstate
        # confirmer still decides truth, so this only expands addressability, never FP.
        if getattr(self, "giant_protocol", False):
            try:
                from .protocol import extra_object_ids
                for x in extra_object_ids(self):
                    if x not in seen:
                        seen.add(x); out.append(x)
            except Exception:
                pass
        return out

    def endpoint_key(self) -> str:
        """Normalised endpoint identity — id-bearing segments collapsed to {id}.
        For GraphQL requests, the real endpoint is the operation (type+name) in
        the body, not the path (improvement #2). The contract lookup uses this
        key so GraphQL contracts can register `MUTATION transferFunds` etc."""
        c = self.__dict__.get("_ekey_cache")
        if c is not None:
            return c
        gql_op = self.graphql_op()
        if gql_op is not None:
            c = gql_op.endpoint_key()
        else:
            parts = ["{id}" if is_id else seg for seg, is_id in self.segments()]
            c = f"{self.method} /" + "/".join(parts)
        self.__dict__["_ekey_cache"] = c
        return c


@dataclass
class HTTPResponse:
    status: int
    body: dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Exchange:
    """A request/response pair tagged with the acting principal."""
    request: HTTPRequest
    response: HTTPResponse
    principal: Principal
    rid: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    session_id: str = "s0"
    observed_at: float = field(default_factory=time.time)


# --------------------------------------------------------------------------- #
# Axis 1 — Value-Origin Provenance (§4.1) — proven by parsing, no LLM          #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ValueOrigin:
    """Where a structurally-significant value provably came from."""
    value: Any
    response_id: str               # the rid of the Exchange it was first seen in
    principal_id: str              # who legitimately received it
    endpoint: str                  # normalised endpoint key
    field_path: str                # JSON-pointer-ish path, e.g. "body.order_id"
    session_id: str
    observed_at: float


# --------------------------------------------------------------------------- #
# Axis 2 — Principal Envelope (§4.2) — measured authority                      #
# --------------------------------------------------------------------------- #

@dataclass
class Envelope:
    """
    The measured set of authorities a principal legitimately exercised.
    Grown ONLY by the principal's own authenticated actions (a measured fact,
    never an induced rule — RL1).
    """
    principal_id: str
    object_ids: set[str] = field(default_factory=set)        # ids it legitimately holds
    # RL9 (host-scoped authority): ids held PER SERVICE/HOST. A hold proven on
    # service X does not authorise the same id on service Y — authority is
    # host-scoped. The global set above is kept for non-host-aware callers; the
    # IDOR law consults the per-host view so cross-service access is not silently
    # cleared by a hold on a different service.
    object_ids_by_host: dict = field(default_factory=dict)
    effects: set[EffectClass] = field(default_factory=set)   # effect-classes it exercised
    granted_authority: set[str] = field(default_factory=set)  # function-level rights held
    # sealed value-ranges per effect, e.g. {"PAYMENT": (0, 999)} — measured, not assumed
    value_ranges: dict[str, tuple[float, float]] = field(default_factory=dict)
    # R4 FIX: privileged-field VALUES the principal legitimately held (measured from
    # its own authenticated responses). Lets OwnershipLaw distinguish a real
    # elevation from a benign resubmission of an already-held value (no induction).
    held_field_values: dict[str, set] = field(default_factory=dict)

    def holds_object(self, object_id: Any) -> bool:
        return str(object_id) in self.object_ids

    def holds_object_on_host(self, object_id: Any, host: str) -> bool:
        """RL9: did the principal legitimately hold this object ON THIS SERVICE?
        A cross-service access is NOT covered by a hold on a different service."""
        return str(object_id) in self.object_ids_by_host.get(host or "", set())

    def holds_authority(self, authority: str) -> bool:
        return authority in self.granted_authority


# --------------------------------------------------------------------------- #
# Effect classification (§4.3) — the one probabilistic, fail-safe step (D5)    #
# --------------------------------------------------------------------------- #

class ClassificationSource(str, Enum):
    CONTRACT = "contract"          # declared by the target (preferred)
    INFERRED = "inferred"          # dynamic fallback, HIGHER caution


@dataclass
class EffectClassification:
    endpoint: str
    effect: EffectClass
    source: ClassificationSource
    # security-critical params the law will inspect (object ids, amounts, fields…)
    critical_params: list[str] = field(default_factory=list)
    # fail-safe flag: inferred classifications carry elevated scrutiny (D5)
    high_caution: bool = False
    notes: str = ""


# --------------------------------------------------------------------------- #
# Law verdicts, candidates, findings (§4.4–4.6)                                #
# --------------------------------------------------------------------------- #

class Verdict(str, Enum):
    PASS = "PASS"                  # law holds — clean
    CANDIDATE = "CANDIDATE"        # law potentially violated — MUST be Δstate-confirmed
    SKIP = "SKIP"                  # no law applies to this effect-class


@dataclass
class LawVerdict:
    verdict: Verdict
    law_name: str
    effect: EffectClass
    reason: str
    impact: Optional[ImpactClass] = None
    # the evidence the law leaned on — feeds the causal path
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Candidate:
    """A potential violation. NOT yet a finding (RL3 — needs Δstate proof)."""
    cid: str
    exchange: Exchange
    classification: EffectClassification
    verdict: LawVerdict
    causal_origin: Optional[ValueOrigin] = None   # the value that laundered authority


@dataclass
class StateProof:
    """The authenticated read-back that proves Δstate (RL3)."""
    confirmed: bool
    method: str                    # what we read back, in words
    before: Any
    after: Any
    read_as: str                   # principal id we read back as (the owner)
    detail: str = ""


@dataclass
class PoC:
    """Reproducible proof — the minimal request sequence (RL4)."""
    steps: list[str]               # human-readable ordered steps
    curl: list[str]                # copy-pasteable curl commands
    notes: str = ""


@dataclass
class Finding:
    """A CONFIRMED violation — fully reportable (RL4)."""
    fid: str
    title: str
    effect: EffectClass
    impact: ImpactClass
    severity: Severity
    causal_path: list[str]         # ordered narrative of how authority was laundered
    state_proof: StateProof
    poc: PoC
    classification: EffectClassification
    law_name: str
    actor_pid: str = ""            # the principal that performed the violating action
    target_ref: str = ""           # the object/owner the authority was laundered against
    resource_ref: str = ""         # the concrete resource id accessed (for policy #1 gate)
    discovered_at: float = field(default_factory=time.time)
    # CVSS 3.1 (improvement #8) — deterministic vector→score from effect+facts.
    cvss_score: float = 0.0
    cvss_label: str = ""
    cvss_vector: str = ""
    # Blast-radius classification of the exposed id (dev idea #3) — report-only,
    # deliberately NOT folded into the CVSS base score (non-standard there).
    enumerability: str = ""
    enumerability_note: str = ""
    # off-hot-path human prose (may be LLM-drafted from this proven finding — RL2)
    report_markdown: str = ""


# --------------------------------------------------------------------------- #
# Scope-Guard decisions (§7.5, RL5)                                            #
# --------------------------------------------------------------------------- #

class ScopeVerdict(str, Enum):
    ALLOW = "ALLOW"
    HALT = "HALT"                  # fail-safe: uncertainty ⇒ do nothing


@dataclass
class ScopeDecision:
    verdict: ScopeVerdict
    reason: str
    host: str = ""


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #

def _looks_like_id(seg: str) -> bool:
    """uuid / hex / mongo-id heuristic for endpoint normalisation only.
    This touches NO security decision — purely cosmetic endpoint grouping."""
    if len(seg) >= 16 and all(c in "0123456789abcdefABCDEF-" for c in seg):
        return True
    return False


import re as _re
_UUID_RE = _re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                       r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def classify_enumerability(object_id: str) -> tuple[str, str]:
    """Classify how enumerable an exposed identifier is (dev idea #3).

    The enumerability of the leaked id determines the BLAST RADIUS of an
    object-access finding — whether one record or every record is reachable.
    This is a recognised severity factor (OWASP IDOR guidance) but it does NOT
    map onto the CVSS 3.1 base vector, so we surface it as an explicit
    blast-radius note rather than distorting the standard score.

    Returns (level, note). level ∈ {sequential, numeric, uuid, opaque, slug}.
    """
    s = str(object_id).strip()
    if not s:
        return "unknown", ""
    if s.isdigit():
        if len(s) <= 9:
            return ("sequential",
                    "identifier is a short sequential integer — an attacker can "
                    "enumerate EVERY object by incrementing/decrementing the value; "
                    "blast radius is the entire collection, not a single record")
        return ("numeric",
                "identifier is numeric — enumeration is feasible though the larger "
                "value space slows a full sweep")
    if _UUID_RE.match(s):
        return ("uuid",
                "identifier is a UUID (high entropy) — not directly enumerable; "
                "exploitation requires first obtaining a target id (e.g. one leaked "
                "by another endpoint), so blast radius is bounded by id disclosure")
    if len(s) >= 16 and all(c in "0123456789abcdefABCDEF-_=" for c in s):
        return ("opaque",
                "identifier is a long opaque token — enumeration is impractical; "
                "the finding requires a disclosed id to exploit at scale")
    return ("slug",
            "identifier is a human-readable slug — may be guessable or discoverable "
            "via search/listing endpoints; assess discoverability for blast radius")



# Action words that follow an id (e.g. /orders/{id}/fulfil) — never themselves ids.
ACTION_SEGMENTS = {
    "fulfil", "fulfill", "ship", "cancel", "approve", "reject", "redeem",
    "price", "checkout", "pay", "settle", "refund", "activate", "deactivate",
    "lock", "unlock", "verify", "confirm", "submit", "complete",
}


# Self-referential aliases resolve to the CALLER, never to a shared object id.
# Treating them as ids would make two principals hitting /users/me look like they
# touch the SAME object (a guaranteed cross-principal false signal). (defect #7)
SELF_ALIASES = {"me", "self", "current", "mine", "my", "current_user"}

def _ident_like(seg: str) -> bool:
    """A short token usable as a resource id (cosmetic routing only). Allows '.'
    and '@' so dotted usernames / emails (john.doe, a@b.com) are recognised as
    ids too — previously they silently became un-normalised, blinding IDOR
    detection on slug-keyed endpoints (defect #7/#8)."""
    if not seg or seg.lower() in SELF_ALIASES:
        return False
    return len(seg) <= 64 and all(c.isalnum() or c in "-_.@" for c in seg)
