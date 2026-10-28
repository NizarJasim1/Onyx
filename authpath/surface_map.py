"""
authpath.surface_map — RESOURCE-IDENTITY UNIFICATION + CROSS-SURFACE LEDGER (RL15).

THE SHIFT THIS MODULE ENCODES
-----------------------------
Every prior ONYX component treats the *endpoint* as the unit of identity:
`GET /v1/orders/42`, `GET /v2/orders/42`, `POST /graphql {order(id:42)}` and
`GET /orders?filter=42` are four unrelated things to the engine. But they are the
SAME TRUTH — order 42 — reached through four different *doors*. The boundary
vulnerability lives in the disagreement between doors, never in one door, which is
exactly why a per-endpoint scanner (and a human who tests one door, then another
hours later) cannot see it: the two sides of the boundary are produced by
different code paths and only a tool that compares them *simultaneously and
deterministically* can catch the divergence.

This module gives the engine a first-class notion of a RESOURCE — independent of
the door — and records, per (resource, principal), which sensitive fields each
door exposed and which door was the CANONICAL authoritative view.

LOAD-BEARING DISCIPLINE (the five red lines are preserved, by construction)
---------------------------------------------------------------------------
  * RL1 (no induction): unification is a STRUCTURAL parse — the resource type comes
    from the collection noun in the path; the id is canonicalised through the
    deterministic `idformat` decoder (b64-typed / prefixed / int). There is NO
    fuzzy/similarity matching anywhere. Two doors unify iff they parse to the
    identical (type, normalised-id). A wrong unification is therefore impossible
    on well-formed names, and ambiguous names simply fail to unify (fail-safe).
  * RL5 (fail-safe): anything we cannot parse into a (type, id) yields `None` and
    is silently ignored — it never produces a comparison, so it never produces a
    false positive.

This module is PURE DATA + STRUCTURAL PARSING. It holds no verdict logic; the law
(`CrossSurfaceConsistencyLaw` in eil.py) reads this ledger, and the confirmer
proves the divergence by an authoritative read-back (RL3). Disabled by default at
the engine (the `cross_surface` flag) ⇒ this module is never consulted ⇒
byte-identical to the pre-RL15 engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .idformat import detect_shape
from .provenance import extract_values


# --------------------------------------------------------------------------- #
# Resource identity — the door-independent name of a thing                    #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ResourceIdentity:
    """A truth, independent of the door used to reach it.

    `rtype` is the resource type (the collection noun: 'order', 'account', ...),
    singularised so 'orders' and 'order' unify. `rid` is the id normalised across
    encodings so a REST '900', a prefixed 'acc_900' and a GraphQL b64('Account:900')
    all collapse to the same identity. Frozen ⇒ usable as a dict key.
    """
    rtype: str
    rid: str

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.rtype}:{self.rid}"


# Door kinds, ordered by how authoritative/narrow the view is. The CANONICAL door
# is the single-object detail read — by REST convention `GET /collection/{id}` —
# which is the serializer a careful team writes most defensively. Non-canonical
# doors (list, search, graphql field selections) are the ones that historically
# over-project, because nobody expects PII to ride along in a list row.
DOOR_CANONICAL = "canonical"     # GET /collection/{id} — the authoritative detail view
DOOR_LIST = "list"               # GET /collection      — a collection/list view
DOOR_GRAPHQL = "graphql"         # a GraphQL field selection over the object
DOOR_SEARCH = "search"           # a search/filter endpoint returning the object
DOOR_OTHER = "other"             # any other shape that still addresses the resource


def _singular(noun: str) -> str:
    """Cheap, deterministic singularisation of a collection noun so 'orders' and
    'order' unify. Conservative: strips a trailing plural 's', and 'es' ONLY for
    genuine sibilant plurals (classes→class, boxes→box). Crucially it does NOT
    strip 'es' from words whose singular ends in 'e' (resources→resource,
    devices→device, services→service, invoices→invoice) — getting this wrong
    silently breaks identity unification on very common REST collection names.
    This is cosmetic key-normalisation, not a verdict (RL1)."""
    n = (noun or "").strip().lower()
    if len(n) > 3 and n.endswith("ies"):
        return n[:-3] + "y"
    # true '-es' plurals: the singular ends in a sibilant (s/x/z/ch/sh).
    for suf in ("sses", "shes", "ches", "xes", "zes"):
        if len(n) > len(suf) and n.endswith(suf):
            return n[:-2]
    if len(n) > 2 and n.endswith("s") and not n.endswith("ss"):
        return n[:-1]
    return n


def _normalise_id(raw: str) -> Optional[str]:
    """Canonicalise an id across encodings via the deterministic idformat decoder.
    A b64-typed id decodes to its inner '<num>' (and carries the type); a prefixed
    id collapses to its digits; an int stays as-is. UUID/hex/opaque pass through
    verbatim. Returns None for empty. NO heuristics beyond the structural decoder."""
    s = str(raw).strip()
    if not s:
        return None
    shape = detect_shape(s)
    if shape.kind in ("int", "padded_int"):
        return str(int(s)) if shape.kind == "int" else s.lstrip("0") or "0"
    if shape.kind == "prefixed":
        return shape.detail.get("num", s)
    if shape.kind == "b64_typed":
        return shape.detail.get("num") or shape.detail.get("decoded") or s
    # uuid / hex / unknown — verbatim, lowercased for stable matching
    return s.lower()


def _typed_id_type(raw: str) -> Optional[str]:
    """If the id itself carries a type (b64-typed 'Account:900'), return it. Used
    only as a FALLBACK for the resource type when the path has no collection noun
    (e.g. a GraphQL global id). Structural, deterministic."""
    shape = detect_shape(str(raw))
    if shape.kind == "b64_typed":
        t = shape.detail.get("type") or ""
        return _singular(t) if t else None
    return None


def identify(request, pq_registry=None) -> Optional[ResourceIdentity]:
    """Derive the door-independent ResourceIdentity this request addresses, or None.

    Strategy (all structural — RL1):
      1. Take the primary object id and its parent collection from the request's
         AIP-122 resource_name() parse (already in models.py).
      2. Normalise the id across encodings via idformat.
      3. Resource type = the (singularised) collection noun preceding the id; if
         the path has none (bare global id), fall back to a type encoded in the id.
    A request that addresses no single object (a pure collection list with no id)
    has no *primary* identity here — but it is still recorded against the
    identities of the ELEMENTS it returns (see SurfaceLedger.record), so the list
    door is the one that gets compared. Returns None only when nothing parseable.
    """
    # GraphQL — text OR APQ-persisted hash (#2-a). The resource lives in the
    # operation, not the path. A pq_registry lets a hash-only request resolve its
    # operation from a prior observed registration (RL1: learned, never guessed).
    from .graphql import is_persisted_query
    try:
        is_text_gql = request.is_graphql()
    except Exception:
        is_text_gql = False
    is_apq = is_persisted_query(getattr(request, "body", None))
    if is_text_gql or is_apq:
        return identify_graphql(request, pq_registry)
    try:
        primary_id, parents, _all = request.resource_name()
    except Exception:
        return None
    if primary_id is None:
        # SECONDARY-KEY object: a collection endpoint addressed by a single
        # non-pagination query key (?invoice=, ?email=, ?id=) is a distinct object —
        # the strange form of BOLA. Pagination/projection/filter params are NOT object
        # keys and stay non-objects (precision). Δstate/ownership guards still decide.
        return _secondary_key_identity(request)
    nid = _normalise_id(primary_id)
    if nid is None:
        return None
    rtype = ""
    if parents:
        rtype = _singular(parents[-1].get("collection", ""))
    if not rtype:
        # primary id's own immediate collection (last collection in the path)
        rtype = _collection_for_primary(request)
    if not rtype:
        rtype = _typed_id_type(primary_id) or ""
    if not rtype:
        return None
    return ResourceIdentity(rtype, nid)


# query keys that are pagination / projection / filter — NEVER an object's secondary key.
_PAGINATION_KEYS = {"page", "limit", "offset", "sort", "order", "expand", "fields", "q",
                    "query", "filter", "per_page", "perpage", "cursor", "after", "before",
                    "size", "count", "page_size", "pagesize", "skip", "top", "format",
                    "include", "embed", "lang", "locale", "version"}


def _secondary_key_identity(request) -> Optional[ResourceIdentity]:
    """A collection endpoint addressed by ONE meaningful (non-pagination) query key names a
    single object (the secondary-key BOLA form). Returns a distinct ResourceIdentity, or
    None when the query is empty / pagination-only / multi-key (not a single object)."""
    from urllib.parse import urlparse, parse_qs
    path = getattr(request, "path", "") or getattr(request, "url", "") or ""
    try:
        u = urlparse(path)
        qs = parse_qs(u.query)
    except Exception:
        return None
    keys = [(k, v[0]) for k, v in qs.items()
            if k.lower() not in _PAGINATION_KEYS and v and v[0]]
    if len(keys) != 1:                       # zero / multiple meaningful keys ⇒ not one object
        return None
    key, val = keys[0]
    segs = [s for s in u.path.split("/") if s]
    coll = _singular(segs[-1]) if segs else ""
    if not coll:
        return None
    nid = _normalise_id(val) or str(val)
    return ResourceIdentity(coll, f"{key.lower()}={nid}")


def identify_graphql(request, pq_registry=None) -> Optional[ResourceIdentity]:
    """ResourceIdentity for a GraphQL request: type = the (singularised) root
    field, id = the first id-shaped variable, normalised across encodings. This is
    how a GraphQL door binds to the SAME resource identity a REST door produces, so
    a GraphQL-declared FORBIDDEN on `vault.secret` for principal P can be matched
    against a REST list that later serves `secret` for the same vault to P.

    Resolves APQ (#2-a): a hash-only request is resolved to its operation via the
    pq_registry (learned from an observed registration). When the text was never
    observed, the operation is keyed by the hash itself (a stable identity across
    principals) — so a hash-vs-hash cross-principal differential still works, but
    the type is the hash handle rather than a real root field.

    Structural only (RL1): the type comes from the selected root field, the id from
    a declared variable. No selection-set guessing beyond the root field name."""
    op = None
    body = getattr(request, "body", None)
    if pq_registry is not None:
        op = pq_registry.resolve_op(body)
    if op is None:
        try:
            op = request.graphql_op()
        except Exception:
            op = None
    if op is None or not op.root_fields:
        return None
    rtype = _singular(op.root_fields[0])
    from .graphql import extract_variable_ids
    ids = extract_variable_ids(op.variables or {})
    rid = None
    for _name, val in ids:
        nid = _normalise_id(str(val))
        if nid is not None:
            rid = nid
            break
    if not rtype or rid is None:
        return None
    return ResourceIdentity(rtype, rid)


def _collection_for_primary(request) -> str:
    """The collection segment immediately preceding the primary (last) id."""
    try:
        segs = request.segments()
    except Exception:
        return ""
    last_id_idx = None
    for i, (_seg, is_id) in enumerate(segs):
        if is_id:
            last_id_idx = i
    if last_id_idx is None or last_id_idx == 0:
        return ""
    return _singular(segs[last_id_idx - 1][0])


def classify_door(request) -> str:
    """Which kind of door is this request? Structural, deterministic.

    Canonical = a single-object detail READ: a GET whose final segment is the
    primary object id (REST `GET /collection/{id}`). This is the authoritative
    view we trust as the reference for the differential. Everything else that
    still touches the resource is a non-canonical door that we test AGAINST it.
    """
    method = (request.method or "").upper()
    if request.is_graphql():
        return DOOR_GRAPHQL
    path = (request.path or "")
    pl = path.lower()
    if "search" in pl or "query" in pl or (request.query and method in ("GET", "HEAD")):
        # a filter/search read that returns objects
        if method in ("GET", "HEAD"):
            return DOOR_SEARCH
    try:
        segs = request.segments()
    except Exception:
        segs = []
    if method in ("GET", "HEAD") and segs:
        last_seg, last_is_id = segs[-1]
        if last_is_id:
            return DOOR_CANONICAL          # GET /collection/{id}
        # GET /collection  (no trailing id) → a list view
        return DOOR_LIST
    return DOOR_OTHER


# --------------------------------------------------------------------------- #
# Field exposure extraction — what sensitive values did a door reveal?        #
# --------------------------------------------------------------------------- #

# Ephemeral / echo fields excluded from the comparison (timestamps, etags, ...).
# Mirrors the confirmer's closed vocabulary so the two stay consistent (RL1).
_EPHEMERAL = {
    "created_at", "updated_at", "last_seen", "last_seen_at", "timestamp",
    "request_id", "trace_id", "etag", "version", "_rev", "modified_at",
    "fetched_at", "as_of", "now", "server_time",
}


@dataclass
class DoorExposure:
    """What a single door revealed for one resource, for one principal."""
    door: str
    endpoint: str
    # leaf field name -> value, for SENSITIVE fields only, with a real (non-null,
    # non-redacted) value. Keyed by leaf so REST 'phone' and a nested 'buyer.phone'
    # compare on the meaningful name. Non-sensitive fields are deliberately NOT
    # recorded — the cross-surface law fires ONLY on sensitive divergence (the
    # false-positive guard from CRUCIBLE law 12).
    sensitive_fields: dict = field(default_factory=dict)


def _is_redacted(v: Any) -> bool:
    return v in (None, "", "redacted", "***", "[REDACTED]", "REDACTED")


def exposed_sensitive_fields(body: Any, element_id: Optional[str] = None) -> dict:
    """Sensitive leaf fields with real values in a body. When `element_id` is given
    and the body is a collection, restrict to the element whose id matches (so a
    list row is attributed to its own resource identity, never to a sibling).

    Sensitivity is the project's existing closed vocabulary (confirmer.SENSITIVE_FIELDS
    + intrinsic.name_sensitivity) — never learned (RL1). Returns {leaf: value}.
    """
    from .confirmer import _is_sensitive_key
    try:
        from .intrinsic import name_sensitivity
    except Exception:                      # pragma: no cover
        name_sensitivity = lambda _p: 0    # noqa: E731

    target = body
    if element_id is not None and isinstance(body, (dict, list)):
        target = _find_element(body, element_id)
        if target is None:
            return {}

    out: dict = {}
    for tv in extract_values(target):
        leaf = tv.field_path.split(".")[-1].split("[")[0].lower()
        if leaf in _EPHEMERAL:
            continue
        if _is_redacted(tv.value):
            continue
        sensitive = _is_sensitive_key(leaf) or name_sensitivity(tv.field_path) >= 6
        if sensitive:
            # last write wins is fine; sensitive leaves rarely collide meaningfully
            out[leaf] = tv.value
    return out


def _find_element(body: Any, element_id: str):
    """Locate the collection element whose id == element_id (any nesting depth).
    Used to attribute a list row to its own resource identity. Returns the element
    dict or None."""
    nid = _normalise_id(element_id)

    def walk(node):
        if isinstance(node, dict):
            for k in ("id", "_id", "uid", "uuid"):
                if k in node and _normalise_id(str(node[k])) == nid:
                    return node
            for v in node.values():
                r = walk(v)
                if r is not None:
                    return r
        elif isinstance(node, list):
            for v in node:
                r = walk(v)
                if r is not None:
                    return r
        return None

    return walk(body)


# --------------------------------------------------------------------------- #
# The ledger — per (resource, principal) door exposures                       #
# --------------------------------------------------------------------------- #

class SurfaceLedger:
    """Records, per (ResourceIdentity, principal_id), the canonical door's exposed
    sensitive fields. The cross-surface law consults this to ask: "did the
    authoritative detail view HIDE a sensitive field that this other door is now
    exposing — for the SAME principal?"

    We store ONLY the canonical observation as the reference (the non-canonical
    door is the live exchange under analysis). Bounded by #resources × #principals,
    not by traffic volume.
    """

    def __init__(self, pq_registry=None) -> None:
        # (rtype, rid, principal) -> DoorExposure for the canonical door
        self._canonical: dict = {}
        # (rtype, rid, principal) -> {field_leaf: {"path":..., "request": HTTPRequest}}
        self._denials: dict = {}
        # APQ (#2-a): hash -> query-text registry, learned from observed
        # registrations so hash-only requests resolve to their real operation.
        if pq_registry is None:
            from .graphql import PersistedQueryRegistry
            pq_registry = PersistedQueryRegistry()
        self.pq_registry = pq_registry

    def observe_persisted(self, request) -> None:
        """Learn a hash->query mapping from an APQ registration (text + hash)."""
        self.pq_registry.observe(getattr(request, "body", None))

    def record(self, request, response, principal_id: str) -> None:
        """Record a legitimate observation. Only the CANONICAL door is stored as a
        reference; non-canonical doors are not (they are what we test live). A
        canonical observation overwrites the prior one for that (resource,principal)
        — the most recent authoritative view wins."""
        self.observe_persisted(request)
        body = getattr(response, "body", None)
        if not isinstance(body, (dict, list)):
            return
        door = classify_door(request)
        if door != DOOR_CANONICAL:
            return
        ident = identify(request, self.pq_registry)
        if ident is None:
            return
        fields = exposed_sensitive_fields(body)
        self._canonical[(ident.rtype, ident.rid, principal_id)] = DoorExposure(
            door=door, endpoint=request.endpoint_key(), sensitive_fields=fields)

    def record_denials(self, request, response, principal_id: str) -> None:
        """Record fields the server EXPLICITLY refused on authorization grounds for
        this (resource, principal) — the GraphQL intent-declared canonical. Handles
        APQ hash-only requests (resolved via the registry). Only SENSITIVE denied
        fields are stored; the request is kept so the confirmer can replay it and
        prove the denial is still live. A `null` value is NOT a denial (kill-test):
        only an authz-class error counts."""
        from .graphql import is_persisted_query
        body = getattr(request, "body", None)
        try:
            is_gql = request.is_graphql()
        except Exception:
            is_gql = False
        if not is_gql and not is_persisted_query(body):
            return
        resp_body = getattr(response, "body", None)
        from .graphql import authz_denied_paths
        denied = authz_denied_paths(resp_body)
        if not denied:
            return
        ident = identify(request, self.pq_registry)
        if ident is None:
            return
        from .confirmer import _is_sensitive_key
        try:
            from .intrinsic import name_sensitivity
        except Exception:                      # pragma: no cover
            name_sensitivity = lambda _p: 0    # noqa: E731
        key = (ident.rtype, ident.rid, principal_id)
        bucket = self._denials.setdefault(key, {})
        for path in denied:
            leaf = path.split(".")[-1].split("[")[0].lower()
            if _is_sensitive_key(leaf) or name_sensitivity(path) >= 6:
                bucket[leaf] = {"path": path, "request": request,
                                "endpoint": request.endpoint_key()}

    def denials_for(self, ident: ResourceIdentity, principal_id: str) -> dict:
        return self._denials.get((ident.rtype, ident.rid, principal_id), {})

    def canonical_for(self, ident: ResourceIdentity, principal_id: str) -> Optional[DoorExposure]:
        return self._canonical.get((ident.rtype, ident.rid, principal_id))

    def has_canonical(self, ident: ResourceIdentity, principal_id: str) -> bool:
        return (ident.rtype, ident.rid, principal_id) in self._canonical
