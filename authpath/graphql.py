"""
GraphQL adapter (improvement #2).

GraphQL flips REST's premises: every operation is POST /graphql, and the real
"endpoint" lives in the body — the operation name + type (query|mutation|
subscription). This module is the deterministic bridge that lets the existing
ONYX engine reason about a GraphQL request without touching the EIL or the
confirmer.

Design constraints:
  * No GraphQL lexer dependency. Parsing is lightweight, signature-level only —
    we extract the operation type, name, and TOP-LEVEL field selections
    (including aliases). This is sufficient for effect-class classification and
    contract lookup; field-level detail is unnecessary on the hot path.
  * Mutation-name → effect-class is HEURISTIC and contract-overridable. Per
    RL2, the contract is authoritative; heuristics only seed the inferred path.
  * Failure is signalled by `errors: [...]` in the response body, REGARDLESS of
    HTTP status. We expose `gql_succeeded()` so the EIL keeps working.
  * Introspection is treated as a free schema oracle — if the operator can run
    `{ __schema { ... } }`, we can build a contract automatically (kept off the
    hot path; the operator runs it once at setup).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterator


# --------------------------------------------------------------------------- #
# Detection                                                                    #
# --------------------------------------------------------------------------- #
GRAPHQL_PATH_HINTS = ("/graphql", "/api/graphql", "/v1/graphql", "/query")


def looks_like_graphql(path: str, body: Any) -> bool:
    """True if this request is GraphQL-shaped — path-based hint OR body shape."""
    if path:
        p = path.lower()
        if any(p == h or p.endswith(h) for h in GRAPHQL_PATH_HINTS):
            return True
    if isinstance(body, dict):
        if isinstance(body.get("query"), str):
            # has a string `query` (and optionally variables/operationName)
            return True
    return False


# --------------------------------------------------------------------------- #
# Lightweight parsing                                                          #
# --------------------------------------------------------------------------- #
_OP_RE = re.compile(
    r"^\s*(query|mutation|subscription)\b\s*([A-Za-z_][A-Za-z0-9_]*)?",
    re.IGNORECASE | re.DOTALL,
)
_ROOT_FIELD_RE = re.compile(
    r"(?:([A-Za-z_][A-Za-z0-9_]*)\s*:\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(",
)
_SHORTHAND_RE = re.compile(r"^\s*\{", re.MULTILINE)


@dataclass
class GraphQLOperation:
    """A parsed view of a GraphQL request. All fields best-effort, never trusted
    for the security verdict (the verdict comes from EIL+Δstate)."""
    op_type: str               # "query" | "mutation" | "subscription"
    op_name: str               # operation name (empty if anonymous)
    root_fields: list[str]     # selected root field names (mutations of interest)
    aliases: list[str]         # alias names if any (for aliased multi-op)
    variables: dict            # operation variables (verbatim from request)
    raw_query: str             # the original query text (truncated for safety)

    def endpoint_key(self) -> str:
        """Stable identifier used for contract lookup and reporting.
        Examples:
          QUERY GetOrder
          MUTATION transferFunds
          QUERY <anonymous>:user
        """
        if self.op_name:
            return f"{self.op_type.upper()} {self.op_name}"
        # anonymous operation — use the first root field as a stable handle
        leaf = self.root_fields[0] if self.root_fields else "<unknown>"
        return f"{self.op_type.upper()} <anonymous>:{leaf}"


def parse_graphql_request(body: Any) -> GraphQLOperation | None:
    """Parse a GraphQL request body. Returns None if the body is not a parseable
    GraphQL request shape. Fail-safe: any ambiguity → None (caller falls back
    to REST handling)."""
    if not isinstance(body, dict):
        return None
    query = body.get("query")
    if not isinstance(query, str) or not query.strip():
        return None
    variables = body.get("variables") or {}
    if not isinstance(variables, dict):
        variables = {}
    op_name_explicit = body.get("operationName") or ""

    m = _OP_RE.match(query.lstrip())
    if m:
        op_type = m.group(1).lower()
        op_name = op_name_explicit or (m.group(2) or "")
    else:
        # shorthand `{ ... }` is query by definition
        if _SHORTHAND_RE.match(query):
            op_type = "query"
            op_name = op_name_explicit or ""
        else:
            return None

    # root field selections — only the first level inside the outermost {}.
    # We capture both `field(` and `alias: field(` and bare `field {`.
    aliases, roots = _root_selections(query)

    return GraphQLOperation(
        op_type=op_type, op_name=op_name,
        root_fields=roots, aliases=aliases, variables=variables,
        raw_query=query[:1200],
    )


def _root_selections(query: str) -> tuple[list[str], list[str]]:
    """Extract top-level field names + aliases from a GraphQL query.

    Lightweight: we find the outermost `{ ... }` and scan its body at depth 0.
    Handles aliased fields and field-with-args; ignores fragment spreads. This
    is signature-level — sufficient for classification and contract matching."""
    aliases: list[str] = []
    roots: list[str] = []
    # find outermost braces
    start = query.find("{")
    if start == -1:
        return aliases, roots
    depth = 0
    body_chars = []
    for i, ch in enumerate(query[start:]):
        if ch == "{":
            depth += 1
            if depth == 1:
                continue
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        if depth == 1:
            body_chars.append(ch)
    body = "".join(body_chars)
    # split top-level by commas/newlines, but the safest is regex over the body
    # for `alias: name(` or `name(` or `name `
    for m in re.finditer(
        r"(?:([A-Za-z_]\w*)\s*:\s*)?([A-Za-z_]\w*)(?=\s*[({\s])",
        body,
    ):
        alias, name = m.group(1), m.group(2)
        if name in {"on", "fragment"}:
            continue
        if alias and alias not in {"on", "fragment"}:
            aliases.append(alias)
        if name not in roots:
            roots.append(name)
    return aliases, roots


# --------------------------------------------------------------------------- #
# Response success — GraphQL signals failure via `errors`, not HTTP status     #
# --------------------------------------------------------------------------- #
def gql_succeeded(status: int, body: Any) -> bool:
    """A GraphQL operation truly succeeded only when:
      * HTTP status is 2xx, AND
      * the response body has no `errors` array (or it is empty), AND
      * `data` is present and not null.
    A 200 with `errors: [...]` is a SOFT FAILURE; treating it as success would
    inflate findings.  This is the Δstate dual of the same principle in REST."""
    if not (200 <= status < 300):
        return False
    if not isinstance(body, dict):
        return False
    errs = body.get("errors")
    if errs and isinstance(errs, list) and len(errs) > 0:
        return False
    if "data" in body and body["data"] is None:
        return False
    return True


# --------------------------------------------------------------------------- #
# Effect-class classification — mutation-name heuristics (contract overrides)  #
# --------------------------------------------------------------------------- #
# Each entry: (regex over the field name → suggested effect-class).
# Conservative: returns None if no pattern matches, letting the contract
# (or REST-style inference) take over.
_CC = r"(?=[A-Z_]|$)"   # camelCase-aware boundary: next is Upper, underscore, or end
_MUTATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^(?:set|update|grant|promote|assign|change)Role", re.I), "AUTHORITY"),
    (re.compile(r"(?:^|_)(?:make|set)Admin", re.I), "AUTHORITY"),
    (re.compile(r"(?:^|_)(?:pay|charge|transfer|capture|withdraw|refund|payout)" + _CC, re.I), "PAYMENT"),
    (re.compile(r"(?:^|_)(?:price|setPrice|repriceItem)", re.I), "PRICE"),
    (re.compile(r"(?:^|_)(?:redeem|applyCoupon|applyPromo|usePromo)" + _CC, re.I), "COUPON"),
    (re.compile(r"(?:^|_)(?:approve|release|activate|complete|finalize|fulfill|ship)" + _CC, re.I), "STATE_GATE"),
    (re.compile(r"(?:^|_)(?:update|edit|set|patch|modify|delete|remove)" + _CC, re.I), "OWNERSHIP"),
]
_QUERY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^(?:admin|allUsers|adminGet|listAllUsers)", re.I), "AUTHORITY"),
    (re.compile(r"^(?:user|order|invoice|account|profile|document|file)(?:s)?$", re.I), "OBJECT_ACCESS"),
]


def infer_effect_class(op: GraphQLOperation) -> str | None:
    """Heuristic only.  Returns the suggested effect-class for an inferred
    classification; the contract path overrides this when an explicit mapping
    exists."""
    patterns = _MUTATION_PATTERNS if op.op_type == "mutation" else _QUERY_PATTERNS
    for field in op.root_fields:
        for rx, eff in patterns:
            if rx.search(field):
                return eff
    return None


# --------------------------------------------------------------------------- #
# Variable-based object-id extraction                                          #
# --------------------------------------------------------------------------- #
# Variable names that conventionally carry object identifiers (and identity
# scope) — matches the REST identity-header allowlist in spirit.
_ID_VAR_NAMES = ("id", "user_id", "userId", "order_id", "orderId", "account_id",
                  "accountId", "customer_id", "customerId", "tenant_id",
                  "tenantId", "org_id", "orgId", "workspace_id", "workspaceId")


def extract_variable_ids(variables: dict) -> list[tuple[str, Any]]:
    """Return [(name, value)] pairs for variables that look like object-ids."""
    if not isinstance(variables, dict):
        return []
    out: list[tuple[str, Any]] = []
    for k, v in variables.items():
        if v is None:
            continue
        if k in _ID_VAR_NAMES or k.lower().endswith("id") or k.lower().endswith("_id"):
            out.append((k, v))
    return out


# --------------------------------------------------------------------------- #
# Introspection-driven contract building (off the hot path)                    #
# --------------------------------------------------------------------------- #
def contract_from_introspection(schema: dict) -> dict:
    """Build a partial ONYX contract from an introspection result.

    The operator runs `{ __schema { queryType { fields { name } } mutationType
    { fields { name } } } }` once and feeds the result here.  We emit best-guess
    effect classifications keyed by GraphQL endpoint_key; the operator is
    expected to review and tighten before scanning.  Per RL2, this is OFF the
    decision path."""
    contract: dict = {}
    data = schema.get("data") or schema
    sch = data.get("__schema") or data
    for kind, op_label in (("queryType", "QUERY"), ("mutationType", "MUTATION")):
        t = (sch or {}).get(kind) or {}
        for f in (t.get("fields") or []):
            name = f.get("name")
            if not name:
                continue
            stub = GraphQLOperation(op_label.lower(), name, [name], [], {}, name)
            eff = infer_effect_class(stub) or ("OBJECT_ACCESS" if op_label == "QUERY" else "OWNERSHIP")
            contract[f"{op_label} {name}"] = {
                "effect": eff,
                "source": "introspection-inferred",
            }
    return contract


# --------------------------------------------------------------------------- #
# Field-level projection: request <-> response (the GraphQL-native authz lens) #
# --------------------------------------------------------------------------- #
_AUTHZ_ERR_CODES = {
    "FORBIDDEN", "UNAUTHORIZED", "UNAUTHENTICATED", "ACCESS_DENIED",
    "PERMISSION_DENIED", "NOT_AUTHORIZED", "INSUFFICIENT_PERMISSIONS",
}
_AUTHZ_ERR_HINTS = ("not authorized", "not authorised", "forbidden", "permission",
                    "access denied", "unauthorized", "unauthorised",
                    "insufficient", "not allowed")


def response_data(body: Any) -> Any:
    """Project a GraphQL response onto its OBJECT GRAPH: return `data` so the
    structural engines analyse the real object, not the `{data,errors}` envelope.
    Returns None when there is no usable data tree (caller keeps the raw body)."""
    if not isinstance(body, dict) or "data" not in body:
        return None
    data = body.get("data")
    return data if isinstance(data, (dict, list)) else None


def _err_is_authz(err: dict) -> bool:
    ext = err.get("extensions") or {}
    code = str(ext.get("code") or ext.get("classification") or "").upper()
    if code in _AUTHZ_ERR_CODES:
        return True
    msg = str(err.get("message") or "").lower()
    return any(h in msg for h in _AUTHZ_ERR_HINTS)


def authz_denied_paths(body: Any) -> list[str]:
    """Dotted field-paths the server itself refused on AUTHORIZATION grounds:
    a field that was REQUESTED but returned with an authz-class error. This is
    the field-level boundary the backend discloses — a measured fact (0-FP), and
    the residual BOLA/BFLA signal in GraphQL where there is no PRESENT_NULL to
    find. Non-authz errors (validation, not-found, timeout) are ignored."""
    if not isinstance(body, dict):
        return []
    out: list[str] = []
    for err in (body.get("errors") or []):
        if not isinstance(err, dict) or not _err_is_authz(err):
            continue
        path = err.get("path")
        if isinstance(path, list) and path:
            # match the fingerprint path convention: list indices become [i],
            # nested under their parent key, so a denied list-element field aligns
            # with the structural populated-path (orders[0].internal, not orders.internal).
            parts: list[str] = []
            for p in path:
                if isinstance(p, bool):
                    continue
                if isinstance(p, int):
                    if parts:
                        parts[-1] = f"{parts[-1]}[{p}]"
                    continue
                parts.append(str(p))
            dotted = ".".join(parts)
            if dotted and dotted not in out:
                out.append(dotted)
    return out


# --------------------------------------------------------------------------- #
# Automatic Persisted Queries (APQ) — Residue A closure (#2-a)                 #
# --------------------------------------------------------------------------- #
# Hyperscale GraphQL (Google, Apollo-based stacks) sends a sha256 HASH instead
# of the query text to save bandwidth. The text is sent ONCE (registration);
# every later call carries only the hash + variables. To a per-request tool the
# intent is opaque. But the hash is NOT encryption — it is a reference to a text
# the engine can OBSERVE at registration time. We learn `hash -> operation` from
# that one observation (RL1: measured, never guessed) and resolve every later
# hash-only request from the learned map. When the text was never observed, the
# hash itself is a STABLE identity key (same query => same hash for every
# principal), which still permits a hash-keyed cross-principal differential.
# This lives entirely behind the cross-surface flag (callers below are only
# reached from the flag-gated ledger), so global GraphQL detection is unchanged.

def persisted_query_hash(body) -> "str | None":
    """The APQ sha256 hash carried in extensions.persistedQuery, or None.
    Tolerant of the standard Apollo shape and a flattened variant."""
    if not isinstance(body, dict):
        return None
    ext = body.get("extensions")
    if isinstance(ext, dict):
        pq = ext.get("persistedQuery")
        if isinstance(pq, dict):
            h = pq.get("sha256Hash") or pq.get("sha256") or pq.get("hash")
            if isinstance(h, str) and h:
                return h
    return None


def is_persisted_query(body) -> bool:
    """A request that carries a persisted-query hash (with or without text)."""
    return persisted_query_hash(body) is not None


class PersistedQueryRegistry:
    """Learns hash -> query-text from observed APQ registrations, then resolves
    hash-only requests to their operation. Pure data; deterministic; no guessing
    — a hash with no observed text resolves to a SYNTHETIC operation keyed by the
    hash (stable across principals) so a cross-principal differential still works,
    but its resource TYPE is the hash handle rather than a real root field."""

    def __init__(self) -> None:
        self._by_hash: dict = {}          # hash -> query text

    def observe(self, body) -> None:
        """If this body carries BOTH a hash and the query text, learn the mapping."""
        h = persisted_query_hash(body)
        if not h or not isinstance(body, dict):
            return
        q = body.get("query")
        if isinstance(q, str) and q.strip() and h not in self._by_hash:
            self._by_hash[h] = q

    def has(self, h: str) -> bool:
        return h in self._by_hash

    def resolve_op(self, body) -> "GraphQLOperation | None":
        """Return the GraphQLOperation a body addresses, resolving APQ hashes.
          * query text present            -> parse it directly (registers too).
          * hash present, text learned    -> parse the learned text, keep THIS
                                             request's variables.
          * hash present, text unknown    -> a synthetic op keyed by the hash, with
                                             this request's variables (stable id).
          * neither                       -> None.
        """
        if not isinstance(body, dict):
            return None
        if isinstance(body.get("query"), str) and body["query"].strip():
            self.observe(body)
            return parse_graphql_request(body)
        h = persisted_query_hash(body)
        if not h:
            return None
        variables = body.get("variables") or {}
        if not isinstance(variables, dict):
            variables = {}
        learned = self._by_hash.get(h)
        if learned:
            op = parse_graphql_request({"query": learned, "variables": variables,
                                        "operationName": body.get("operationName") or ""})
            if op is not None:
                return op
        # text unknown — synthetic, hash-keyed operation (stable identity)
        return GraphQLOperation(
            op_type="query", op_name=f"persisted:{h[:16]}",
            root_fields=[f"persisted:{h[:16]}"], aliases=[],
            variables=variables, raw_query="")
