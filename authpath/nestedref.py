"""
GAP 2 — nested object-reference extraction & swap.

BOLA also manifests in request BODIES, nested object graphs, and query strings — not
just path ids. ONYX extracted/swapped PATH ids only, so those surfaces were never
probed across principals. This module finds object-reference FIELDS anywhere in a
body (including nested JSON) and in the query string, and generates
structure-preserving SWAP candidates (replace one principal's ref with another's).

CONSERVATIVE by design: a field is treated as an object reference ONLY if its NAME
matches an id-pattern AND its VALUE matches a known id-shape (reused from idformat).
Non-reference fields (amount, name, description) are never swapped. It only PROPOSES
candidate requests; the engine's Δstate read-back gates every finding, so it cannot
add a false positive. Output is bounded and deterministic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# field NAMES that denote an object reference (conservative whitelist of patterns)
_REF_NAME = re.compile(
    r"(^|_)(id|uid|gid|guid|uuid|ref|owner|account|acct|user|customer|member|"
    r"order|invoice|doc|document|file|project|group|ticket|record|object|entity)"
    r"(_id|_ref|_uid|_uuid|_key|_no|_number)?$",
    re.IGNORECASE,
)
_NEVER = re.compile(r"(^|_)(amount|price|qty|quantity|count|total|sum|name|title|"
                    r"description|email|phone|date|time|status|type|role)$",
                    re.IGNORECASE)


@dataclass
class RefField:
    location: str            # "body" | "query" | "header" | "gql_var" | "jwt"
    json_path: str           # dotted path, e.g. "doc.id" or "from_account"
    value: str
    confidence: int
    swappable: bool = True   # G10: JWT claims are extraction-only (signed → not forgeable)


def _is_ref_name(name: str) -> bool:
    if _NEVER.search(name):
        return False
    return bool(_REF_NAME.search(name))


def _walk(obj, prefix, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                _walk(v, path, out)
            else:
                out.append((path, k, v))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            path = f"{prefix}.{i}"
            if isinstance(v, (dict, list)):
                _walk(v, path, out)
            else:
                out.append((path, str(i), v))


def find_refs(body=None, query: dict | None = None, *, min_confidence: int = 70,
              headers: dict | None = None, variables: dict | None = None) -> list:
    """Find object-reference fields in a body (nested) and/or query string.

    G10 — reference sources extended beyond body+query to headers, JWT claims, and
    GraphQL variables. New sources default to None ⇒ byte-identical to the prior
    body+query behavior. Every new source reuses the SAME conservative guards
    (`_is_ref_name` + `_NEVER` + `detect_shape`); JWT claims are extraction-only
    (`swappable=False`) because a signed token cannot be forged with a swapped ref.
    """
    from .idformat import detect_shape
    refs = []
    flat = []
    if isinstance(body, (dict, list)):
        _walk(body, "", flat)
    for path, key, val in flat:
        if not isinstance(val, (str, int)):
            continue
        if not _is_ref_name(key):
            continue
        shape = detect_shape(val)
        if shape.confidence >= min_confidence or _is_strong_ref_name(key):
            refs.append(RefField("body", path, str(val), shape.confidence))
    for key, val in (query or {}).items():
        if not _is_ref_name(key) or not isinstance(val, (str, int)):
            continue
        shape = detect_shape(val)
        if shape.confidence >= min_confidence or _is_strong_ref_name(key):
            refs.append(RefField("query", str(key), str(val), shape.confidence))
    # G10 new sources
    refs.extend(_refs_from_headers(headers, min_confidence))
    refs.extend(_refs_from_gql_variables(variables, min_confidence))
    refs.extend(_refs_from_jwt(headers, min_confidence))
    refs.sort(key=lambda r: (r.location, r.json_path))     # deterministic
    return refs


# Header names normalise to a ref-name check (strip a leading X-, dashes→underscores).
def _normalise_header_name(name: str) -> str:
    n = name.strip().lower()
    if n.startswith("x-"):
        n = n[2:]
    return n.replace("-", "_")


def _refs_from_headers(headers: dict | None, min_confidence: int) -> list:
    """Identity-bearing / reference headers (X-Customer-ID, X-Tenant-ID, X-User-Id…).
    Skips the Authorization header itself (handled by the JWT extractor)."""
    from .idformat import detect_shape
    if not headers:
        return []
    out = []
    for raw_name, val in headers.items():
        if raw_name.lower() in ("authorization", "cookie", "set-cookie"):
            continue
        if not isinstance(val, (str, int)):
            continue
        name = _normalise_header_name(str(raw_name))
        if not _is_ref_name(name):
            continue
        shape = detect_shape(str(val))
        if shape.confidence >= min_confidence or _is_strong_ref_name(name):
            out.append(RefField("header", str(raw_name), str(val), shape.confidence))
    return out


def _b64url_decode(seg: str) -> bytes:
    import base64
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _refs_from_jwt(headers: dict | None, min_confidence: int) -> list:
    """Extract reference-like CLAIMS from a bearer JWT payload. Extraction-only:
    `swappable=False` (a signed token cannot be re-forged with a swapped ref). Used
    for cross-step provenance/observation, never for swap candidates. Fail-safe:
    any parse error ⇒ no claims (never raises)."""
    from .idformat import detect_shape
    if not headers:
        return []
    auth = None
    for k, v in headers.items():
        if k.lower() == "authorization" and isinstance(v, str):
            auth = v
            break
    if not auth:
        return []
    tok = auth.split(None, 1)[1].strip() if auth.lower().startswith("bearer ") else auth
    parts = tok.split(".")
    if len(parts) < 2:
        return []
    try:
        import json
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    out = []
    for k, val in payload.items():
        if not isinstance(val, (str, int)) or not _is_ref_name(str(k)):
            continue
        shape = detect_shape(str(val))
        if shape.confidence >= min_confidence or _is_strong_ref_name(str(k)):
            out.append(RefField("jwt", str(k), str(val), shape.confidence, swappable=False))
    return out


def _refs_from_gql_variables(variables: dict | None, min_confidence: int) -> list:
    """GraphQL operation variables carry object refs (ids) that per-request checks
    often miss. Walk them like a body; same guards; swappable (they are client-sent)."""
    from .idformat import detect_shape
    if not isinstance(variables, (dict, list)):
        return []
    flat = []
    _walk(variables, "", flat)
    out = []
    for path, key, val in flat:
        if not isinstance(val, (str, int)) or not _is_ref_name(str(key)):
            continue
        shape = detect_shape(str(val))
        if shape.confidence >= min_confidence or _is_strong_ref_name(str(key)):
            out.append(RefField("gql_var", path, str(val), shape.confidence))
    return out


def _is_strong_ref_name(name: str) -> bool:
    """Names so clearly an object ref that a low-entropy value is still swappable."""
    return bool(re.search(r"(^|_)(id|uuid|gid|account|owner)(_id)?$", name, re.IGNORECASE))


def _set_by_path(obj, path: str, new_value):
    """Return a deep-ish copy of obj with the value at dotted path replaced."""
    import copy
    clone = copy.deepcopy(obj)
    cur = clone
    parts = path.split(".")
    for p in parts[:-1]:
        cur = cur[int(p)] if isinstance(cur, list) else cur[p]
    last = parts[-1]
    if isinstance(cur, list):
        cur[int(last)] = new_value
    else:
        cur[last] = new_value
    return clone


def swap_ref(body, query, ref: RefField, new_value, headers=None, variables=None):
    """Rebuild the request with ONLY the target reference replaced (exact). Handles
    all G10 locations. JWT claims are NOT swappable (signed → not forgeable): swapping
    one raises, so callers must filter on `ref.swappable` first."""
    if ref.location == "body":
        return _set_by_path(body, ref.json_path, new_value), query
    if ref.location == "query":
        new_query = dict(query or {})
        new_query[ref.json_path] = new_value
        return body, new_query
    if ref.location == "header":
        # header swap is returned via the query slot's sibling; callers that need the
        # new header use swap_ref_full below. Kept for body/query back-compat here.
        return body, query
    if ref.location == "jwt":
        raise ValueError("JWT claims are not swappable (signed token cannot be forged)")
    # gql_var handled by swap_ref_full
    return body, query


def swap_ref_full(*, body=None, query=None, headers=None, variables=None,
                  ref: RefField, new_value):
    """Location-complete swap: returns (body, query, headers, variables) with only the
    target reference replaced. Refuses JWT (not forgeable)."""
    if not ref.swappable or ref.location == "jwt":
        raise ValueError("reference is not swappable (e.g. a signed JWT claim)")
    b, q, h, v = body, dict(query or {}), dict(headers or {}), variables
    if ref.location == "body":
        b = _set_by_path(body, ref.json_path, new_value)
    elif ref.location == "query":
        q[ref.json_path] = new_value
    elif ref.location == "header":
        h[ref.json_path] = new_value
    elif ref.location == "gql_var":
        v = _set_by_path(variables, ref.json_path, new_value)
    return b, q, h, v


def generate_swaps(body, query, victim_ids, *, max_swaps: int = 50,
                   enabled: bool = False, min_confidence: int = 70) -> list:
    """For each detected reference, propose swaps to each victim id. enabled=False
    (default) => [] (no behaviour change). Returns list of (ref, new_value,
    new_body, new_query). Every probe is still Δstate-gated downstream."""
    if not enabled:
        return []
    out = []
    refs = find_refs(body, query, min_confidence=min_confidence)
    for ref in refs:
        for vid in victim_ids:
            if str(vid) == ref.value:
                continue
            nb, nq = swap_ref(body, query, ref, vid)
            out.append({"ref_path": ref.json_path, "location": ref.location,
                        "old": ref.value, "new": str(vid),
                        "body": nb, "query": nq})
            if len(out) >= max_swaps:
                return out
    return out
