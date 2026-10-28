"""
Protocol generalization for giant surfaces (protocol [21], gap G2).
================================================================================
ONYX already addresses objects across REST paths, query ids, identity headers, JWT claims,
and GraphQL variables. Giant surfaces add carriers it did not see, so their objects were
invisible — and an object ONYX cannot SEE is a BOLA it cannot find:

  * OPAQUE / SIGNED ids — base64url handles, signed cursors, encrypted ids ("AItOawn9-Xk...")
    that numeric/uuid detection skips.
  * BATCH / ALIASED operations — one request carrying N sub-operations (JSON-RPC batch
    arrays, GraphQL alias batching, OData $batch); ONYX saw one object, missed the rest.
  * gRPC via JSON transcoding (google.api.http) — object ids live in the transcoded JSON.

This module recognises those carriers so the objects become ADDRESSABLE. It only EXPANDS
what ONYX can address; it never confirms. The Δstate confirmer still decides truth, so a
newly-addressable but safe object yields no finding — zero-FP preserved by construction.

Wall: raw binary protobuf / custom framing with no transcoding is not black-box
introspectable; the operator supplies a decoder, or that surface abstains. Declared.
"""
from __future__ import annotations
import re, json, base64

# an opaque object handle: long base64url / token-like, not a normal word or number-with-units
_OPAQUE = re.compile(r"^[A-Za-z0-9_\-]{16,}={0,2}$")
_LOOKS_ENCODED = re.compile(r"[A-Za-z].*[0-9]|[0-9].*[A-Za-z]")   # mixed alnum (not a plain word)


def is_opaque_id(value) -> bool:
    """True for an opaque/signed object identifier a giant would use — long, base64url-ish,
    mixed alphanumeric — that numeric/uuid detection misses. Deliberately conservative: a
    plain english word or a short token is NOT opaque (avoids over-tagging)."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if len(v) < 16 or not _OPAQUE.match(v):
        return False
    if not _LOOKS_ENCODED.search(v):
        return False                       # e.g. "documentification" (all letters) -> not an id
    # reject normal sentence-y tokens: an id has high char diversity
    return len(set(v)) >= 8


def opaque_ids_in(obj) -> list:
    """All opaque object identifiers reachable in a JSON-ish structure (values only)."""
    out, seen = [], set()

    def walk(n):
        if isinstance(n, dict):
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for x in n:
                walk(x)
        elif is_opaque_id(n):
            if n not in seen:
                seen.add(n); out.append(n)
    walk(obj)
    return out


def batch_operations(body) -> list:
    """Decompose a batched request into its sub-operations. Recognises:
      * JSON-RPC / generic batch: a top-level list of op dicts (each with method/path/params).
      * OData/Graph $batch: {"requests":[{id,method,url,body},...]}.
      * GraphQL alias batching: a single query whose selection set has aliased root fields.
    Returns a list of {op, path, ids} dicts — one per sub-operation — so each object becomes
    independently addressable."""
    ops = []

    def op_ids(d):
        ids = []
        for key in ("id", "url", "path", "params", "variables", "body", "input"):
            v = d.get(key) if isinstance(d, dict) else None
            if isinstance(v, str):
                ids.append(v)
                for seg in v.split("/"):        # pull an opaque id out of a url path
                    if is_opaque_id(seg):
                        ids.append(seg)
            elif isinstance(v, int):
                ids.append(str(v))
            elif isinstance(v, dict):
                ids += [str(x) for x in v.values() if isinstance(x, (str, int))]
        ids += opaque_ids_in(d)
        return list(dict.fromkeys(ids))

    if isinstance(body, list):                       # JSON-RPC / generic batch array
        for d in body:
            if isinstance(d, dict):
                ops.append({"op": d.get("method") or d.get("op") or "batch",
                            "path": d.get("url") or d.get("path") or "", "ids": op_ids(d)})
    elif isinstance(body, dict) and isinstance(body.get("requests"), list):   # OData $batch
        for d in body["requests"]:
            if isinstance(d, dict):
                ops.append({"op": d.get("method", "batch"),
                            "path": d.get("url", ""), "ids": op_ids(d)})
    elif isinstance(body, dict) and isinstance(body.get("query"), str):       # GraphQL aliases
        # aliased root fields:  alias1: user(id: "X") { ... }  alias2: order(id:"Y")
        for m in re.finditer(r'(\w+)\s*:\s*\w+\s*\(\s*[^)]*?id\s*:\s*"?([A-Za-z0-9_\-]+)"?',
                             body["query"]):
            ops.append({"op": f"gql:{m.group(1)}", "path": "graphql", "ids": [m.group(2)]})
    return ops


def grpc_transcoded_ids(body, headers=None) -> list:
    """Object-ids from a gRPC call exposed via JSON transcoding (google.api.http). The
    content-type marks it; the ids live in the transcoded JSON body like any REST call."""
    ct = ""
    if headers:
        ct = str({k.lower(): v for k, v in headers.items()}.get("content-type", "")).lower()
    transcoded = ("grpc" in ct) or (isinstance(body, dict) and "@type" in body)
    if not transcoded:
        return []
    ids = []

    def walk(n, k=""):
        if isinstance(n, dict):
            for kk, v in n.items():
                walk(v, kk)
        elif isinstance(n, list):
            for x in n:
                walk(x, k)
        elif isinstance(n, (str, int)):
            if k.lower().endswith(("id", "name", "ref")) or is_opaque_id(n):
                ids.append(str(n))
    walk(body)
    return list(dict.fromkeys(ids))


def extra_object_ids(request) -> list:
    """Unified extra carriers for the deficiency/giant object model: opaque ids in the body,
    batch sub-operation ids, and gRPC-transcoded ids. Additive to the existing REST/GraphQL/
    JWT carriers — only expands addressability, never confirms."""
    body = getattr(request, "body", None)
    headers = getattr(request, "headers", None)
    ids = []
    ids += opaque_ids_in(body)
    for op in batch_operations(body):
        ids += op["ids"]
    ids += grpc_transcoded_ids(body, headers)
    # opaque ids can also hide in the path or query values
    for seg in (getattr(request, "path", "") or "").split("/"):
        if is_opaque_id(seg):
            ids.append(seg)
    for v in (getattr(request, "query", {}) or {}).values():
        if is_opaque_id(v):
            ids.append(str(v))
    return list(dict.fromkeys(ids))
