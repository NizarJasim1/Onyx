"""
㉒ State-machine inference (Gap G9) — target SELECTION only, pure logic.

ONYX probes blind without knowing which multi-step sequences exist. Infer
producer->consumer relations from an OpenAPI spec and flag validate-then-commit
seams. CRITICAL: inference only PRODUCES TARGET CANDIDATES — it never reports; every
candidate must pass an independent Δstate confirmer first. This keeps zero-FP even
though inference is heuristic.

FP gate: SM-0 inference yields candidates, never findings; SM-1 each candidate must
pass an independent Δstate confirmer before any report; SM-2 seams are directional
only; SM-3 default-OFF.
"""
from __future__ import annotations

_VERBS = ("get", "post", "put", "patch", "delete")


def _ops(path_item):
    if not isinstance(path_item, dict):
        return []
    return [(v.upper(), op) for v, op in path_item.items() if v.lower() in _VERBS and isinstance(op, dict)]


def _path_param_names(path):
    import re
    return set(re.findall(r"\{([^}]+)\}", path or ""))


def _produced_ids(op):
    """Ref names an operation likely produces: OpenAPI links + a created-resource id."""
    out = set()
    for resp in (op.get("responses", {}) or {}).values():
        if isinstance(resp, dict):
            for lname in (resp.get("links", {}) or {}):
                out.add(str(lname).lower())
    # a 201/200 that returns an object with an id
    out.add("id")
    return out


def infer_producer_consumer(openapi_spec):
    """Return (producer_op, consumer_op, shared_ref) candidate edges. Candidates only."""
    edges = []
    paths = (openapi_spec or {}).get("paths", {}) if isinstance(openapi_spec, dict) else {}
    for c_path, c_item in paths.items():
        cparams = _path_param_names(c_path)
        for c_verb, c_op in _ops(c_item):
            for p_path, p_item in paths.items():
                if p_path == c_path:
                    continue
                for p_verb, p_op in _ops(p_item):
                    if p_verb not in ("POST", "PUT"):
                        continue
                    # consumer references an id in its path that a producer creates
                    for ref in cparams:
                        if "id" in ref.lower():
                            edges.append((f"{p_verb} {p_path}", f"{c_verb} {c_path}", ref))
                            break
    # de-dup, deterministic
    return sorted(set(edges))


def find_validate_commit_seams(openapi_spec):
    """Flag endpoints with 202/PENDING responses — directional seams (SM-2)."""
    seams = []
    paths = (openapi_spec or {}).get("paths", {}) if isinstance(openapi_spec, dict) else {}
    for path, item in paths.items():
        for verb, op in _ops(item):
            responses = op.get("responses", {}) or {}
            if "202" in responses:
                seams.append((f"{verb} {path}", "async-commit-seam"))
    return sorted(set(seams))
