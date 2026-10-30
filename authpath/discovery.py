"""
PROBLEM 1 — endpoint discovery (the "discover-then-test" bridge).

ONYX's detection (Δstate) is strong, but on a large target it only ever sees the
handful of endpoints that happened to appear in the capture. Real APIs expose
hundreds/thousands; every endpoint NOT observed is invisible and therefore untested.

This module EXPANDS the tested surface from AUTHORITATIVE, READ-ONLY sources and
feeds the result into the EXISTING engine — it never changes how a finding is judged:

  * OpenAPI / Swagger documents (declared routes + schemas)  -> contract + candidates
  * GraphQL introspection (reuses graphql.contract_from_introspection)
  * merge with the endpoints already observed in the capture, de-duplicated and
    RANKED by IDOR-likelihood (object-bearing GETs first)

It is structurally impossible for discovery to add a false positive: it only proposes
WHAT to test; every resulting finding is still confirmed by the engine's Δstate
read-back. Auto-generated probes are GET-only (object reads). Discovered mutating
endpoints (POST/PUT/PATCH/DELETE) are recorded for chains/manual use but NEVER
auto-probed. All output is deterministic (sorted, stable).

HONEST BOUNDARY: this finds DECLARED endpoints. Hidden/undocumented endpoints need
JS/source-map mining + fuzzing (noisier, separate) — not claimed here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# defensive caps against a hostile/huge document
_MAX_PATHS = 5000
_MAX_DEPTH = 40

# path parameter detector: /users/{id}, /users/:id, /users/<id>
_PARAM = re.compile(r"\{[^}/]+\}|:[A-Za-z_][A-Za-z0-9_]*|<[^>/]+>")
_ID_HINT = re.compile(r"(?:^|[/_-])(id|uid|uuid|gid|pid|guid|key|ref|number|no|slug)s?$",
                      re.IGNORECASE)


@dataclass
class Endpoint:
    method: str
    path: str                       # template form, e.g. /api/orders/{id}
    params: list = field(default_factory=list)
    effect: str = "NONE"            # conservative effect-class hint
    source: str = "openapi"
    idor_score: int = 0             # ranking: higher = more IDOR-likely

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"


# --------------------------------------------------------------------------- #
# effect-class inference — CONSERVATIVE (wrong-but-safe, never wrong-but-FP)
# --------------------------------------------------------------------------- #
def _infer_effect(method: str, path: str, has_path_param: bool) -> str:
    m = method.upper()
    if m == "GET":
        # a GET that takes an object id is the classic OBJECT_ACCESS / IDOR surface
        return "OBJECT_ACCESS" if has_path_param else "NONE"
    if m in ("PUT", "PATCH", "DELETE"):
        return "STATE_GATE" if has_path_param else "NONE"
    if m == "POST":
        return "STATE_GATE"
    return "NONE"


def _idor_score(method: str, path: str, has_param: bool) -> int:
    s = 0
    if method.upper() == "GET" and has_param:
        s += 10                                   # prime IDOR surface
    last = path.rstrip("/").split("/")[-1] if path else ""
    if _ID_HINT.search(last) or _PARAM.search(last):
        s += 5
    for kw in ("user", "account", "order", "invoice", "payment", "document",
               "file", "message", "profile", "member", "project", "group", "ticket"):
        if kw in path.lower():
            s += 2
    return s


# --------------------------------------------------------------------------- #
# OpenAPI / Swagger parser
# --------------------------------------------------------------------------- #
def parse_openapi(doc: dict) -> list:
    """Parse an OpenAPI 3.x or Swagger 2.0 document into ranked Endpoints. Tolerant
    of missing fields; bounded against hostile documents; never raises on shape."""
    if not isinstance(doc, dict):
        return []
    base = ""
    # OpenAPI 3 servers[].url (path part) or Swagger 2 basePath
    try:
        servers = doc.get("servers") or []
        if servers and isinstance(servers, list) and isinstance(servers[0], dict):
            url = servers[0].get("url", "")
            m = re.search(r"https?://[^/]+(/.*)$", url)
            base = (m.group(1) if m else (url if url.startswith("/") else "")).rstrip("/")
        elif doc.get("basePath"):
            base = str(doc["basePath"]).rstrip("/")
    except Exception:
        base = ""

    out = []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    for raw_path, item in list(paths.items())[:_MAX_PATHS]:
        if not isinstance(raw_path, str) or not isinstance(item, dict):
            continue
        full = base + raw_path if not raw_path.startswith(base or "\x00") else raw_path
        full = re.sub(r"/{2,}", "/", full) or "/"
        has_param = bool(_PARAM.search(full))
        params = _PARAM.findall(full)
        for method, _op in item.items():
            mu = method.upper()
            if mu not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            eff = _infer_effect(mu, full, has_param)
            out.append(Endpoint(method=mu, path=full, params=params, effect=eff,
                                source="openapi",
                                idor_score=_idor_score(mu, full, has_param)))
    return _dedup_sorted(out)


def parse_graphql_introspection(schema: dict) -> list:
    """Reuse the existing graphql contract extraction; expose discovered operations
    as Endpoints so they rank/merge alongside REST."""
    out = []
    try:
        from .graphql import contract_from_introspection
        contract = contract_from_introspection(schema) or {}
        for key, meta in contract.items():
            # key looks like "QUERY user" / "MUTATION transferFunds"
            parts = key.split()
            method = parts[0] if parts else "QUERY"
            eff = (meta or {}).get("effect", "NONE")
            out.append(Endpoint(method=method, path=key, params=[], effect=eff,
                                source="graphql",
                                idor_score=8 if method == "QUERY" else 4))
    except Exception:
        pass
    return _dedup_sorted(out)


def _dedup_sorted(eps: list) -> list:
    seen, uniq = set(), []
    for e in eps:
        if e.key in seen:
            continue
        seen.add(e.key); uniq.append(e)
    # stable, deterministic ordering: IDOR-likelihood desc, then key asc
    uniq.sort(key=lambda e: (-e.idor_score, e.key))
    return uniq


# --------------------------------------------------------------------------- #
# discover -> test bridge
# --------------------------------------------------------------------------- #
def merge_with_observed(discovered: list, observed_keys: set) -> list:
    """Mark which discovered endpoints were already seen in the capture (observed
    endpoints are 'warm' — real ids are likely available to thread into probes)."""
    obs = {k.upper() for k in (observed_keys or set())}
    for e in discovered:
        if e.key.upper() in obs:
            e.source = e.source + "+observed"
    return discovered


def build_contract(discovered: list) -> dict:
    """Engine-consumable contract: endpoint key -> {effect}. Only endpoints with a
    real effect-class are emitted (NONE is dropped so the engine skips them)."""
    return {e.key: {"effect": e.effect} for e in discovered if e.effect != "NONE"}


def generate_probes(discovered: list, observed_ids_by_path: dict,
                    attacker_pid: str, max_probes: int = 200) -> list:
    """Generate GET-only cross-principal probe candidates: for each object-bearing
    GET endpoint, have the attacker request an object id the capture shows belongs
    to someone else. NEVER generates mutating probes (safety). Bounded + deterministic.

    observed_ids_by_path maps a path TEMPLATE -> [ids seen for it in the capture].
    """
    probes = []
    for e in discovered:
        if e.method.upper() != "GET" or e.effect != "OBJECT_ACCESS":
            continue                                  # GET object reads only
        # only SINGLE-parameter object templates are auto-probed; multi-param paths
        # (/users/{uid}/orders/{oid}) are skipped to avoid filling the wrong segment
        # (the matrix handles multi-param via concrete observed paths instead).
        if len(_PARAM.findall(e.path)) != 1:
            continue
        ids = observed_ids_by_path.get(e.path) or []
        for oid in ids:
            concrete = _fill_first_param(e.path, oid)
            if concrete is None:
                continue
            probes.append({"principal": attacker_pid, "method": "GET",
                           "path": concrete, "_discovered_from": e.key})
            if len(probes) >= max_probes:
                return probes
    return probes


def _fill_first_param(template: str, value) -> str | None:
    if not _PARAM.search(template):
        return None
    return _PARAM.sub(lambda m: str(value), template, count=1)


def summarize(discovered: list) -> dict:
    by_effect = {}
    for e in discovered:
        by_effect[e.effect] = by_effect.get(e.effect, 0) + 1
    return {
        "total": len(discovered),
        "object_access_GET": sum(1 for e in discovered
                                 if e.method == "GET" and e.effect == "OBJECT_ACCESS"),
        "by_effect": by_effect,
        "top_idor_candidates": [e.key for e in discovered[:10] if e.idor_score >= 10],
    }
