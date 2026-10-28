"""
authpath.acquisition — SPEC ACQUISITION (RL12: the live-network slice of RL8).

RL8 derives the surface AROUND observed traffic (siblings/collections/parents). It
cannot reach a whole subsystem the capture never touched. The authoritative API
spec can: an OpenAPI document lists every declared endpoint, and a GraphQL schema
(via introspection) lists every operation. ONYX's `discovery` module could PARSE a
spec it was handed but had no way to GO GET one from the live target — a
spec-parsing model with no spec-acquisition model.

This module adds the acquirer. Given a target + host it ACTIVELY fetches candidate
specs and returns parsed endpoints in a SurfaceGraph, so they flow into the same
RL8 probe synthesis + RL6 allocator + Δstate confirmer pipeline.

Non-negotiables (this is the first ACTIVE-network capability, so safety is sharper):
  * READ-ONLY (RL5). OpenAPI fetches are GET. The GraphQL introspection request is
    a POST but a pure READ (introspection never mutates). No other verbs.
  * SCOPE-GUARDED. Every request goes through the ScopeGuard — out-of-scope hosts
    are never touched.
  * BOUNDED (RL6). Every fetch draws one request from the budget ledger; the
    well-known path list is a small fixed set (not a wordlist). Budget exhaustion
    or a frozen host stops acquisition immediately.
  * FAIL-SAFE. A 404 / non-spec / corrupt / hostile response is IGNORED — never
    treated as a spec, never crashes. Acquisition can only ADD real endpoints.
  * HONEST. Acquired endpoints are tagged source="acquired-spec" and become PROBES;
    they are never findings. The Δstate confirmer still proves everything.

Deterministic: a fixed, ordered path list; no clock, no randomness.
"""
from __future__ import annotations

from typing import Optional

from .discovery import parse_openapi, parse_graphql_introspection, Endpoint
from .surface import SurfaceGraph
from .models import HTTPRequest
from .scope_guard import ScopeVerdict

# Conventional, ordered, BOUNDED well-known OpenAPI/Swagger locations. Not a
# wordlist — just the handful of de-facto standard spec paths.
OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/.well-known/openapi.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/v1/openapi.json",
)

# Conventional GraphQL endpoints to try introspection against.
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql")

# The standard GraphQL introspection query (read-only). Trimmed to what
# contract_from_introspection consumes: type names, kinds, fields, args.
INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { "
    "queryType { name fields { name args { name } } } "
    "mutationType { name fields { name args { name } } } "
    "} }"
)


class SpecAcquirer:
    """Actively acquire an API spec from a live target, safely and within budget."""

    def __init__(self, target, scope_guard, ledger=None):
        self.target = target
        self.scope = scope_guard
        if ledger is None:
            from .economy import BudgetLedger
            ledger = BudgetLedger.unbounded()
        self.ledger = ledger
        self.attempts: list = []        # (path, status/outcome) — for honest reporting

    # -- one safe, bounded, scope-guarded read ----------------------------- #
    def _read(self, method: str, path: str, host: str, principal, body=None):
        """Issue one read-only request, gated by scope + budget. Returns the
        response or None (out of scope / over budget / error). Never raises."""
        req = HTTPRequest(method, path, host=host, body=body)
        try:
            decision = self.scope.check(req)
            if decision.verdict is ScopeVerdict.HALT:
                self.attempts.append((path, "out-of-scope"))
                return None
        except Exception:
            return None
        if not self.ledger.acquire(host):
            self.attempts.append((path, "over-budget"))
            return None
        try:
            return self.target.send(req, principal)
        except Exception:
            self.attempts.append((path, "error"))
            return None

    # -- OpenAPI / Swagger -------------------------------------------------- #
    def acquire_openapi(self, host: str, principal) -> list:
        """GET each well-known OpenAPI path; the FIRST response that is a valid
        OpenAPI/Swagger document is parsed. Returns parsed Endpoints (possibly [])."""
        for path in OPENAPI_PATHS:
            resp = self._read("GET", path, host, principal)
            if resp is None:
                continue
            doc = self._as_spec_doc(resp)
            if doc is None:
                self.attempts.append((path, f"status={getattr(resp,'status','?')} not-a-spec"))
                continue
            eps = parse_openapi(doc)
            if eps:
                self.attempts.append((path, f"OpenAPI spec parsed ({len(eps)} endpoints)"))
                return eps
        return []

    def _as_spec_doc(self, resp) -> Optional[dict]:
        """Validate that a response body is an OpenAPI/Swagger doc (decoding wire
        formats via RL7 if needed). Fail-safe: anything else ⇒ None."""
        if resp is None or not (200 <= getattr(resp, "status", 0) < 300):
            return None
        body = resp.body
        if not isinstance(body, (dict, list)):
            try:
                from .codec import normalize_body
                body = normalize_body(body).data
            except Exception:
                return None
        if not isinstance(body, dict):
            return None
        # an OpenAPI/Swagger doc declares its version AND a paths object
        if ("openapi" in body or "swagger" in body) and isinstance(body.get("paths"), dict):
            return body
        return None

    # -- GraphQL introspection --------------------------------------------- #
    def acquire_graphql(self, host: str, principal) -> list:
        """POST the standard introspection query to conventional GraphQL paths; the
        FIRST response carrying a __schema is parsed. Read-only."""
        body = {"query": INTROSPECTION_QUERY}
        for path in GRAPHQL_PATHS:
            resp = self._read("POST", path, host, principal, body=body)
            if resp is None:
                continue
            schema = self._as_schema(resp)
            if schema is None:
                continue
            eps = parse_graphql_introspection(schema)
            if eps:
                self.attempts.append((path, f"GraphQL schema introspected ({len(eps)} ops)"))
                return eps
        return []

    def _as_schema(self, resp) -> Optional[dict]:
        if resp is None or not (200 <= getattr(resp, "status", 0) < 300):
            return None
        body = resp.body
        if not isinstance(body, (dict, list)):
            try:
                from .codec import normalize_body
                body = normalize_body(body).data
            except Exception:
                return None
        if not isinstance(body, dict):
            return None
        # introspection result: {data: {__schema: {...}}} or {__schema: {...}}
        if isinstance(body.get("__schema"), dict):
            return body
        data = body.get("data")
        if isinstance(data, dict) and isinstance(data.get("__schema"), dict):
            return body
        return None

    # -- combined ----------------------------------------------------------- #
    def acquire(self, host: str, principal) -> SurfaceGraph:
        """Acquire OpenAPI + GraphQL specs and return a SurfaceGraph of the declared
        endpoints, tagged source='acquired-spec' so they rank below observed traffic
        but feed the same probe-synthesis pipeline. Always safe to call — an empty
        graph just means nothing was acquired."""
        g = SurfaceGraph()
        for eps in (self.acquire_openapi(host, principal),
                    self.acquire_graphql(host, principal)):
            for e in eps:
                g.add(Endpoint(method=e.method, path=e.path, params=e.params,
                               effect=e.effect, source="acquired-spec",
                               idor_score=e.idor_score))
        return g
