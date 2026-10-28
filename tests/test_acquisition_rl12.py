"""
RL12 regression suite — SPEC ACQUISITION (the live-network slice of RL8).

ONYX could PARSE a spec it was handed but never GO GET one. The acquirer actively
fetches OpenAPI/Swagger (GET, read-only) and the GraphQL introspection schema
(a read), expanding the testable surface beyond captured traffic — safely.

Properties under guard:
  1. OPENAPI   — a well-known OpenAPI path is fetched and parsed into endpoints.
  2. GRAPHQL   — the introspection schema is fetched and parsed into operations.
  3. READ-ONLY — only GET / introspection-POST are ever issued (RL5).
  4. SCOPE     — out-of-scope hosts are never touched.
  5. BUDGET    — fetches are bounded by the RL6 ledger.
  6. FAIL-SAFE — 404 / garbage / corrupt responses are ignored, never a spec,
                 never a crash.
  7. END-TO-END — a vuln on a SPEC-ONLY endpoint (never walked, never captured) is
                 confirmed through the normal pipeline.
"""
from authpath.models import Principal, HTTPRequest, HTTPResponse
from authpath.scope_guard import ScopeGuard, ScopeConfig
from authpath.economy import BudgetLedger
from authpath.acquisition import SpecAcquirer, OPENAPI_PATHS, GRAPHQL_PATHS
from authpath.engine import AuthPathEngine
from authpath.surface import synth_probes
from authpath.transport import make_exchange

A = Principal("A", "Alice")
B = Principal("B", "Bob")


def _sg(hosts):
    return ScopeGuard(ScopeConfig(allowed_hosts=hosts, dry_run=True))


_OPENAPI = {"openapi": "3.0.0",
            "paths": {"/records/{id}": {"get": {}}, "/admin/audit": {"get": {}}}}
_SCHEMA = {"data": {"__schema": {
    "queryType": {"name": "Query", "fields": [{"name": "user", "args": [{"name": "id"}]}]},
    "mutationType": {"name": "Mutation", "fields": [{"name": "transferFunds", "args": []}]}}}}


class _OpenAPITarget:
    def __init__(self):
        self.sends = []
    def send(self, req, p):
        self.sends.append((req.method, req.path))
        if req.path == "/openapi.json":
            return HTTPResponse(200, dict(_OPENAPI))
        return HTTPResponse(404, {"error": "nf"})


class _GraphQLTarget:
    def __init__(self):
        self.sends = []
    def send(self, req, p):
        self.sends.append((req.method, req.path))
        if req.path == "/graphql" and req.method == "POST":
            return HTTPResponse(200, dict(_SCHEMA))
        return HTTPResponse(404, {})


# --- (1) OPENAPI ------------------------------------------------------------ #
def test_openapi_acquired_and_parsed():
    g = SpecAcquirer(_OpenAPITarget(), _sg(["h"])).acquire("h", A)
    keys = {e.key for e in g.endpoints()}
    assert "GET /records/{id}" in keys and "GET /admin/audit" in keys
    assert all(e.source == "acquired-spec" for e in g.endpoints())


# --- (2) GRAPHQL ------------------------------------------------------------ #
def test_graphql_introspection_acquired():
    g = SpecAcquirer(_GraphQLTarget(), _sg(["h"])).acquire("h", A)
    assert g.summary()["total"] >= 2          # user + transferFunds


# --- (3) READ-ONLY ---------------------------------------------------------- #
def test_only_read_only_requests_issued():
    # the RL5 guarantee: acquisition NEVER issues a mutating verb. GET (OpenAPI)
    # and the introspection POST (a read) are the only methods that ever appear.
    for target in (_OpenAPITarget(), _GraphQLTarget()):
        SpecAcquirer(target, _sg(["h"])).acquire("h", A)
        assert all(method in ("GET", "POST") for method, path in target.sends)
        assert not any(method in ("PUT", "PATCH", "DELETE") for method, path in target.sends)


# --- (4) SCOPE -------------------------------------------------------------- #
def test_out_of_scope_host_never_touched():
    t = _OpenAPITarget()
    g = SpecAcquirer(t, _sg(["other.svc"])).acquire("h", A)
    assert len(t.sends) == 0 and g.summary()["total"] == 0


# --- (5) BUDGET ------------------------------------------------------------- #
def test_acquisition_is_budget_bounded():
    t = _OpenAPITarget()
    led = BudgetLedger(global_budget=3, per_host_budget=3)
    SpecAcquirer(t, _sg(["h"]), ledger=led).acquire("h", A)
    assert len(t.sends) <= 3


# --- (6) FAIL-SAFE ---------------------------------------------------------- #
def test_garbage_response_is_not_a_spec():
    class Garbage:
        def send(self, req, p):
            return HTTPResponse(200, {"random": "json", "not": "a spec"})
    g = SpecAcquirer(Garbage(), _sg(["h"])).acquire("h", A)
    assert g.summary()["total"] == 0


def test_all_404_yields_nothing():
    class NF:
        def send(self, req, p):
            return HTTPResponse(404, {})
    g = SpecAcquirer(NF(), _sg(["h"])).acquire("h", A)
    assert g.summary()["total"] == 0


def test_hostile_target_does_not_crash():
    class Boom:
        def send(self, req, p):
            raise RuntimeError("connection reset")
    g = SpecAcquirer(Boom(), _sg(["h"])).acquire("h", A)   # must not raise
    assert g.summary()["total"] == 0


def test_swagger_doc_also_parsed():
    class SwaggerT:
        def send(self, req, p):
            if req.path == "/swagger.json":
                return HTTPResponse(200, {"swagger": "2.0", "basePath": "/v1",
                                          "paths": {"/items/{id}": {"get": {}}}})
            return HTTPResponse(404, {})
    g = SpecAcquirer(SwaggerT(), _sg(["h"])).acquire("h", A)
    assert any("/v1/items/{id}" in e.path for e in g.endpoints())


# --- (7) END-TO-END --------------------------------------------------------- #
class _SpecApp:
    """Serves the OpenAPI doc AND a broken object read on a spec-only endpoint."""
    def send(self, req, p):
        if req.path == "/openapi.json":
            return HTTPResponse(200, dict(_OPENAPI))
        if req.path.startswith("/records/"):
            oid = req.path.rsplit("/", 1)[1]
            return HTTPResponse(200, {"id": oid, "owner_id": "B", "ssn": "SSN-B"})
        return HTTPResponse(404, {})


def test_confirm_idor_on_spec_only_endpoint():
    t = _SpecApp()
    surf = SpecAcquirer(t, _sg(["h"])).acquire("h", A)
    assert "GET /records/{id}" in {e.key for e in surf.endpoints()}
    eng = AuthPathEngine(t, {"A": A, "B": B},
                         ScopeConfig(allowed_hosts=["h"], dry_run=False),
                         contract={}, ledger=BudgetLedger.unbounded())
    eng.observe(make_exchange(t, HTTPRequest("GET", "/records/77", host="h"), B))
    probes = synth_probes(surf, {"/records/{id}": ["77"]}, attacker_pid="A")
    for pr in [p for p in probes if "/records/" in p["path"]]:
        eng.analyze(make_exchange(t, HTTPRequest("GET", pr["path"], host="h"), A), defer=True)
    rep = eng.drain_deferred()
    assert rep["confirmed"] >= 1            # a vuln no human walked, found via the spec
