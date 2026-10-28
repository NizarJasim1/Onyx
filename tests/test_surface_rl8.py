"""
RL8 surface-enumeration regression suite.

Locks the surface MODEL: ONYX now DERIVES the testable surface from observed
traffic instead of being limited to what a human walked. Properties under guard:

  1. DERIVE   — observed exchanges expand into sibling/collection/parent/method
                endpoints (deterministic, network-free).
  2. HARVEST  — ids in a list/collection body feed the item template (list->item).
  3. SYNTH    — probes are GET/read-only (RL5) and provenance-tagged.
  4. SAFE     — no mutating verb is ever synthesized as a probe.
  5. BOUNDED  — running the derived surface honours the RL6 budget.
  6. SOUND    — a derived-but-absent endpoint yields no finding; the confirmer
                still has the final word (discovery never promotes a finding).
  7. WIN      — ONYX synthesises and confirms a cross-principal attack that NO
                human performed (combining two separate single-principal walks).
"""
from authpath.models import Principal, HTTPRequest, HTTPResponse, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.economy import BudgetLedger
from authpath.transport import make_exchange
from authpath.surface import (
    generalize, observed_ids_by_template, synth_probes, SurfaceGraph,
)

A = Principal("A", "Alice")
B = Principal("B", "Bob")


def _ex(method, path, body=None, principal=A):
    return Exchange(HTTPRequest(method, path, host="h"),
                    HTTPResponse(200, body if body is not None else {"id": "x"}), principal)


# --- (1) DERIVE ------------------------------------------------------------- #
def test_item_derives_collection_and_parents():
    g = generalize([_ex("GET", "/v1/projects/12/datasets/34")])
    keys = {e.key for e in g.endpoints()}
    assert "GET /v1/projects/{id}/datasets/{id}" in keys      # observed
    assert "GET /v1/projects/{id}/datasets" in keys           # this collection
    assert "GET /v1/projects/{id}" in keys                    # parent item
    assert "GET /v1/projects" in keys                         # grandparent collection


def test_collection_derives_item():
    g = generalize([_ex("GET", "/api/orders")])
    keys = {e.key for e in g.endpoints()}
    assert "GET /api/orders/{id}" in keys                     # item derived from list


def test_method_family_recorded():
    g = generalize([_ex("GET", "/api/orders/101")])
    keys = {e.key for e in g.endpoints()}
    assert {"PUT /api/orders/{id}", "PATCH /api/orders/{id}",
            "DELETE /api/orders/{id}"} <= keys


def test_surface_expands_beyond_observed():
    g = generalize([_ex("GET", "/api/orders/101")])
    s = g.summary()
    assert s["total"] > 1 and s["derived"] >= 1               # more than the 1 walked


# --- (2) HARVEST ------------------------------------------------------------ #
def test_ids_harvested_from_list_body():
    cap = [_ex("GET", "/api/orders", body={"orders": [{"id": "701"}, {"id": "702"}]})]
    ids = observed_ids_by_template(cap)
    assert set(ids.get("/api/orders/{id}", [])) >= {"701", "702"}


def test_path_ids_collected():
    ids = observed_ids_by_template([_ex("GET", "/api/orders/101")])
    assert "101" in ids.get("/api/orders/{id}", [])


# --- (3,4) SYNTH + SAFE ----------------------------------------------------- #
def test_probes_are_get_only():
    g = generalize([_ex("GET", "/api/orders/101")])
    ids = observed_ids_by_template([_ex("GET", "/api/orders/101")])
    probes = synth_probes(g, ids, attacker_pid="A")
    assert probes and all(p["method"] == "GET" for p in probes)   # RL5


def test_generic_roots_not_probed():
    g = generalize([_ex("GET", "/v1/projects/12")])
    probes = synth_probes(g, observed_ids_by_template([_ex("GET", "/v1/projects/12")]),
                          attacker_pid="A")
    assert not any(p["path"] in ("/v1", "/api") for p in probes)


# --- (5,6,7) BOUNDED + SOUND + WIN (end to end) ----------------------------- #
class _IdorApp:
    """GET /api/orders/{id} returns the order to ANY caller (IDOR). 500 is A's,
    others are B's. The collection 404s (absent)."""
    def send(self, req, p):
        path = req.path
        if path.startswith("/api/orders/") and path.count("/") == 3:
            oid = path.rsplit("/", 1)[1]
            owner = "A" if oid == "500" else "B"
            return HTTPResponse(200, {"id": oid, "owner_id": owner, "ssn": f"SSN-{oid}"})
        return HTTPResponse(404, {"error": "absent"})


def _run_surface(app, budget=50):
    t = app
    cap = [make_exchange(t, HTTPRequest("GET", "/api/orders/500", host="h"), A),
           make_exchange(t, HTTPRequest("GET", "/api/orders/101", host="h"), B)]
    g = generalize(cap)
    ids = observed_ids_by_template(cap)
    probes = synth_probes(g, ids, attacker_pid="A")
    led = BudgetLedger(global_budget=budget, per_host_budget=budget)
    eng = AuthPathEngine(t, {"A": A, "B": B},
                         ScopeConfig(allowed_hosts=["h"], dry_run=False),
                         contract={}, ledger=led)
    for ex in cap:
        eng.observe(ex)
    for p in probes:
        eng.analyze(make_exchange(t, HTTPRequest(p["method"], p["path"], host="h"), A),
                    defer=True)
    rep = eng.drain_deferred()
    return eng, led, rep


def test_confirms_cross_principal_attack_no_human_walked():
    eng, led, rep = _run_surface(_IdorApp())
    # the synthesized A->101 (B's order) is confirmed; A->500 (A's own) is not.
    assert rep["confirmed"] >= 1
    assert led.spent <= 50                       # BOUNDED


def test_absent_endpoint_yields_no_finding():
    eng, led, rep = _run_surface(_IdorApp())
    # the derived collection 404s -> must not become a finding (soundness)
    assert all("orders/" in getattr(f, "endpoint", "orders/") for f in eng.findings)


def test_surface_graph_dedup_keeps_highest_confidence():
    g = SurfaceGraph()
    from authpath.discovery import Endpoint
    g.add(Endpoint("GET", "/api/orders", source="derived-collection"))
    g.add(Endpoint("GET", "/api/orders", source="observed"))
    eps = [e for e in g.endpoints() if e.key == "GET /api/orders"]
    assert len(eps) == 1 and eps[0].source == "observed"
