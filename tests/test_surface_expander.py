"""
Deficiency #2 (surface discovery) — solved-criterion, every gap.

ONYX discovers hidden endpoints by HARVESTING references the target emitted (bodies, JS,
version lineage) — deterministic, quiet, and grounded — never by blind fuzzing. Critically,
discovery only FEEDS detection: a discovered endpoint that is not vulnerable yields no
finding, so discovery cannot add a false positive.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.expander import (SurfaceExpander, harvest_references, derive_lineage,
                               extract_from_js, mine_params)


def test_gap1_reference_harvesting_from_body():
    body = {"user": "A",
            "invoice_id": 42,                                   # nested ref -> /invoices/42
            "_links": {"receipt": {"href": "/api/v2/receipts/42"}},   # HATEOAS
            "note": "see https://svc.test/api/v2/audit/42 for details"}  # url in text
    paths = {c.path for c in harvest_references(body)}
    assert "/invoices/42" in paths                              # nested id ref
    assert "/api/v2/receipts/42" in paths                       # HATEOAS link
    assert "/api/v2/audit/42" in paths                          # url in free text


def test_gap2_version_lineage_derivation():
    paths = {c.path: c for c in derive_lineage("/api/v2/orders/9")}
    assert "/api/v1/orders/9" in paths and "/api/v0/orders/9" in paths
    assert paths["/api/v1/orders/9"].tier == "lineage"
    assert any("internal" in p for p in paths)                  # internal sibling


def test_gap3_js_bundle_extraction():
    js = 'const API="/api/v2/users";fetch("/api/internal/flags/all");x("/v3/secrets/1")'
    paths = {c.path for c in extract_from_js(js)}
    assert "/api/internal/flags/all" in paths and "/v3/secrets/1" in paths


def test_gap4_param_mining():
    fields = mine_params({"id": 1, "role": "user", "profile": {"is_admin": False}})
    assert {"role", "is_admin"} <= fields                       # undocumented mass-assign candidates


def test_gap5_unified_ingest_tiered_and_only_new():
    exp = SurfaceExpander()
    exp.feed_body({"_links": {"x": {"href": "/api/v2/hidden/1"}}})
    exp.feed_js('fetch("/api/internal/debug")')
    exp.feed_lineage(["/api/v2/orders/9"])
    observed = {"GET /api/v2/orders/9"}
    new = exp.new_endpoints(observed)
    keys = {c.key() for c in new}
    assert "GET /api/v2/hidden/1" in keys                       # referenced
    assert "GET /api/internal/debug" in keys                    # js
    assert "GET /api/v1/orders/9" in keys                       # lineage
    assert "GET /api/v2/orders/9" not in keys                   # already observed -> excluded
    tiers = {c.tier for c in new}
    assert {"referenced", "js", "lineage"} <= tiers             # provenance preserved


def test_gap5_discovery_cannot_add_a_false_positive():
    """The load-bearing guarantee: discovery yields ENDPOINTS to test, not findings. A
    discovered endpoint that is not vulnerable produces zero findings — the confirmer still
    requires a proven Δstate. So expanding the surface can never add an FP."""
    from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig

    class SafeStore:                                            # a discovered-but-SAFE endpoint
        host = "svc.test"
        def send(self, req, principal):
            return HTTPResponse(403, {"error": "forbidden"})   # properly enforces authz

    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    scope = ScopeConfig(allowed_hosts=["svc.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(SafeStore(), P, scope, contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(eng, f, True)
    eng.confirmer.strict_leak = True
    # a hidden endpoint we DISCOVERED and now probe cross-principal:
    req = HTTPRequest("GET", "/api/internal/debug/9", host="svc.test")
    eng.analyze(Exchange(request=req, response=SafeStore().send(req, P["A"]), principal=P["A"]))
    eng.drain_deferred()
    assert len(eng.findings) == 0, "a safe discovered endpoint must never yield a finding"


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
