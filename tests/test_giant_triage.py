"""
Protocol [21] gap G1 — authz-risk triage on a GIANT-EMULATING surface.

A 10^4-endpoint surface (giant-scale volume + protocol/path diversity + junk). The triage
must (a) rank the genuinely risky authz endpoints above the noise, (b) capture most of the
total risk within a small confirmation budget, and (c) NOT touch precision — triage only
reorders; the Δstate confirmer still decides truth, so a high-ranked but safe endpoint
yields no finding.
"""
import os, sys, random
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.triage import RiskTriage, score_endpoint


def _giant_surface(n=10000, seed=7):
    """Emulate a giant surface: a huge mass of low-risk static/read endpoints + a SMALL,
    fixed set of genuinely high-authz-risk ones. The triage win is that a budget the size of
    the risky set — a tiny fraction of the whole — captures essentially all the risk."""
    rnd = random.Random(seed)
    nouns = ["static", "asset", "css", "img", "help", "docs", "ping", "health", "blog"]
    t = RiskTriage()
    risky = set()
    # a small fixed set of distinct high-risk authz endpoints (40 of them)
    base = [
        ("DELETE", "/api/v2/admin/users/{}"),
        ("PATCH", "/api/v1/org/9/accounts/{}/role"),
        ("GET", "/internal/tenant/7/invoices/{}"),
        ("POST", "/api/v1/manage/payment/tokens/{}"),
    ]
    for i in range(10):
        for m, tmpl in base:
            p = tmpl.format(1000 + i)
            t.add(m, p); risky.add(f"{m} {p}")
    # the rest is low-risk noise
    for i in range(n - len(risky)):
        t.add("GET", f"/{rnd.choice(nouns)}/page{i}")
    return t, risky


def test_g1_high_risk_endpoints_rank_at_the_top():
    t, risky = _giant_surface()
    top = [r.endpoint for r in t.budget(len(risky))]
    assert all(e in risky for e in top), "triage must rank real authz-risk above the noise"


def test_g1_small_budget_captures_most_of_the_risk():
    t, risky = _giant_surface()
    k = len(risky)                       # budget == size of the risky set (40 of 10000 = 0.4%)
    cov = t.coverage(k)
    frac = cov["risk_captured"] / cov["risk_total"]
    assert frac >= 0.9, f"a {k}/{cov['total']} budget should capture >=90% of risk, got {frac:.2f}"
    assert k / cov["total"] < 0.01, "and that budget is <1% of the surface (the triage win)"


def test_g1_scoring_is_deterministic_and_transparent():
    a = score_endpoint("DELETE", "/api/v2/admin/users/123")
    b = score_endpoint("DELETE", "/api/v2/admin/users/123")
    assert a == b                                            # reproducible
    assert "privilege-surface" in a.reasons and "destructive" in a.reasons  # auditable why


def test_g1_triage_does_not_touch_precision():
    """The load-bearing guarantee: triage reorders WHAT to confirm first; it never confirms.
    A high-ranked but SAFE endpoint still yields no finding — the Δstate confirmer decides."""
    from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig
    # a top-ranked admin-delete endpoint that is properly enforced (403) -> must NOT flag
    hi = score_endpoint("DELETE", "/api/v1/admin/users/9")
    assert hi.score >= 7                                     # ranks high
    class SafeStore:
        host = "svc.test"
        def send(self, req, principal): return HTTPResponse(403, {"error": "forbidden"})
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    scope = ScopeConfig(allowed_hosts=["svc.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(SafeStore(), P, scope, contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(eng, f, True)
    eng.xprincipal_delete = True
    req = HTTPRequest("DELETE", "/api/v1/admin/users/9", host="svc.test")
    eng.analyze(Exchange(request=req, response=SafeStore().send(req, P["A"]), principal=P["A"]))
    eng.drain_deferred()
    assert len(eng.findings) == 0, "high rank must not fabricate a finding on a safe endpoint"


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
