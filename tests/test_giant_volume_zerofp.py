"""
Protocol [21] gap G3 — the sacred constraint (zero-FP) under 10^6 VOLUME.

At giant scale the birthday paradox guarantees coincidental value collisions: two different
principals independently holding the same value. Attributing such a value would be a
scale-only FALSE POSITIVE the small proving world never triggers. The collision-proof
resolver attributes a value ONLY when its legitimate origin is a single principal; a shared/
colliding value abstains. This test drives a 10^6-scale value population and proves
precision 1.0 while distinctive real leaks are still attributed.
"""
import os, sys, random, hashlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.provenance import ProvenanceStore
from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange


class _Prov:
    """Minimal harness over ProvenanceStore to record legitimate origins at scale."""
    def __init__(self):
        self.p = ProvenanceStore()
    def observe(self, pid, value):
        req = HTTPRequest("GET", f"/u/{pid}", host="h")
        resp = HTTPResponse(200, {"v": value})
        self.p.observe_response(Exchange(request=req, response=resp,
                                         principal=Principal(pid, pid, auth={})), legitimate=True)


def test_g3_collision_proof_attribution_at_scale():
    h = _Prov()
    N_PRINCIPALS = 1000
    COMMON = ["active", "true", "false", "user", "US", "John Smith", "default.png", "0", "1", "pending"]
    rnd = random.Random(1)
    # ~10^6 legitimate value observations: each principal holds many COMMON values (which
    # therefore collide across principals) plus ONE distinctive per-principal secret.
    secrets = {}
    for i in range(N_PRINCIPALS):
        pid = f"P{i}"
        for _ in range(1000):                       # 1000 * 1000 = 10^6 common observations
            h.observe(pid, rnd.choice(COMMON))
        secret = "SECRET-" + hashlib.sha256(f"{pid}".encode()).hexdigest()   # distinctive
        secrets[pid] = secret
        h.observe(pid, secret)

    # (1) every COMMON value collides across many principals -> unambiguous_owner abstains
    fp = 0
    for v in COMMON:
        if h.p.unambiguous_owner(v) is not None:
            fp += 1
    assert fp == 0, f"a colliding common value must never be attributed (got {fp} scale-FPs)"

    # (2) every distinctive per-principal secret IS still attributed to its true owner
    attributed = sum(1 for pid, s in secrets.items() if h.p.unambiguous_owner(s) == pid)
    assert attributed == N_PRINCIPALS, f"distinctive leaks must still attribute ({attributed}/{N_PRINCIPALS})"


def test_g3_base_resolver_WOULD_misattribute_a_collision():
    """Show the vector is real: the base owner_of_value attributes a colliding value to
    whoever was seen first — the scale-only FP the giant gate removes."""
    h = _Prov()
    h.observe("A", "John Smith")            # A seen first
    h.observe("B", "John Smith")            # B coincidentally holds the same value
    assert h.p.owner_of_value("John Smith") == "A"        # base -> misattributes to A
    assert h.p.unambiguous_owner("John Smith") is None    # giant gate -> abstains (no FP)


def test_g3_engine_giant_volume_suppresses_collision_finding():
    """End-to-end: with giant_volume on, a cross-principal read of a COLLIDING value yields
    no finding (it would be a scale FP), while the flag-off path is unchanged."""
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig

    class Store:
        host = "svc.test"
        def send(self, req, principal):
            # both principals' profiles return the SAME common value (a collision)
            return HTTPResponse(200, {"city": "Springfield"})
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    scope = ScopeConfig(allowed_hosts=["svc.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(Store(), P, scope, contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(eng, f, True)
    eng.confirmer.strict_leak = True
    eng.embedded_owner_exposure = eng.field_exposure = True
    eng.giant_volume = True
    def ex(pid, rid):
        req = HTTPRequest("GET", f"/profile/{rid}", host="svc.test")
        return Exchange(request=req, response=Store().send(req, P[pid]), principal=P[pid])
    eng.observe(ex("A", "a")); eng.observe(ex("B", "b"))    # both legit-hold "Springfield"
    eng.analyze(ex("A", "b"))                                # A reads B's profile
    eng.drain_deferred()
    assert len(eng.findings) == 0, "a colliding common value must not produce a scale FP"


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
