"""
Protocol [21] gap G2 — object addressing across giant-scale protocol diversity.

Giants use opaque/signed ids, batched/aliased operations, and gRPC(-transcoded) — carriers
ONYX's REST/numeric detection misses, making those objects (and their BOLAs) invisible.
This makes them addressable. It only expands addressability; the Δstate confirmer still
decides truth, so precision is untouched.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.protocol import (is_opaque_id, batch_operations,
                               grpc_transcoded_ids)
from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange


def test_g2_1_opaque_signed_ids_are_recognised():
    assert is_opaque_id("AItOawn9-Xk3lK2p_Qz8vB1")           # signed cursor / opaque handle
    assert is_opaque_id("dXNlcjoxMjM0NTY3ODkw")              # base64
    assert not is_opaque_id("documentification")             # plain word -> not an id
    assert not is_opaque_id("42")                            # short numeric -> handled elsewhere
    assert not is_opaque_id("orders")                        # a path noun -> not an id


def test_g2_1_opaque_id_in_body_becomes_addressable():
    # base REST logic already handles opaque PATH segments; the G2 gain is opaque ids in
    # non-path carriers (body cursors, batch, gRPC) that base mining misses.
    req = HTTPRequest("POST", "/api/v1/graph", body={"pageCursor": "AItOawn9-Xk3lK2p_Qz8vB1"},
                      host="h")
    req.giant_protocol = True
    assert "AItOawn9-Xk3lK2p_Qz8vB1" in req.object_ids(), "opaque body id must be addressable under G2"


def test_g2_2_batch_operations_decomposed():
    body = [{"method": "GET", "url": "/users/AItOawn9-Xk3lK2p_Qz8", "id": 1},
            {"method": "DELETE", "url": "/orders/Zx8Kp2Lm9-Qw4Rt7Yu", "id": 2}]
    ops = batch_operations(body)
    assert len(ops) == 2
    allids = sum((o["ids"] for o in ops), [])
    assert "AItOawn9-Xk3lK2p_Qz8" in allids and "Zx8Kp2Lm9-Qw4Rt7Yu" in allids


def test_g2_2_graphql_alias_batching_decomposed():
    body = {"query": 'query { a: user(id: "Xk3lK2p9Qz8vB1aa") { name } '
                     'b: order(id: "Zx8Kp2Lm9Qw4Rt77") { total } }'}
    ops = batch_operations(body)
    ids = sum((o["ids"] for o in ops), [])
    assert "Xk3lK2p9Qz8vB1aa" in ids and "Zx8Kp2Lm9Qw4Rt77" in ids   # both aliased objects seen


def test_g2_3_grpc_transcoded_ids():
    body = {"@type": "type.googleapis.com/GetUser", "userId": "AItOawn9-Xk3lK2p_Qz8", "name": "x"}
    ids = grpc_transcoded_ids(body, headers={"Content-Type": "application/grpc+json"})
    assert "AItOawn9-Xk3lK2p_Qz8" in ids


def test_g2_4_fp_safety_new_carriers_do_not_fabricate_findings():
    """A batched request against a properly-enforced (403) endpoint: the objects are now
    ADDRESSABLE, but nothing is confirmed -> no finding. Expanding addressability cannot FP."""
    class SafeStore:
        host = "svc.test"
        def send(self, req, principal): return HTTPResponse(403, {"error": "forbidden"})
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    scope = ScopeConfig(allowed_hosts=["svc.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(SafeStore(), P, scope, contract={})
    for f in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(eng, f, True)
    eng.xprincipal_delete = True
    req = HTTPRequest("POST", "/api/v1/$batch",
                      body=[{"method": "DELETE", "url": "/orders/Zx8Kp2Lm9-Qw4Rt7Yu"}], host="svc.test")
    req.giant_protocol = True
    eng.analyze(Exchange(request=req, response=SafeStore().send(req, P["A"]), principal=P["A"]))
    eng.drain_deferred()
    assert len(eng.findings) == 0, "new carriers must not fabricate a finding on a safe target"


def test_g2_default_off_is_byte_identical():
    # off -> the body cursor is NOT mined (unchanged REST behaviour)
    off = HTTPRequest("POST", "/api/v1/lookup", body={"cursor": "AItOawn9-Xk3lK2p_Qz8vB1"}, host="h")
    assert "AItOawn9-Xk3lK2p_Qz8vB1" not in off.object_ids()
    # on (set before first read) -> addressable
    on = HTTPRequest("POST", "/api/v1/lookup", body={"cursor": "AItOawn9-Xk3lK2p_Qz8vB1"}, host="h")
    on.giant_protocol = True
    assert "AItOawn9-Xk3lK2p_Qz8vB1" in on.object_ids()


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
