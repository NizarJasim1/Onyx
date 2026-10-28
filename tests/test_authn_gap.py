"""
AUTHN-gap detection regression — CRUCIBLE problem #4.

An ANONYMOUS principal receiving a 200 body that DECLARES an owner (owner_id = a real
identity) is receiving private, owner-scoped data with no credential → AUTHN gap, confirmed
by reading as the declared owner. A PUBLIC body (no ownership field) must abstain (could be
legitimately public). A missing/failed owner read-back must abstain.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.broadcast import BroadcastLedger
from authpath.act_bridge import ActBridge
from authpath.scope_guard import ScopeGuard, ScopeConfig
from authpath.models import HTTPRequest, HTTPResponse, Principal


def test_broadcast_records_anon_and_owner_ref():
    L = BroadcastLedger()
    L.record("anon", "acct:4", HTTPResponse(200, {"id": "4", "balance": 9, "owner_id": "u-bob"}),
             is_anonymous=True)
    pb = L._by_resource["acct:4"]["anon"]
    assert pb.is_anonymous and pb.accessible and pb.owner_ref == "u-bob"


def test_public_body_has_no_owner_ref():
    L = BroadcastLedger()
    L.record("anon", "pub:1", HTTPResponse(200, {"id": "1", "announcement": "hi"}),
             is_anonymous=True)
    assert L._by_resource["pub:1"]["anon"].owner_ref is None


class _Target:
    host = "t.local"

    def __init__(self, owner_body):
        self.owner_body = owner_body

    def send(self, req, principal):
        return HTTPResponse(200, self.owner_body)


def _bridge(owner_body):
    cfg = ScopeConfig(allowed_hosts=["t.local"], dry_run=True, automation_permitted=True)
    from authpath.confirmer import Confirmer
    conf = Confirmer.__new__(Confirmer)
    conf.scope = ScopeGuard(cfg)
    conf.target = _Target(owner_body)

    class _L:
        def acquire(self, host): return True
        def record(self, host, struck=False): pass
    conf.ledger = _L()
    return ActBridge(conf, {"u-bob": Principal("u-bob", "Bob", {"Authorization": "Bearer b"})})


def test_authn_gap_confirmed_when_owner_view_confirms():
    # owner's view declares owner_id == u-bob → confirms the resource is u-bob's private datum
    br = _bridge({"id": "4", "balance": 9, "owner_id": "u-bob", "iban": "X"})
    rq = HTTPRequest("GET", "/api/accounts/4", host="t.local")
    f = br.confirm_authn_gap("acct:4", "anon", "u-bob",
                             br.by_identity["u-bob"], rq)
    assert f is not None and f.kind == "authn_gap" and f.accessor == "anon"


def test_authn_gap_abstains_when_owner_view_does_not_confirm():
    # owner read-back does NOT carry owner_ref → not provably the owner's datum → abstain
    br = _bridge({"id": "4", "balance": 9})
    rq = HTTPRequest("GET", "/api/accounts/4", host="t.local")
    assert br.confirm_authn_gap("acct:4", "anon", "u-bob",
                                br.by_identity["u-bob"], rq) is None


def test_authn_gap_is_method_independent():
    """The AUTHN-gap signal keys on (anon + 200 + owner-declaring body), NOT on the HTTP
    method — so a method-only gap (e.g. OPTIONS/HEAD leaking a private body to anon) is
    caught whenever that exchange is observed. Generalization, not memorization (GT3)."""
    br = _bridge({"id": "1", "balance": 9, "owner_id": "u-bob", "iban": "X"})
    # the confirmation read-back request method is irrelevant to the verdict
    for method in ("GET", "OPTIONS", "HEAD", "POST"):
        rq = HTTPRequest(method, "/api/accounts/1", host="t.local")
        f = br.confirm_authn_gap("acct:1", "anon", "u-bob",
                                 br.by_identity["u-bob"], rq)
        assert f is not None and f.kind == "authn_gap", f"missed method-only gap via {method}"
