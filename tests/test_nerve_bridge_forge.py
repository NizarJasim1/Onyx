"""
FORGE — NerveBridge regression suite (nerve build, step 4: candidates → live Δstate).

Locks the only place the nerve touches a conviction path. A candidate becomes a
finding ONLY when a live read-back as the declared owner proves the non-owner
accessor reproduced the owner's private fields. Every abstain guard (X-1..X-4) is
pinned, end-to-end through the REAL Confirmer (audited _read: scope/budget/WAF/expiry).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.nerve_bridge import NerveBridge
from authpath.confirmer import Confirmer
from authpath.scope_guard import ScopeConfig, ScopeGuard
from authpath.models import HTTPRequest, HTTPResponse, Principal


def _H(method, path):
    return HTTPRequest(method, path, host="demo.local")


class _BolaTarget:
    """Real BOLA shape: authentication IS enforced (anon → 403 on private docs), but
    ownership is NOT checked (any authenticated user reads any private doc)."""
    host = "demo.local"

    def __init__(self, owner_readback_status=200, redact_for_nonowner=False):
        self._owner_status = owner_readback_status
        self._redact = redact_for_nonowner

    def send(self, req, principal):
        p = req.path
        authed = bool(principal.auth) and not principal.is_anonymous
        if p == "/api/me":
            if not authed:
                return HTTPResponse(401, {"error": "login required"})
            return HTTPResponse(200, {"id": {"A": "u-1", "B": "u-2"}.get(principal.pid, "?")})
        if p.startswith("/api/docs/"):
            did = p.rsplit("/", 1)[-1]
            owners = {"1": "u-1", "2": "u-1", "9": "u-2", "pub": "u-2"}
            owner = owners.get(did)
            if owner is None:
                return HTTPResponse(404, {"error": "nf"})
            if did == "pub":
                return HTTPResponse(200, {"id": "pub", "owner_id": "u-2", "public": True})
            if not authed:
                return HTTPResponse(403, {"error": "forbidden"})
            # owner read-back can be made to fail (X-4) for the true owner B
            if principal.pid == "B" and self._owner_status != 200:
                return HTTPResponse(self._owner_status, {"error": "unavailable"})
            full = {"id": did, "owner_id": owner, "ssn": "404-11-9087", "notes": "private"}
            if self._redact and principal.pid != "B":      # non-owner gets a redacted view (X-3)
                return HTTPResponse(200, {"id": did, "owner_id": owner, "ssn": "REDACTED"})
            return HTTPResponse(200, full)
        return HTTPResponse(404, {"error": "no route"})


def _bridge(target, by_identity, anon=True):
    A = Principal("A", "Alice", {"Authorization": "Bearer A"})
    B = Principal("B", "Bob", {"Authorization": "Bearer B"})
    an = Principal("anon", "anon", {}, is_anonymous=True)
    sg = ScopeGuard(ScopeConfig(allowed_hosts=["demo.local"], dry_run=True,
                                automation_permitted=True))
    conf = Confirmer(target, {"A": A, "B": B, "anon": an}, sg)
    pid_map = {"u-1": A, "u-2": B}
    br = NerveBridge(conf, principals_by_identity={k: pid_map[k] for k in by_identity},
                     anon_principal=an if anon else None)
    br.feed_self("fpA", _H("GET", "/api/me"), target.send(_H("GET", "/api/me"), A))
    br.feed_self("fpB", _H("GET", "/api/me"), target.send(_H("GET", "/api/me"), B))
    for d in ("1", "2"):
        r = _H("GET", f"/api/docs/{d}")
        br.feed_owned(r, target.send(r, A), "fpA")
    return br, A


def test_core_bola_confirmed_by_owner_readback():
    t = _BolaTarget()
    br, A = _bridge(t, ["u-1", "u-2"])
    r = _H("GET", "/api/docs/9")
    br.feed_access(r, t.send(r, A), "fpA")
    fs = br.confirmed_findings()
    assert len(fs) == 1
    assert fs[0].declared_owner == "u-2" and fs[0].accessor == "u-1"
    assert "ssn" in fs[0].leaked_fields            # a substantive private field, not just owner_id
    assert "owner_id" not in fs[0].leaked_fields   # ownership metadata excluded


def test_self_owned_no_finding():
    t = _BolaTarget()
    br, A = _bridge(t, ["u-1", "u-2"])
    r = _H("GET", "/api/docs/1")
    br.feed_access(r, t.send(r, A), "fpA")
    assert br.confirmed_findings() == []


def test_x1_owner_not_provisioned_abstains():
    t = _BolaTarget()
    br, A = _bridge(t, ["u-1"])                     # u-2 (owner) NOT provisioned
    r = _H("GET", "/api/docs/9")
    br.feed_access(r, t.send(r, A), "fpA")
    assert br.confirmed_findings() == []
    assert any("not provisioned" in why for _, why in br.abstained)


def test_x2_public_object_abstains():
    t = _BolaTarget()
    br, A = _bridge(t, ["u-1", "u-2"])
    r = _H("GET", "/api/docs/pub")
    br.feed_access(r, t.send(r, A), "fpA")
    assert br.confirmed_findings() == []
    assert any("public" in why for _, why in br.abstained)


def test_x3_no_substantive_leak_abstains():
    """Non-owner gets a REDACTED view (ssn='REDACTED'); the only reproduced field is
    the ownership metadata, which is excluded → no substantive leak → abstain."""
    t = _BolaTarget(redact_for_nonowner=True)
    br, A = _bridge(t, ["u-1", "u-2"])
    r = _H("GET", "/api/docs/9")
    br.feed_access(r, t.send(r, A), "fpA")
    assert br.confirmed_findings() == []
    assert any("no substantive" in why for _, why in br.abstained)


def test_x4_owner_readback_fails_abstains():
    """Owner read-back returns 503 → _read yields a non-2xx view → cannot prove the
    object is the owner's → abstain (never confirm on a failed read-back)."""
    t = _BolaTarget(owner_readback_status=503)
    br, A = _bridge(t, ["u-1", "u-2"])
    r = _H("GET", "/api/docs/9")
    br.feed_access(r, t.send(r, A), "fpA")
    assert br.confirmed_findings() == []
    assert any("read-back failed" in why for _, why in br.abstained)
