"""
RL9 regression suite — HOST-SCOPED AUTHORITY (cross-service authority model).

ONYX's authority (held objects, seen ids) was host-blind: an object legitimately
held on service X was treated as held everywhere, silently MISSING cross-service
IDOR. Authority is now scoped to the (principal, host) it was measured on, and the
companion JWT audience-confusion signal surfaces a token honoured outside its
audience. Properties under guard:

  1. CATCH    — cross-service IDOR (hold on X, read another's object on Y) fires.
  2. NO FP    — same-service self-access stays clean; the confirmer filters
                shared-namespace legitimate cross-service self-access.
  3. SCOPED   — held/seen accessors are correct per host.
  4. AUDIENCE — JWT audience confusion flags a host-like aud mismatch (provisional
                lead, never a finding) and stays silent on match / opaque aud.
"""
import base64
import json

from authpath.models import Principal, HTTPRequest, HTTPResponse, Exchange, EffectClass
from authpath.engine import AuthPathEngine, _host_like, _host_covered
from authpath.scope_guard import ScopeConfig
from authpath.economy import BudgetLedger
from authpath.transport import make_exchange
from authpath.provenance import ProvenanceStore

A = Principal("A", "Alice")
B = Principal("B", "Bob")


class _Multi:
    """Object 500 is A's on api.svc but B's on internal.svc (separate namespaces)."""
    def send(self, req, p):
        if req.host == "internal.svc":
            return HTTPResponse(200, {"id": "500", "owner_id": "B", "ssn": "SSN-B"})
        return HTTPResponse(200, {"id": "500", "owner_id": "A", "data": "x"})


def _engine(target, hosts):
    return AuthPathEngine(target, {"A": A, "B": B},
                          ScopeConfig(allowed_hosts=hosts, dry_run=False),
                          contract={}, ledger=BudgetLedger.unbounded())


# --- (1) CATCH cross-service IDOR ------------------------------------------ #
def test_cross_host_idor_caught():
    t = _Multi()
    eng = _engine(t, ["api.svc", "internal.svc"])
    eng.observe(make_exchange(t, HTTPRequest("GET", "/data/500", host="api.svc"), A))
    eng.observe(make_exchange(t, HTTPRequest("GET", "/data/500", host="internal.svc"), B))
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/data/500", host="internal.svc"), A))
    assert tr.outcome == "finding"          # was a silent MISS pre-RL9


# --- (2) NO false positive on same-service self-access --------------------- #
def test_same_host_self_read_clean():
    t = _Multi()
    eng = _engine(t, ["api.svc"])
    eng.observe(make_exchange(t, HTTPRequest("GET", "/data/500", host="api.svc"), A))
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/data/500", host="api.svc"), A))
    assert tr.outcome != "finding"


# --- (3) SCOPED held/seen accessors ---------------------------------------- #
def test_held_is_host_scoped():
    pv = ProvenanceStore()
    ex = Exchange(HTTPRequest("GET", "/data/500", host="api.svc"),
                  HTTPResponse(200, {"id": "500"}), A)
    pv.observe_response(ex, legitimate=True)
    assert pv.held_object_by_principal("500", "A", host="api.svc") is True
    assert pv.held_object_by_principal("500", "A", host="internal.svc") is False
    assert pv.held_object_by_principal("500", "A") is True          # global still works


def test_seen_is_host_scoped():
    pv = ProvenanceStore()
    ex = Exchange(HTTPRequest("GET", "/orders", host="api.svc"),
                  HTTPResponse(200, {"items": [{"id": "9"}]}), A)
    pv.observe_response(ex, legitimate=True)
    assert pv.seen_by_principal("9", "A", host="api.svc") is True
    assert pv.seen_by_principal("9", "A", host="other.svc") is False


def test_envelope_hold_is_host_scoped():
    from authpath.envelope import EnvelopeEngine
    ee = EnvelopeEngine()
    ee.observe(Exchange(HTTPRequest("GET", "/data/500", host="api.svc"),
                        HTTPResponse(200, {"id": "500"}), A), EffectClass.OBJECT_ACCESS)
    env = ee.envelope_for("A")
    assert env.holds_object_on_host("500", "api.svc") is True
    assert env.holds_object_on_host("500", "internal.svc") is False


# --- (4) AUDIENCE confusion (provisional lead) ----------------------------- #
def _jwt(aud):
    h = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps({"sub": "A", "aud": aud}).encode()).decode().rstrip("=")
    return f"Bearer {h}.{p}.sig"


class _Ok:
    def send(self, req, p):
        return HTTPResponse(200, {"ok": True})


def _aud_leads(aud, host):
    eng = AuthPathEngine(_Ok(), {"A": A},
                         ScopeConfig(allowed_hosts=[host], dry_run=False),
                         contract={}, ledger=BudgetLedger.unbounded())
    ex = Exchange(HTTPRequest("GET", "/x", headers={"Authorization": _jwt(aud)}, host=host),
                  HTTPResponse(200, {"ok": True}), A)
    eng.analyze(ex)
    return [l for _t, l in eng.leads if getattr(l, "kind", "") == "TOKEN_AUDIENCE_CONFUSION"]


def test_audience_mismatch_flags():
    assert _aud_leads("auth.example.com", "api.example.com")
    assert _aud_leads("https://auth.example.com/", "api.example.com")


def test_audience_match_silent():
    assert not _aud_leads("api.example.com", "api.example.com")


def test_opaque_audience_silent():
    assert not _aud_leads("client_12345", "api.svc")        # not host-like → skip


def test_audience_lead_is_not_a_finding():
    eng = AuthPathEngine(_Ok(), {"A": A},
                         ScopeConfig(allowed_hosts=["api.example.com"], dry_run=False),
                         contract={}, ledger=BudgetLedger.unbounded())
    ex = Exchange(HTTPRequest("GET", "/x",
                              headers={"Authorization": _jwt("auth.example.com")},
                              host="api.example.com"),
                  HTTPResponse(200, {"ok": True}), A)
    eng.analyze(ex)
    assert len(eng.findings) == 0          # provisional lead only, never a finding


def test_host_helpers():
    assert _host_like("auth.example.com") and _host_like("https://x.io/")
    assert not _host_like("client_12345")
    assert _host_covered("api.example.com", "example.com")     # suffix covered
    assert not _host_covered("api.example.com", "auth.other.com")
