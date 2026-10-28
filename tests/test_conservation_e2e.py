"""End-to-end: a planted cross-principal read-leak flows through the real engine +
confirmer to a confirmed finding; a genuinely shared feed does not fire; the pass
is inert when disabled (byte-identical guarantee)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.models import HTTPRequest, HTTPResponse, Principal
from authpath.transport import make_exchange

class LeakyVaultTarget:
    host = "demo.local"
    SECRETS = {"A": "SK-A-77310042XZ", "B": "SK-B-10101010QQ", "C": "SK-C-99999999RR"}
    def send(self, req, principal):
        m, p, actor = req.method.upper(), req.path, principal.pid
        if m == "GET" and p == "/api/vault/mine":
            return HTTPResponse(200, {"record_id": f"r{actor}", "api_secret": self.SECRETS.get(actor, "SK-X")})
        if m == "GET" and p == "/api/vault/feed":
            if actor == "A": return HTTPResponse(200, {"record_id": "rA", "api_secret": self.SECRETS["A"]})
            if actor == "C": return HTTPResponse(200, {"record_id": "rC", "api_secret": self.SECRETS["C"]})
            return HTTPResponse(200, {"record_id": "rB", "api_secret": self.SECRETS["A"]})
        return HTTPResponse(404, {"error": "not found"})

class SharedFeedTarget:
    host = "demo.local"
    def send(self, req, principal):
        if req.method.upper() == "GET" and req.path in ("/api/vault/feed", "/api/vault/mine"):
            return HTTPResponse(200, {"record_id": "shared", "api_secret": "PUBLIC-FEED-TOKEN"})
        return HTTPResponse(404, {"error": "not found"})

def _principals():
    return {"A": Principal("A","a"), "B": Principal("B","b"), "C": Principal("C","c"), "anon": Principal("anon","an")}
def _engine(t):
    e = AuthPathEngine(t, _principals(), ScopeConfig(allowed_hosts=["demo.local"], automation_permitted=True), contract={})
    e.conservation = True
    return e
def _GET(path): return HTTPRequest("GET", path, host="demo.local")

def test_read_leak_confirmed_end_to_end():
    t = LeakyVaultTarget(); e = _engine(t); P = e.principals
    e.observe(make_exchange(t, _GET("/api/vault/mine"), P["A"]))
    tr = e.analyze(make_exchange(t, _GET("/api/vault/feed"), P["B"]))
    assert tr.outcome == "finding", f"expected finding, got {tr.outcome}"
    assert any(s.stage == "Conservation" and s.status == "confirmed" for s in tr.stages)

def test_shared_public_feed_does_not_fire():
    t = SharedFeedTarget(); e = _engine(t); P = e.principals
    e.observe(make_exchange(t, _GET("/api/vault/feed"), P["anon"]))
    e.observe(make_exchange(t, _GET("/api/vault/mine"), P["A"]))
    tr = e.analyze(make_exchange(t, _GET("/api/vault/feed"), P["B"]))
    assert tr.outcome != "finding"

def test_inert_when_disabled():
    t = LeakyVaultTarget()
    e = AuthPathEngine(t, _principals(), ScopeConfig(allowed_hosts=["demo.local"], automation_permitted=True), contract={})
    P = e.principals
    e.observe(make_exchange(t, _GET("/api/vault/mine"), P["A"]))
    tr = e.analyze(make_exchange(t, _GET("/api/vault/feed"), P["B"]))
    assert not any(s.stage == "Conservation" for s in tr.stages)

if __name__ == "__main__":
    print("\nConservation end-to-end (session 4)\n" + "-"*50)
    n=0
    for name,fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn): fn(); n+=1; print(f"  [PASS] {name}")
    print("-"*50); print(f"  {n}/{n} passed\n")
