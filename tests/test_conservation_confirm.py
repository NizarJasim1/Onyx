"""Session-5 confirmation rebuild: the cross-principal VALUE-PRESENCE differential
confirms read-leaks on FEED/SEARCH endpoints (where the old whole-body owner audit
breaks), and fail-safe drops when the owner cannot read the value back."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.models import HTTPRequest, HTTPResponse, Principal
from authpath.transport import make_exchange

class FeedTarget:
    """/api/feed should show only your own items. BUG: B's feed leaks A's item.
    Owner A's feed contains A's item; control C's feed does not — so value-presence
    differential confirms, even though A's feed and B's feed are different sets."""
    host = "demo.local"
    def send(self, req, principal):
        m, p, a = req.method.upper(), req.path, principal.pid
        if m == "GET" and p == "/api/items/ELEM-A" and a == "A":
            return HTTPResponse(200, {"id": "ELEM-A", "ssn": "A-PRIVATE-SSN"})
        if m == "GET" and p == "/api/feed":
            if a == "A": return HTTPResponse(200, {"items": [{"id": "ELEM-A", "ssn": "A-PRIVATE-SSN"}]})
            if a == "C": return HTTPResponse(200, {"items": [{"id": "ELEM-C", "ssn": "C-SSN"}]})
            # attacker B: over-broad feed leaks A's item
            return HTTPResponse(200, {"items": [{"id": "ELEM-B", "ssn": "B-SSN"},
                                                {"id": "ELEM-A", "ssn": "A-PRIVATE-SSN"}]})
        return HTTPResponse(404, {"error": "nf"})

class RotatedTarget:
    """B's feed shows a value, but the owner can no longer read it back (rotated/
    gone) — the confirmer must fail-safe DROP, never fabricate a finding."""
    host = "demo.local"
    def send(self, req, principal):
        m, p, a = req.method.upper(), req.path, principal.pid
        if m == "GET" and p == "/api/items/GHOST" and a == "A":
            return HTTPResponse(200, {"id": "GHOST", "ssn": "GHOST-SSN"})
        if m == "GET" and p == "/api/feed":
            if a == "B": return HTTPResponse(200, {"items": [{"id": "GHOST", "ssn": "GHOST-SSN"}]})
            return HTTPResponse(200, {"items": []})   # owner & control read back EMPTY
        return HTTPResponse(404, {"error": "nf"})

def _principals():
    return {"A": Principal("A","a"), "B": Principal("B","b"), "C": Principal("C","c")}
def _engine(t):
    e = AuthPathEngine(t, _principals(), ScopeConfig(allowed_hosts=["demo.local"], automation_permitted=True), contract={})
    e.conservation = True
    return e
def _GET(p): return HTTPRequest("GET", p, host="demo.local")

def test_feed_leak_confirmed_by_value_presence():
    t = FeedTarget(); e = _engine(t); P = e.principals
    e.observe(make_exchange(t, _GET("/api/items/ELEM-A"), P["A"]))   # A owns ELEM-A's ssn
    tr = e.analyze(make_exchange(t, _GET("/api/feed"), P["B"]))      # B's feed leaks it
    assert tr.outcome == "finding", f"feed leak must confirm, got {tr.outcome}"
    assert any(s.stage == "Conservation" and s.status == "confirmed" for s in tr.stages)

def test_owner_cannot_read_back_drops_safely():
    t = RotatedTarget(); e = _engine(t); P = e.principals
    e.observe(make_exchange(t, _GET("/api/items/GHOST"), P["A"]))
    tr = e.analyze(make_exchange(t, _GET("/api/feed"), P["B"]))
    # candidate may raise, but it must NOT become a finding (owner read-back lacks V)
    assert tr.outcome != "finding", "owner cannot vouch -> must fail-safe drop"

if __name__ == "__main__":
    print("\nConservation confirmation rebuild (session 5)\n"+"-"*50)
    n=0
    for nm,fn in sorted(globals().items()):
        if nm.startswith("test_") and callable(fn): fn(); n+=1; print(f"  [PASS] {nm}")
    print("-"*50); print(f"  {n}/{n} passed\n")
