"""
RL18 — GLOBAL INVARIANT / EMERGENT BREAK regression suite (AEGIS).

The 4th dimension: a SEQUENCE of individually-permitted operations that breaks a
global invariant no single step owns. Invariant under test: "a child's authority
follows its parent's." A child accessible to a principal whose DECLARED parent is
forbidden to it — with no independent grant — is a Δstate-confirmed emergent break,
proven READ-ONLY (no writes ever issued). Guarantees:

  * positive            — child accessible ∧ declared parent forbidden → finding
  * no-parent-loss      — parent still held → no break (the sequence didn't happen)
  * independent grant    — child explicitly shared with the principal → abstain (FP guard)
  * read-only proof      — confirmation issues only GETs (AEGIS gate 3)
  * additive isolation  — flag OFF ⇒ byte-identical (no finding, ledger inert)
  * declared invariant   — no parent link declared ⇒ no break (RL1: never inferred)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.transport import make_exchange
from authpath.models import HTTPRequest, HTTPResponse, Principal
from authpath.global_invariants import InvariantLedger

D = Principal("D", "Dave")

_PARENTS = {"doc:d1": "folder:f1", "doc:d2": "folder:f2", "doc:d3": "folder:f1"}


class _HierTarget:
    """folders/docs hierarchy; f1 is transferred to B so D loses it, but the docs
    inside never follow. d3 is independently shared with D."""
    host = "demo.local"

    def __init__(self):
        self._transferred = set()

    def send(self, req, principal):
        m, p = req.method.upper(), req.path
        a = principal.pid
        if m == "POST" and p.endswith("/transfer"):
            self._transferred.add(p.split("/")[3].lower())
            return HTTPResponse(200, {"id": p.split("/")[3].lower(), "owner": "B"})
        if m == "GET" and p.startswith("/api/folders/"):
            fid = p.rsplit("/", 1)[-1].lower()
            if fid in self._transferred and a != "B":
                return HTTPResponse(403, {"error": "forbidden"})
            return HTTPResponse(200, {"id": fid, "owner": a})
        if m == "GET" and p.startswith("/api/docs/"):
            did = p.rsplit("/", 1)[-1].lower()
            if did == "d3":
                return HTTPResponse(200, {"id": "d3", "parent": "f1", "shared_with": ["D"]})
            if did in ("d1", "d2"):
                return HTTPResponse(200, {"id": did, "parent": did.replace("d", "f")})
            return HTTPResponse(404, {"error": "not found"})
        return HTTPResponse(404, {"error": "no route"})


def _engine(target, gi=True):
    scope = ScopeConfig(allowed_hosts=["demo.local"], dry_run=True, automation_permitted=True)
    eng = AuthPathEngine(target, {"D": D}, scope,
                         contract={"resource_parents": dict(_PARENTS),
                                   "GET /api/folders/{id}": {"effect": "OBJECT_ACCESS"},
                                   "GET /api/docs/{id}": {"effect": "OBJECT_ACCESS"}})
    eng.global_invariants = gi
    return eng


def _baseline(eng, t):
    # D legitimately reads everything (into its envelope), then loses f1.
    for path in ("/api/folders/F1", "/api/folders/F2", "/api/docs/D1",
                 "/api/docs/D2", "/api/docs/D3"):
        eng.observe(make_exchange(t, HTTPRequest("GET", path), D))
    eng.analyze(make_exchange(t, HTTPRequest("POST", "/api/folders/F1/transfer"), D))
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/folders/F1"), D))  # 403 now


# ----------------------------- the guarantees ------------------------------ #

def test_emergent_break_confirms():
    t = _HierTarget()
    eng = _engine(t)
    _baseline(eng, t)
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/docs/D1"), D))
    assert tr.outcome == "finding", f"expected finding, got {tr.outcome}"
    f = eng.findings[-1]
    assert f.effect.value == "EMERGENT_BREAK"


def test_no_parent_loss_no_break():
    t = _HierTarget()
    eng = _engine(t)
    _baseline(eng, t)
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/docs/D2"), D))
    assert tr.outcome != "finding", "F2 was never transferred — no break"


def test_independent_grant_abstains():
    t = _HierTarget()
    eng = _engine(t)
    _baseline(eng, t)
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/docs/D3"), D))
    assert tr.outcome != "finding", "D3 is independently shared with D — legitimate"


def test_flag_off_byte_identical():
    t = _HierTarget()
    eng = _engine(t, gi=False)
    _baseline(eng, t)
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/docs/D1"), D))
    assert not any(f.effect.value == "EMERGENT_BREAK" for f in eng.findings)


def test_proof_is_read_only():
    """AEGIS gate 3: confirmation must issue only GETs — never a write."""
    t = _HierTarget()
    methods = []
    orig = t.send

    def spy(req, principal):
        methods.append(req.method.upper())
        return orig(req, principal)
    t.send = spy
    eng = _engine(t)
    _baseline(eng, t)
    methods.clear()
    eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/docs/D1"), D))
    # during analysis + confirmation, the GIE must never POST/PUT/PATCH/DELETE
    assert all(mth in ("GET", "HEAD") for mth in methods), \
        f"RL18 confirmation issued a non-read method: {methods}"


# --------------------------- ledger unit guarantees ------------------------ #

def test_ledger_requires_declared_parent():
    """RL1: with no declared parent link, there is no invariant → no break."""
    led = InvariantLedger(parent_map={})           # nothing declared
    led.observe(HTTPRequest("GET", "/api/folders/F1"), HTTPResponse(403, {}), "D")
    brk = led.break_for(HTTPRequest("GET", "/api/docs/D1"), HTTPResponse(200, {"id": "d1"}), "D")
    assert brk is None


def test_ledger_requires_parent_forbidden_observation():
    led = InvariantLedger(parent_map=dict(_PARENTS))
    # parent observed ACCESSIBLE → no break
    led.observe(HTTPRequest("GET", "/api/folders/F1"), HTTPResponse(200, {"id": "f1"}), "D")
    brk = led.break_for(HTTPRequest("GET", "/api/docs/D1"), HTTPResponse(200, {"id": "d1"}), "D")
    assert brk is None
    # now parent observed FORBIDDEN → break surfaces
    led.observe(HTTPRequest("GET", "/api/folders/F1"), HTTPResponse(403, {}), "D")
    brk = led.break_for(HTTPRequest("GET", "/api/docs/D1"), HTTPResponse(200, {"id": "d1"}), "D")
    assert brk is not None and brk.parent == "folder:f1" and brk.child == "doc:d1"
