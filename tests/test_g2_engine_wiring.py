"""
Tests the engine's _bva_drift_probe wiring (INTEGRATION #5): the engine drives the
G2 object-binding-drift oracle through its own nonce authority. A fake confirmer
models an ETag'd object with a re-bind window (412) and drift onto the owner.
No network; deterministic.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig, ScopeVerdict
from authpath.models import Principal, HTTPRequest, HTTPResponse


class _T:
    host = "t.local"
    def send(self, req, p):
        return HTTPResponse(404, {})


class _Conf:
    """Fake confirmer wired into the bridge: models ETag + 412 window + drift onto owner."""
    def __init__(self, scope, *, window=True, drift=True):
        self.scope = scope
        self._window = window
        self._drift = drift
        self._owner_view = {"id": 1}
    def _read(self, req, principal):
        if req.method == "GET":
            return HTTPResponse(200, dict(self._owner_view), headers={"ETag": '"v1"'})
        if "If-Match" in (req.headers or {}):
            if self._window:
                if self._drift:
                    self._owner_view.update(req.body or {})
                return HTTPResponse(412, None, headers={})
            return HTTPResponse(200, None, headers={})
        return HTTPResponse(200, None, headers={})


class _ArmedScope:
    """Armed scope: mutations proceed (so the positive drift path can be exercised)."""
    _PROCEED = ScopeVerdict.PROCEED if hasattr(ScopeVerdict, "PROCEED") else list(ScopeVerdict)[0]
    class _V:
        def __init__(s, v): s.verdict = v; s.reason = ""
    def may_mutate(self, req):
        return _ArmedScope._V(_ArmedScope._PROCEED)


def _conf_obj(resource="/o/1", declared="update", accessor="B"):
    class C: pass
    c = C(); c.kind = "hidden_action"; c.resource = resource
    c.accessor = accessor; c.declared = declared; c.owner_hint = "A"
    return c


def _engine_with_bridge(window=True, drift=True):
    eng = AuthPathEngine(_T(), {"B": Principal("B", "B", {"Authorization": "Bearer b"}),
                                "A": Principal("A", "A", {"Authorization": "Bearer a"})},
                         ScopeConfig(allowed_hosts=["t.local"], dry_run=True,
                                     automation_permitted=True))
    eng.bva = True
    eng.stateful_attribution = True
    ch = eng._bva_channel()
    # swap in a fake confirmer that models ETag+drift, keep the engine authority
    ch["bridge"].confirmer = _Conf(_ArmedScope(), window=window, drift=drift)
    ch["by_identity"]["A"] = eng.principals["A"]
    ch["by_identity"]["B"] = eng.principals["B"]
    return eng, ch


def test_engine_drift_probe_confirms_when_window_and_drift():
    eng, ch = _engine_with_bridge(window=True, drift=True)
    mut = HTTPRequest("PATCH", "/o/1", host="t.local")
    f = eng._bva_drift_probe(ch, _conf_obj(), "PATCH", mut, owner="A",
                             read_req=HTTPRequest("GET", "/o/1", host="t.local"))
    assert f is not None and f.kind == "authz_drift"


def test_engine_drift_probe_abstains_no_window():
    eng, ch = _engine_with_bridge(window=False, drift=True)
    mut = HTTPRequest("PATCH", "/o/1", host="t.local")
    f = eng._bva_drift_probe(ch, _conf_obj(), "PATCH", mut, owner="A",
                             read_req=HTTPRequest("GET", "/o/1", host="t.local"))
    assert f is None


def test_engine_drift_probe_noop_without_authority():
    eng = AuthPathEngine(_T(), {"A": Principal("A", "A")},
                         ScopeConfig(allowed_hosts=["t.local"], dry_run=True,
                                     automation_permitted=True))
    eng.bva = True   # channel on, attribution OFF ⇒ no authority ⇒ probe is a no-op
    ch = eng._bva_channel()
    f = eng._bva_drift_probe(ch, _conf_obj(), "PATCH",
                             HTTPRequest("PATCH", "/o/1", host="t.local"), owner="A",
                             read_req=HTTPRequest("GET", "/o/1", host="t.local"))
    assert f is None


def test_engine_drift_probe_noop_without_owner():
    eng, ch = _engine_with_bridge()
    f = eng._bva_drift_probe(ch, _conf_obj(), "PATCH",
                             HTTPRequest("PATCH", "/o/1", host="t.local"), owner=None,
                             read_req=HTTPRequest("GET", "/o/1", host="t.local"))
    assert f is None


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS  {fn.__name__}"); passed += 1
        except Exception:
            print(f"FAIL  {fn.__name__}"); traceback.print_exc()
    print(f"\n{passed}/{len(fns)} passed")
