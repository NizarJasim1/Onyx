"""
Integration test: G2 (ETag/If-Match oracle) wired into ActBridge as a live
object-binding-drift confirmer. A fake target models a re-bind window:
 * GET returns an object carrying a strong ETag,
 * a conditional (If-Match) mutation returns 412 (version changed) — the window fired,
 * the attacker's write can (or cannot) land on the owner's object.
No network; deterministic.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import HTTPRequest, HTTPResponse, Principal
from authpath.act_bridge import ActBridge


class _Scope:
    from authpath.scope_guard import ScopeVerdict as _SV
    _PROCEED = _SV.PROCEED if hasattr(_SV, "PROCEED") else list(_SV)[0]
    class _V:
        def __init__(self, verdict): self.verdict = verdict; self.reason = ""
    def may_mutate(self, req):
        return _Scope._V(_Scope._PROCEED)


class _Conf:
    """Fake confirmer. Models: object has a strong ETag; a conditional mutation
    returns 412 (version changed); the write optionally drifts onto the owner view."""
    def __init__(self, *, window_fires=True, drift_lands=True, weak_etag=False, proxy=False):
        self.scope = _Scope()
        self._window = window_fires
        self._drift = drift_lands
        self._weak = weak_etag
        self._proxy = proxy
        self._owner_view = {"id": 1, "owner": "OWNER"}
    def _read(self, req, principal):
        h = {}
        if self._proxy:
            h["X-Amzn-Trace-Id"] = "1-2-3"
        if req.method == "GET":
            etag = 'W/"v1"' if self._weak else '"v1"'
            # owner's view reflects drift if it landed
            body = dict(self._owner_view)
            return HTTPResponse(200, body, headers={**h, "ETag": etag})
        # conditional mutation (has If-Match)
        if "If-Match" in (req.headers or {}):
            if self._window:
                if self._drift:
                    # attacker's write drifts onto the owner's object
                    self._owner_view.update(req.body or {})
                return HTTPResponse(412, None, headers=h)  # version changed
            return HTTPResponse(200, None, headers=h)       # applied, no window
        return HTTPResponse(200, None, headers=h)


class _Conf2(_Conf):
    """Owner GET must reflect drift AFTER the mutation — override to read live state."""
    def _read(self, req, principal):
        if req.method == "GET":
            etag = 'W/"v1"' if self._weak else '"v1"'
            h = {"X-Amzn-Trace-Id": "1-2-3"} if self._proxy else {}
            return HTTPResponse(200, dict(self._owner_view), headers={**h, "ETag": etag})
        return super()._read(req, principal)


def _conf_obj(resource="/o/1", accessor="B", declared="update"):
    class C: pass
    c = C(); c.kind = "hidden_action"; c.resource = resource
    c.accessor = accessor; c.declared = declared; c.owner_hint = "A"
    return c


def _bridge(conf):
    ppl = {"B": Principal("B", "B", auth={"Authorization": "Bearer B"}),
           "A": Principal("A", "A", auth={"Authorization": "Bearer A"})}
    return ActBridge(conf, ppl)


def test_drift_confirmed_when_window_fires_and_write_lands():
    b = _bridge(_Conf2(window_fires=True, drift_lands=True))
    mut = HTTPRequest("PATCH", "/o/1", host="h", body={"note": "DRIFTMARK"})
    f = b.confirm_action_conditional(_conf_obj(), mut, owner_identity="A",
                                     drift_marker="DRIFTMARK", host="h")
    assert f is not None and f.kind == "authz_drift"


def test_no_window_2xx_abstains():
    b = _bridge(_Conf2(window_fires=False, drift_lands=True))
    mut = HTTPRequest("PATCH", "/o/1", host="h", body={"note": "DRIFTMARK"})
    f = b.confirm_action_conditional(_conf_obj(), mut, owner_identity="A",
                                     drift_marker="DRIFTMARK", host="h")
    assert f is None
    assert any("no confirmable re-bind window" in r[1] for r in b.abstained)


def test_window_fires_but_no_cross_principal_landing_abstains():
    b = _bridge(_Conf2(window_fires=True, drift_lands=False))
    mut = HTTPRequest("PATCH", "/o/1", host="h", body={"note": "DRIFTMARK"})
    f = b.confirm_action_conditional(_conf_obj(), mut, owner_identity="A",
                                     drift_marker="DRIFTMARK", host="h")
    assert f is None
    assert any("did not land on the owner" in r[1] for r in b.abstained)


def test_weak_etag_abstains():
    b = _bridge(_Conf2(window_fires=True, drift_lands=True, weak_etag=True))
    mut = HTTPRequest("PATCH", "/o/1", host="h", body={"note": "DRIFTMARK"})
    f = b.confirm_action_conditional(_conf_obj(), mut, owner_identity="A",
                                     drift_marker="DRIFTMARK", host="h")
    assert f is None and any("no strong ETag" in r[1] for r in b.abstained)


def test_proxy_412_abstains_not_confirmed():
    """E-3: a 412 behind a proxy is indeterminate — must not confirm even if the
    write appears to land."""
    b = _bridge(_Conf2(window_fires=True, drift_lands=True, proxy=True))
    mut = HTTPRequest("PATCH", "/o/1", host="h", body={"note": "DRIFTMARK"})
    f = b.confirm_action_conditional(_conf_obj(), mut, owner_identity="A",
                                     drift_marker="DRIFTMARK", host="h")
    assert f is None
    assert any("no confirmable re-bind window" in r[1] for r in b.abstained)


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
