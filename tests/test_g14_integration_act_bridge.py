"""
Integration test: G14 (nonce provenance) wired into ActBridge's mass-assignment
path. Proves (a) the attributed path confirms a real write-side BOPLA with
cryptographic attribution, and (b) it KILLS the pre-existing-value false positive
that the string-equality M-4 could not distinguish. No network — a fake target
that binds arbitrary body fields stands in for a vulnerable API.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import HTTPResponse, Principal
from authpath.act_bridge import ActBridge
from authpath.nonce_provenance import NonceAuthority, NonceSeeker


class _Scope:
    class _V:
        from authpath.scope_guard import ScopeVerdict as _SV
        verdict = _SV.PROCEED if hasattr(_SV, "PROCEED") else list(_SV)[0]
    def may_mutate(self, req):
        return _Scope._V()


class _FakeConfirmer:
    """Minimal stand-in exposing the two members ActBridge uses: `scope.may_mutate`
    and `_read`. The 'server' binds ANY body field (the mass-assignment bug) and
    persists per-object state."""
    def __init__(self, vulnerable=True, preexisting=None):
        self.scope = _Scope()
        self._store = {"/u/1": dict(preexisting or {})}
        self._vulnerable = vulnerable
    def _read(self, req, principal):
        obj = self._store.setdefault(req.path, {})
        if req.method in ("PATCH", "PUT", "POST"):
            for k, v in (req.body or {}).items():
                if self._vulnerable or k in obj:   # vulnerable: binds arbitrary fields
                    obj[k] = v
            return HTTPResponse(200, dict(obj))
        return HTTPResponse(200, dict(obj))


def _bridge(preexisting=None, vulnerable=True):
    conf = _FakeConfirmer(vulnerable=vulnerable, preexisting=preexisting)
    member = Principal("m", "m", auth={"Authorization": "Bearer m"})
    a = NonceAuthority(); s = NonceSeeker(a)
    return ActBridge(conf, {"m": member}, nonce_authority=a, seeker=s)


def test_attributed_massassign_confirms_with_nonce():
    b = _bridge()
    f = b.confirm_mass_assignment_attributed(
        "m", "/u/1", field="role", privileged_value="admin",
        companion_field="bio")
    assert f is not None and f.kind == "mass_assignment"


def test_preexisting_admin_is_NOT_a_false_positive():
    """The killer test: the object ALREADY has role=admin before we write. The old
    string-equality M-4 would see 'admin stuck' and could FP. The attributed path
    still confirms ONLY because our unique nonce landed in the companion — proving
    OUR write caused it. If the server had ignored our write, no nonce → abstain."""
    # server that IGNORES writes but already shows admin (simulates pre-existing state)
    b = _bridge(preexisting={"role": "admin"}, vulnerable=False)
    f = b.confirm_mass_assignment_attributed(
        "m", "/u/1", field="role", privileged_value="admin",
        companion_field="bio")
    # write ignored ⇒ nonce absent on read-back ⇒ abstain (no FP)
    assert f is None
    assert any("nonce not found" in r[1] or "did not land" in r[1]
               for r in b.abstained)


def test_abstains_without_authority():
    conf = _FakeConfirmer()
    b = ActBridge(conf, {"m": Principal("m", "m")})   # no authority wired
    f = b.confirm_mass_assignment_attributed(
        "m", "/u/1", field="role", privileged_value="admin", companion_field="bio")
    assert f is None and any("no nonce authority" in r[1] for r in b.abstained)


def test_refuses_constrained_companion():
    """The companion must be free-text; a constrained field (status) is refused so
    we never plant a nonce into something that would reject it."""
    b = _bridge()
    f = b.confirm_mass_assignment_attributed(
        "m", "/u/1", field="role", privileged_value="admin",
        companion_field="status")   # 'status' is semantic, not free-text
    assert f is None
    assert any("not a usable free-text companion" in r[1] for r in b.abstained)


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
