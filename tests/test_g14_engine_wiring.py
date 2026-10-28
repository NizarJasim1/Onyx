"""
Wiring regression: the engine builds the BvA ActBridge WITH a ledger-tied nonce
authority iff `stateful_attribution` is on. Flag OFF ⇒ no authority (byte-identical
to the pre-integration behavior). Pins INTEGRATION #4 (engine wiring of G14/G1/G2).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.models import Principal


class _T:
    host = "t.local"
    def send(self, req, p):
        from authpath.models import HTTPResponse
        return HTTPResponse(404, {})


def _engine():
    return AuthPathEngine(_T(), {"a": Principal("a", "a", {"Authorization": "Bearer a"})},
                          ScopeConfig(allowed_hosts=["t.local"], dry_run=True,
                                      automation_permitted=True))


def test_flag_off_bridge_has_no_authority():
    eng = _engine()
    eng.bva = True                      # channel on, attribution OFF (default)
    ch = eng._bva_channel()
    assert ch["bridge"].nonce_authority is None
    assert ch["bridge"].seeker is None


def test_flag_on_bridge_gets_ledger_tied_authority():
    eng = _engine()
    eng.bva = True
    eng.stateful_attribution = True     # opt in
    ch = eng._bva_channel()
    assert ch["bridge"].nonce_authority is not None
    assert ch["bridge"].seeker is not None
    # minting works and is unique through the engine-owned authority
    n1 = ch["bridge"].nonce_authority.mint("x")
    n2 = ch["bridge"].nonce_authority.mint("y")
    assert n1.value != n2.value
    assert ch["bridge"].nonce_authority.recognises(n1.value) is True


def test_authority_is_singleton_across_channel_rebuilds():
    eng = _engine()
    eng.bva = True
    eng.stateful_attribution = True
    a1 = eng._bva_channel()["bridge"].nonce_authority
    a2 = eng._bva_channel()["bridge"].nonce_authority
    assert a1 is a2                     # one authority per engine, not rebuilt each call


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
