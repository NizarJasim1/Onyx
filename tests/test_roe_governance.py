"""
Deficiency #9 (ROE = a governing system, not flags) — solved-criterion, every gap.
Multi-level fail-closed authorization + tamper-evident audit + PII sanitization, governing
every capability path. Empty contract == unchanged behaviour.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.roe import EngagementContract, TamperEvidentAudit, ALLOW, HALT
from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig


def _contract():
    return EngagementContract(
        engagement_id="ENG-1",
        test_principals={"A", "B"},
        allowed_paths=["/api/v1/*"],
        automation_allowed=True,
        test_resources={"9", "10"},
        pii_fields={"internal_note"})


def test_gap2_scope_level_path_outside_engagement_halts():
    c = _contract()
    assert c.authorize("GET", "/admin/secrets", "A").verdict == HALT
    assert c.authorize("GET", "/api/v1/orders/9", "A").verdict == ALLOW


def test_gap1_data_level_non_test_principal_halts():
    c = _contract()
    d = c.authorize("GET", "/api/v1/orders/9", "REALUSER", cross_principal=True)
    assert d.verdict == HALT and d.clause == "data"


def test_gap4_fine_destruction_only_on_declared_test_resource():
    c = _contract()
    assert c.authorize("DELETE", "/api/v1/orders/9", "A", resource="9").verdict == ALLOW
    d = c.authorize("DELETE", "/api/v1/orders/77", "A", resource="77")   # not a test resource
    assert d.verdict == HALT and d.clause == "fine-destruction"


def test_gap3_policy_level_no_automation_halts_everything():
    c = _contract(); c.automation_allowed = False
    assert c.authorize("GET", "/api/v1/orders/9", "A").verdict == HALT


def test_gap5_pii_is_sanitized():
    c = _contract()
    out = c.sanitize({"email": "a@b.com", "content": "ok", "internal_note": "secret",
                      "nested": {"api_key": "xyz"}})
    assert out["email"] == "[REDACTED]" and out["internal_note"] == "[REDACTED]"
    assert out["nested"]["api_key"] == "[REDACTED]" and out["content"] == "ok"


def test_gap6_audit_is_tamper_evident():
    a = TamperEvidentAudit()
    from authpath.roe import Decision
    a.record("GET", "/api/v1/x", "A", Decision(ALLOW, "ok", "scope"))
    a.record("DELETE", "/api/v1/x/9", "A", Decision(ALLOW, "ok", "fine-destruction"))
    assert a.verify() is True
    a._chain[0]["actor"] = "MALLORY"          # tamper
    assert a.verify() is False                # chain breaks


def test_gap7_governs_engine_fail_closed_and_audited():
    class Store:
        host = "svc.test"
        def send(self, req, principal): return HTTPResponse(200, {"ok": True})
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    scope = ScopeConfig(allowed_hosts=["svc.test"], automation_permitted=True,
                        target_provenance="third_party", dry_run=False)
    eng = AuthPathEngine(Store(), P, scope, contract={})
    eng.contract_roe = EngagementContract(engagement_id="E", allowed_paths=["/api/v1/*"],
                                          test_principals={"A"})
    eng.audit = TamperEvidentAudit()
    # an out-of-scope path must be ROE-halted, not analyzed
    req = HTTPRequest("GET", "/admin/dump", host="svc.test")
    tr = eng.analyze(Exchange(request=req, response=HTTPResponse(200, {}), principal=P["A"]))
    assert tr.outcome == "roe_halted"
    assert eng.audit.verify() and len(eng.audit.entries()) == 1
    assert eng.audit.entries()[0]["verdict"] == "halt"


def test_empty_contract_is_byte_identical_noop():
    assert EngagementContract().active() is False
    assert EngagementContract().authorize("DELETE", "/x", "anyone").verdict == ALLOW


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
