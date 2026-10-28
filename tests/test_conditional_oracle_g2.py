"""
Falsification suite for G2 (ETag/If-Match conditional oracle). Each test encodes a
clause of the Anti-Patch Gate / No-Regression Invariant or an RFC-7232 correctness
rule. If any fails, G2 is NOT solved. Deterministic, no network.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import HTTPRequest, HTTPResponse
from authpath.conditional_oracle import (
    parse_etag, build_if_match, interpret, Verdict,
    conditional_drift_confirmed, proxy_suspected_from,
)


def test_parse_strong_and_weak_etag():
    assert parse_etag({"ETag": '"abc"'}).strong is True
    assert parse_etag({"etag": 'W/"abc"'}).weak is True     # case-insensitive + weak
    assert parse_etag({"X": "y"}) is None
    assert parse_etag(None) is None


def test_if_match_uses_exact_etag_never_wildcard():
    req = HTTPRequest("PUT", "/o/1", host="h", body={"x": 1})
    out = build_if_match(req, parse_etag({"ETag": '"v7"'}))
    assert out.headers["If-Match"] == '"v7"'
    assert out.headers["If-Match"] != "*"


def test_weak_etag_refused_for_if_match():
    req = HTTPRequest("PUT", "/o/1", host="h")
    assert build_if_match(req, parse_etag({"ETag": 'W/"v7"'})) is None   # rule 1


def test_412_is_version_changed():
    assert interpret(HTTPResponse(412)) is Verdict.VERSION_CHANGED


def test_412_behind_proxy_is_indeterminate():
    assert interpret(HTTPResponse(412), proxy_suspected=True) is Verdict.INDETERMINATE


def test_2xx_is_applied():
    assert interpret(HTTPResponse(200)) is Verdict.APPLIED_ON_READ_VERSION


def test_proxy_detection_from_headers():
    assert proxy_suspected_from({"X-Amzn-Trace-Id": "1-2-3"}) is True
    assert proxy_suspected_from({"CF-RAY": "abc"}) is True
    assert proxy_suspected_from({"Content-Type": "json"}) is False


def test_no_validator_abstains():
    check = HTTPResponse(200, {"id": 1}, headers={})   # no ETag, no version field
    r = conditional_drift_confirmed(
        check_response=check, commit_request=HTTPRequest("PUT", "/o/1", host="h"),
        send=lambda req: HTTPResponse(412), cross_principal_readback_ok=True)
    assert r.confirmed is False and r.verdict is Verdict.NO_VALIDATOR


def test_full_finding_requires_412_and_cross_principal():
    check = HTTPResponse(200, {"id": 1}, headers={"ETag": '"v1"'})
    send = lambda req: HTTPResponse(412)   # server says version changed
    # cross-principal proven ⇒ finding
    r = conditional_drift_confirmed(
        check_response=check, commit_request=HTTPRequest("PUT", "/o/1", host="h"),
        send=send, cross_principal_readback_ok=True)
    assert r.confirmed is True and r.verdict is Verdict.VERSION_CHANGED
    # cross-principal NOT proven ⇒ abstain (observation ≠ finding, E-4)
    r2 = conditional_drift_confirmed(
        check_response=check, commit_request=HTTPRequest("PUT", "/o/1", host="h"),
        send=send, cross_principal_readback_ok=False)
    assert r2.confirmed is False and "unproven" in r2.reason


def test_proxy_412_does_not_confirm_even_with_cross_principal():
    """E-3: a 412 from behind a proxy must not confirm on status alone."""
    check = HTTPResponse(200, {"id": 1}, headers={"ETag": '"v1"'})
    send = lambda req: HTTPResponse(412, headers={"X-Amzn-Trace-Id": "1-2"})
    r = conditional_drift_confirmed(
        check_response=check, commit_request=HTTPRequest("PUT", "/o/1", host="h"),
        send=send, cross_principal_readback_ok=True)
    assert r.confirmed is False and r.verdict is Verdict.INDETERMINATE


def test_2xx_write_is_not_a_drift_finding():
    check = HTTPResponse(200, {"id": 1}, headers={"ETag": '"v1"'})
    r = conditional_drift_confirmed(
        check_response=check, commit_request=HTTPRequest("PUT", "/o/1", host="h"),
        send=lambda req: HTTPResponse(200), cross_principal_readback_ok=True)
    assert r.confirmed is False and r.verdict is Verdict.APPLIED_ON_READ_VERSION


def test_version_field_fallback_when_no_etag():
    """No ETag but an explicit body version field is a usable validator (E-0 fallback)."""
    check = HTTPResponse(200, {"id": 1, "version": 5}, headers={})
    r = conditional_drift_confirmed(
        check_response=check, commit_request=HTTPRequest("PUT", "/o/1", host="h"),
        send=lambda req: HTTPResponse(412), cross_principal_readback_ok=True,
        version_field="version")
    assert r.confirmed is True and r.verdict is Verdict.VERSION_CHANGED


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
