"""
Diagnostics export regression — the downloadable file that captures everything for
weakness analysis, with redaction that is safe to share and loses no diagnostic signal.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.diag_export import (redact_headers, redact_tree, build_export,
                                   to_json_bytes)
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.models import HTTPRequest, HTTPResponse, Exchange, Principal


def test_secret_headers_redacted_keeping_scheme_and_length():
    out = redact_headers({"Authorization": "Bearer abc.def.ghi", "Accept": "application/json"})
    assert out["Authorization"].startswith("$REDACTED:Bearer:len=")
    assert out["Accept"] == "application/json"            # non-secret kept verbatim


def test_pii_hashed_preserves_value_equality_no_raw_leak():
    a = redact_tree({"ssn": "404-11-9087", "city": "Mosul"})
    b = redact_tree({"ssn": "404-11-9087", "city": "Mosul"})
    assert a["ssn"].startswith("#") and a["ssn"] == b["ssn"]   # equality preserved
    assert "404-11-9087" not in str(a)                          # raw PII gone
    assert a["city"] == "Mosul"                                 # non-PII kept


def test_secret_body_field_redacted():
    out = redact_tree({"password": "hunter2", "note": "hello"})
    assert out["password"].startswith("$REDACTED:len=")
    assert out["note"] == "hello"


def _engine_with_run():
    A = Principal("A", "Alice", {"Authorization": "Bearer secret-A"})
    scope = ScopeConfig(allowed_hosts=["t.local"], dry_run=True, automation_permitted=True)
    eng = AuthPathEngine(MockT(), {"A": A}, scope)
    eng.nerve = True
    eng.capture = []
    r = HTTPRequest("GET", "/api/me", host="t.local", headers={"Authorization": "Bearer secret-A"})
    eng.observe(Exchange(r, HTTPResponse(200, {"id": "u-1"}), A))
    return eng, scope


class MockT:
    host = "t.local"
    def send(self, req, principal):
        return HTTPResponse(200, {"id": "u-1"})


def test_build_export_is_complete_and_safe():
    eng, scope = _engine_with_run()
    exp = build_export(eng, eng.capture, scope=scope, meta={"tool": "ONYX/AuthPath"})
    assert exp["schema"] == "onyx.diag-export/1"
    assert "nerve" in exp["metrics"] and "counts" in exp["metrics"]
    assert exp["run"]["exchange_count"] == 1
    assert exp["raw_exchanges"][0]["request"]["headers"]["Authorization"].startswith("$REDACTED")
    # the whole serialized file must contain no raw credential
    blob = to_json_bytes(exp).decode()
    assert "secret-A" not in blob


def test_export_empty_when_no_capture_still_valid():
    A = Principal("A", "Alice", {})
    scope = ScopeConfig(allowed_hosts=["t.local"], dry_run=True, automation_permitted=True)
    eng = AuthPathEngine(MockT(), {"A": A}, scope)          # nerve off, no capture
    exp = build_export(eng, [], scope=scope)
    assert exp["run"]["exchange_count"] == 0
    assert exp["metrics"]["nerve"]["enabled"] is False
