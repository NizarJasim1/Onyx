"""End-to-end test: fully-offline analysis of a captured HAR — no live target.

Proves the field-use path: point ONYX at a capture (list response + one detail
read) and it elevates a reference-free intrinsic lead into a confirmed finding
using ONLY the captured traffic (ReplayTarget), with zero live access.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.harimport import ingest_har, parse_har_exchanges
from authpath.scope_guard import ScopeConfig


def _entry(method, url, status, body, token="tokB"):
    return {
        "request": {"method": method, "url": url,
                    "headers": [{"name": "Authorization", "value": f"Bearer {token}"}]},
        "response": {"status": status,
                     "content": {"mimeType": "application/json",
                                 "text": __import__("json").dumps(body)}},
    }


def _har():
    base = "https://app.test"
    return {"log": {"entries": [
        # a directory list where ONE row leaked a privileged overlay
        _entry("GET", f"{base}/api/directory", 200, {"members": [
            {"id": "u1", "name": "Dana", "title": "Engineer"},
            {"id": "u2", "name": "Evan", "title": "Engineer",
             "salary": 142000, "internal": {"cost_center": "R&D-7"}},
            {"id": "u3", "name": "Faye", "title": "Designer"},
        ]}),
        # the canonical detail view for u2 — correctly FILTERED (no salary/internal)
        _entry("GET", f"{base}/api/directory/u2", 200,
               {"id": "u2", "name": "Evan", "title": "Engineer"}),
    ]}}


def test_har_parses_to_exchanges_with_responses():
    principals, exchanges = parse_har_exchanges(_har(), ["app.test"])
    assert len(exchanges) == 2
    assert all(ex.response.body is not None for ex in exchanges)
    assert list(principals) == ["A"]              # single credential -> one principal


def test_offline_har_elevates_to_field_projection_finding():
    scope = ScopeConfig(allowed_hosts=["app.test"], automation_permitted=True)
    engine = ingest_har(_har(), scope, in_scope_hosts=["app.test"])
    snap = engine.snapshot()
    fp = [f for f in snap["findings"] if f["effect"] == "FIELD_PROJECTION"]
    assert fp, "offline capture must yield a confirmed FIELD_PROJECTION finding"
    # the leaked privileged field is named in the proof
    assert any("internal" in str(f["state_proof"]) or "salary" in str(f["state_proof"])
               for f in fp)
    # and the reference-free lead is present too
    kinds = {l["kind"] for l in snap["leads"]}
    assert "SIBLING_ASYMMETRY" in kinds


if __name__ == "__main__":
    print("\nHAR offline-ingest tests\n" + "-" * 60)
    passed = 0
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        fn()
        passed += 1
        print(f"  [PASS] {name}")
    print("-" * 60)
    print(f"  {passed}/{len(tests)} tests passed \u2713\n")
