"""GraphQL field-level projection: response_data + authz_denied_paths.

These are the lens that lets the structural engines see a GraphQL object graph
and that turns the server's own FORBIDDEN field-errors into a measured,
zero-false-positive authorization map.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.graphql import authz_denied_paths, response_data


def test_response_data_projects_object_graph():
    body = {"data": {"order": {"id": "101", "internal": {"margin": 1}}}}
    assert response_data(body) == {"order": {"id": "101", "internal": {"margin": 1}}}
    # no usable data tree -> None (caller keeps the raw body)
    assert response_data({"errors": [{"message": "x"}], "data": None}) is None
    assert response_data({"id": 1}) is None          # not a GraphQL envelope


def test_authz_denied_paths_only_authz_class_errors():
    body = {
        "data": {"order": {"id": "101", "internal": None, "audit": None}},
        "errors": [
            {"message": "Not authorized", "path": ["order", "internal"],
             "extensions": {"code": "FORBIDDEN"}},
            {"message": "downstream timeout", "path": ["order", "audit"],
             "extensions": {"code": "INTERNAL_SERVER_ERROR"}},
        ],
    }
    denied = authz_denied_paths(body)
    assert "order.internal" in denied            # authz-class -> flagged
    assert "order.audit" not in denied           # non-authz error -> ignored


def test_authz_denied_paths_message_fallback():
    body = {"errors": [{"message": "permission denied for field secret",
                        "path": ["me", "secret"]}]}
    assert authz_denied_paths(body) == ["me.secret"]


def test_list_element_path_aligns_with_fingerprint_convention():
    """A denied field inside a list element must use the SAME path convention the
    fingerprint emits (orders[0].internal), or cross-principal field-BOLA on
    collections would silently never correlate."""
    from authpath.structural import fingerprint
    denied = authz_denied_paths(
        {"errors": [{"path": ["orders", 0, "internal"],
                     "extensions": {"code": "FORBIDDEN"}}]})
    assert denied == ["orders[0].internal"]
    populated = {p for p in fingerprint({"orders": [{"id": "1", "internal": {"x": 2}}]})
                 .populated_paths() if p != "$"}
    assert denied[0] in populated            # the denied path is a real structural path


def test_active_probe_confirms_field_bola():
    """The opt-in active probe reproduces the field differential in a controlled
    read-only cycle and elevates GRAPHQL_FIELD_BOLA to a confirmed finding (the
    flag-OFF case is covered by the engine's byte-identical isolation proof)."""
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig
    from fixtures import demo_scenario as ds
    SC = ScopeConfig(allowed_hosts=["demo.local"], automation_permitted=True)
    eng = ds.run_demo(lambda t, p, c: AuthPathEngine(t, p, SC, contract=c))[0]
    snap = eng.snapshot()
    fp = [f for f in snap["findings"]
          if f["effect"] == "FIELD_PROJECTION" and "101" in str(f.get("state_proof", ""))]
    assert fp, "active probe must confirm the reproduced field-level BOLA into a finding"
    assert "GRAPHQL_FIELD_BOLA" in {l["kind"] for l in snap["leads"]}


if __name__ == "__main__":
    print("\nGraphQL field-authz tests\n" + "-" * 60)
    passed = 0
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        fn()
        passed += 1
        print(f"  [PASS] {name}")
    print("-" * 60)
    print(f"  {passed}/{len(tests)} tests passed \u2713\n")
