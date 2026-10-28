"""Unit self-tests for the intrinsic (reference-free) interrogation layer."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.intrinsic import (
    Confidence, LeadKind, interrogate, is_masked, name_sensitivity,
)


def test_name_sensitivity_scoring():
    assert name_sensitivity("internal.margin") >= 8
    assert name_sensitivity("password") >= 10
    assert name_sensitivity("buyer.role") >= 7
    assert name_sensitivity("title") == 0
    assert name_sensitivity("items[0].sku") == 0


def test_is_masked():
    assert is_masked("***-**-1111")
    assert is_masked("[REDACTED]")
    assert is_masked("tok_*****")
    assert is_masked("****1234")
    assert not is_masked("Quarterly")
    assert not is_masked("a@demo.local")
    assert not is_masked(None)


def test_ghost_field_on_filtered_privileged_response():
    """The widget-50 filtered shape: internal.*/audit.* present-but-null and
    sensitively named -> GHOST_FIELD leads, reference-free."""
    body = {"id": "50", "status": "active", "total": None,
            "buyer": {"id": "50", "tier": None},
            "internal": {"margin": None, "risk_score": None, "fraud_flags": []},
            "audit": {"by": None, "at": None}}
    leads = interrogate(body, "GET /api/widgets/{id}", "B")
    ghosts = [l for l in leads if l.kind == LeadKind.GHOST_FIELD]
    paths = {p for l in ghosts for p in l.paths}
    assert "internal.margin" in paths
    assert "internal.risk_score" in paths
    # benign null (title) must NOT be flagged
    assert not any("title" in p for p in paths)


def test_masked_field_is_strong_lead():
    body = {"id": "1", "ssn": "***-**-1111", "name": "Bob"}
    leads = interrogate(body, "GET /api/me", "B")
    ghosts = [l for l in leads if l.kind == LeadKind.GHOST_FIELD and "ssn" in l.paths]
    assert ghosts and ghosts[0].confidence == Confidence.STRONG_LEAD


def test_sibling_asymmetry_reference_free_differential():
    """One element of a peer list carries a privileged overlay the others lack."""
    body = {"users": [
        {"id": "1", "name": "A", "email": "a@x"},
        {"id": "2", "name": "B", "email": "b@x", "role": "admin", "internal": {"flag": 1}},
        {"id": "3", "name": "C", "email": "c@x"},
    ]}
    leads = interrogate(body, "GET /api/admin/users", "B")
    sib = [l for l in leads if l.kind == LeadKind.SIBLING_ASYMMETRY]
    assert sib, "must detect the minority privileged overlay"
    flagged = {p for l in sib for p in l.paths}
    assert any("role" in p for p in flagged) or any("internal" in p for p in flagged)
    assert sib[0].confidence == Confidence.STRONG_LEAD


def test_no_false_lead_on_uniform_collection():
    """A homogeneous collection (same schema, only values differ) yields no
    sibling-asymmetry lead."""
    body = {"items": [
        {"id": "1", "sku": "x", "price": 10},
        {"id": "2", "sku": "y", "price": 20},
        {"id": "3", "sku": "z", "price": 30},
    ]}
    leads = interrogate(body, "GET /api/cart", "B")
    assert not [l for l in leads if l.kind == LeadKind.SIBLING_ASYMMETRY]


def test_no_lead_on_type_driven_heterogeneity():
    """A feed of genuinely different element TYPES (tiny/no shared base, non-priv
    names) is not flagged as an authorization asymmetry."""
    body = {"feed": [
        {"kind": "msg", "text": "hi"},
        {"kind": "img", "url": "u"},
        {"kind": "msg", "text": "yo"},
    ]}
    leads = interrogate(body, "GET /api/feed", "B")
    assert not [l for l in leads if l.kind == LeadKind.SIBLING_ASYMMETRY]


def test_leads_ranked_by_weight():
    body = {"id": "1", "secret_token": None, "tier": None}
    leads = interrogate(body, "GET /api/me", "B")
    weights = [l.weight for l in leads]
    assert weights == sorted(weights, reverse=True)


def test_authz_oracle_discloses_gate():
    """A denial body that names the required role/scope is an AUTHZ_ORACLE lead."""
    body = {"error": "forbidden", "required_role": "admin",
            "missing_scopes": ["billing:read"], "your_role": "user"}
    leads = interrogate(body, "GET /api/admin/billing", "B")
    orc = [l for l in leads if l.kind == LeadKind.AUTHZ_ORACLE]
    assert orc and orc[0].confidence == Confidence.STRONG_LEAD
    assert orc[0].evidence["revealed"].get("required_role") == "admin"


def test_no_authz_oracle_on_plain_error():
    """A generic error with no authz disclosure must NOT be an oracle lead."""
    body = {"error": "not found", "code": 404}
    leads = interrogate(body, "GET /api/x/9", "B")
    assert not [l for l in leads if l.kind == LeadKind.AUTHZ_ORACLE]


def test_type_asymmetry_expanded_projection():
    """A sensitive shared field served as an object to a minority but a scalar to
    the rest -> TYPE_ASYMMETRY lead."""
    body = {"members": [
        {"id": "1", "name": "A", "permissions": "read"},
        {"id": "2", "name": "B", "permissions": {"scopes": ["read", "write", "admin"]}},
        {"id": "3", "name": "C", "permissions": "read"},
    ]}
    leads = interrogate(body, "GET /api/team", "B")
    ta = [l for l in leads if l.kind == LeadKind.TYPE_ASYMMETRY]
    assert ta and any("permissions" in p for p in ta[0].paths)


def test_no_type_asymmetry_on_consistent_types():
    body = {"members": [
        {"id": "1", "role": "user"}, {"id": "2", "role": "admin"}, {"id": "3", "role": "user"},
    ]}
    leads = interrogate(body, "GET /api/team", "B")
    assert not [l for l in leads if l.kind == LeadKind.TYPE_ASYMMETRY]


if __name__ == "__main__":
    print("\nISI — intrinsic.py self-tests\n" + "-" * 60)
    passed = 0
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        fn()
        passed += 1
        print(f"  [PASS] {name}")
    print("-" * 60)
    print(f"  {passed}/{len(tests)} self-tests passed \u2713\n")
