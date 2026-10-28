"""
SENTINEL — real-world hardening regression suite.

These lock the fixes that make ONYX's described power hold on a MESSY REAL target,
not just on the clean mock:

  S1 — an additive pass that raises on a malformed real response is CONTAINED
       (the scan never dies) and VISIBLE (a coverage-gap diagnostic + counter),
       never a silent false 'clean'.
  S1/S3 — genuinely messy bodies (bytes, None, scalars, NaN, deep nesting) never
       crash the analysis.
  S2 — short sensitivity tokens no longer false-positive on innocent field names
       (`pan` ⊄ `company`, `pin` ⊄ `shipping`).
  S4 — international PII field names are covered, and the vocabulary is
       operator-extensible for a specific engagement.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.transport import make_exchange
from authpath.models import HTTPRequest, HTTPResponse, Principal
from authpath.confirmer import _is_sensitive_key, register_sensitive_fields, _CUSTOM_SENSITIVE

B = Principal("B", "Bob")


class _Target:
    host = "demo.local"

    def __init__(self, body):
        self.body = body

    def send(self, req, principal):
        return HTTPResponse(200, self.body)


def _engine(target):
    scope = ScopeConfig(allowed_hosts=["demo.local"], dry_run=True, automation_permitted=True)
    eng = AuthPathEngine(target, {"B": B}, scope)
    eng.cross_surface = eng.temporal_shape = eng.combinatorial = eng.global_invariants = True
    return eng


# ----------------------------- S1: crash isolation ------------------------- #

def test_additive_pass_exception_is_contained_and_visible():
    t = _Target({"id": "5", "ssn": "x"})
    eng = _engine(t)

    def boom(ex, tr):
        raise ValueError("simulated real-world parser failure")
    eng._cross_surface_pass = boom

    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/accounts"), B))  # must NOT raise
    assert eng._pass_errors == 1, "the pass error must be counted (coverage honesty)"
    assert any(s.status == "errored" for s in tr.stages), "the error must be VISIBLE on the trace"
    # the rest of the analysis still produced a valid (non-crashed) outcome
    assert tr.outcome in ("clean", "finding", "candidate-unconfirmed")


def test_messy_real_bodies_never_crash():
    messy = [b"\x80\x81raw", "plain string", None, 12345, float("nan"),
             {"a": {"b": {"c": [{"d": None}] * 4}}}, [1, 2, {"x": "y"}],
             {"data": None, "errors": [{"x": 1}]}, {"k": {"nested": [None, {}]}}]
    for body in messy:
        t = _Target(body)
        eng = _engine(t)
        for path in ("/api/orders", "/api/orders/5", "/api/docs/9"):
            ex = make_exchange(t, HTTPRequest("GET", path), B)
            eng.observe(ex)
            eng.analyze(ex)             # must not raise for any messy body
    assert eng._pass_errors == 0, "well-handled messy bodies should not even register as errors"


def test_drivers_isolate_per_exchange():
    """The HAR driver collects per-exchange analysis errors instead of dying."""
    from authpath import harimport
    assert hasattr(harimport, "_ANALYZE_ERRORS")   # the visible coverage-gap sink exists


# ----------------------------- S2: false-positive sensitivity -------------- #

def test_short_tokens_no_false_positive():
    for innocent in ("company", "japan", "shipping", "expand", "spinner",
                     "campaign", "public", "private_label_name", "single", "plan"):
        assert not _is_sensitive_key(innocent), f"{innocent!r} must NOT be sensitive"


def test_real_sensitive_fields_still_match():
    for s in ("ssn", "user_ssn", "userSSN", "iban", "iban_number", "secret",
              "private_key", "card_number", "api_key", "passport_number"):
        assert _is_sensitive_key(s), f"{s!r} must be sensitive"


def test_camelcase_is_tokenized():
    assert _is_sensitive_key("userSSN")
    assert _is_sensitive_key("customerIban")
    assert not _is_sensitive_key("companyName")


# ----------------------------- S4: international + extensibility ------------ #

def test_international_pii_covered():
    for s in ("national_id", "personnummer", "aadhaar", "cpf", "cnpj",
              "steuer_id", "codice_fiscale", "emirates_id", "tax_id"):
        assert _is_sensitive_key(s), f"international identifier {s!r} must be sensitive"


def test_operator_can_extend_vocabulary():
    field = "kunde_geheimnis_xyz"
    assert not _is_sensitive_key(field)
    try:
        register_sensitive_fields(["kunde_geheimnis_xyz", "رقم_الهوية"])
        assert _is_sensitive_key(field)
        assert _is_sensitive_key("رقم_الهوية")
    finally:
        _CUSTOM_SENSITIVE.discard("kunde_geheimnis_xyz")
        _CUSTOM_SENSITIVE.discard("رقم_الهوية")
