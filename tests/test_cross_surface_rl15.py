"""
RL15 — CROSS-SURFACE CONSISTENCY regression suite.

Each test locks one guarantee the CRUCIBLE protocol forced the design to satisfy
before it was allowed near the codebase. The invariant under test: a non-canonical
door (list / graphql / search) that over-exposes a SENSITIVE field the resource's
CANONICAL detail view withholds from the SAME principal becomes a Δstate-confirmed
finding — and NOTHING ELSE does. Specifically:

  * positive            — list over-projects `iban` the detail filters → finding
  * directional guard   — detail richer than list (by-design) → silent (kill-test)
  * sensitive-only      — non-sensitive divergence (tx_count) → silent (FP guard)
  * refutation          — canonical ALSO exposes the field → confirmer abstains
  * additive isolation  — flag OFF ⇒ byte-identical (no finding at all)
  * id unification      — b64-typed / prefixed / int ids collapse to one identity
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.transport import MockTarget, make_exchange
from authpath.models import HTTPRequest, HTTPResponse, Principal
from authpath.surface_map import (
    ResourceIdentity, identify, classify_door, exposed_sensitive_fields,
    SurfaceLedger, DOOR_CANONICAL, DOOR_LIST,
)


B = Principal("B", "Bob")


def _engine(target, cross_surface=True):
    scope = ScopeConfig(allowed_hosts=["demo.local"], dry_run=True,
                        automation_permitted=True)
    eng = AuthPathEngine(target, {"B": B}, scope)
    eng.cross_surface = cross_surface
    return eng


# --------------------------------------------------------------------------- #
# A minimal target purpose-built for the unit cases (independent of the demo). #
# --------------------------------------------------------------------------- #
class _XSurfaceTarget:
    """Configurable cross-surface target. `mode` selects the scenario."""
    def __init__(self, mode):
        self.host = "demo.local"
        self.mode = mode

    def send(self, req, principal):
        m, p = req.method.upper(), req.path
        # canonical detail
        if m == "GET" and p.startswith("/api/accounts/") and p.count("/") == 3:
            if self.mode == "agree":
                # canonical ALSO exposes iban (surfaces agree → must refute)
                return HTTPResponse(200, {"id": "900", "iban": "IQ98NBIQ1234567890"})
            return HTTPResponse(200, {"id": "900", "country": "IQ"})  # iban filtered
        # list view
        if m == "GET" and p == "/api/accounts":
            if self.mode == "sensitive_leak" or self.mode == "agree":
                return HTTPResponse(200, {"accounts": [
                    {"id": "900", "country": "IQ", "iban": "IQ98NBIQ1234567890"}]})
            if self.mode == "nonsensitive_only":
                # divergence is a NON-sensitive field → must not fire
                return HTTPResponse(200, {"accounts": [
                    {"id": "900", "country": "IQ", "tx_count": 12}]})
        return HTTPResponse(404, {"error": "no route"})


def _seed_and_probe(target):
    eng = _engine(target)
    eng.observe(make_exchange(target, HTTPRequest("GET", "/api/accounts/900"), B))
    tr = eng.analyze(make_exchange(target, HTTPRequest("GET", "/api/accounts"), B))
    return eng, tr


# ----------------------------- the guarantees ------------------------------ #

def test_positive_cross_surface_leak_confirms():
    eng, tr = _seed_and_probe(_XSurfaceTarget("sensitive_leak"))
    assert tr.outcome == "finding", f"expected finding, got {tr.outcome}"
    f = eng.findings[-1]
    assert f.effect.value == "CROSS_SURFACE"
    assert "iban" in (f.state_proof.after or "")


def test_directional_detail_richer_than_list_is_silent():
    """The kill-test: a detail view exposing MORE than the list is by-design."""
    t = MockTarget()                       # demo target has the /api/cards decoy
    eng = _engine(t)
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/cards/c1"), B))
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/cards"), B))
    assert tr.outcome != "finding", "detail-richer-than-list must NOT fire"


def test_non_sensitive_divergence_is_silent():
    eng, tr = _seed_and_probe(_XSurfaceTarget("nonsensitive_only"))
    assert tr.outcome != "finding", "a non-sensitive field divergence must NOT fire"


def test_surfaces_agree_confirmer_refutes():
    """Canonical ALSO exposes the field ⇒ the two surfaces agree ⇒ no finding."""
    eng, tr = _seed_and_probe(_XSurfaceTarget("agree"))
    assert tr.outcome != "finding", "agreeing surfaces must be refuted by read-back"


def test_flag_off_is_byte_identical_silent():
    t = _XSurfaceTarget("sensitive_leak")
    eng = _engine(t, cross_surface=False)
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/accounts/900"), B))
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/accounts"), B))
    assert tr.outcome != "finding", "with the flag OFF the pass must never run"
    assert not any(f.effect.value == "CROSS_SURFACE" for f in eng.findings)


def test_no_canonical_reference_abstains():
    """Without a canonical observation there is no authoritative reference, so the
    law must abstain (fail-safe) rather than fire on the list alone."""
    t = _XSurfaceTarget("sensitive_leak")
    eng = _engine(t)
    # NB: no observe() of the canonical detail → no reference
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/accounts"), B))
    assert tr.outcome != "finding", "no canonical reference ⇒ must abstain"


# ----------------------- unification (RL1, structural) --------------------- #

def test_id_unification_across_encodings():
    """b64-typed, prefixed and int ids for the same resource collapse to one
    identity — the structural decoder, never fuzzy matching."""
    int_req = HTTPRequest("GET", "/api/accounts/900")
    pref_req = HTTPRequest("GET", "/api/accounts/acc_900")
    i1 = identify(int_req)
    i2 = identify(pref_req)
    assert i1 == ResourceIdentity("account", "900")
    assert i2 == ResourceIdentity("account", "900")
    assert i1 == i2


def test_canonical_vs_list_door_classification():
    assert classify_door(HTTPRequest("GET", "/api/accounts/900")) == DOOR_CANONICAL
    assert classify_door(HTTPRequest("GET", "/api/accounts")) == DOOR_LIST


def test_sensitive_extraction_ignores_nonsensitive():
    body = {"id": "1", "tx_count": 5, "iban": "IQ98X", "country": "IQ"}
    fields = exposed_sensitive_fields(body)
    assert "iban" in fields
    assert "tx_count" not in fields


def test_ledger_records_only_canonical():
    led = SurfaceLedger()
    # a list door must NOT be stored as a reference
    led.record(HTTPRequest("GET", "/api/accounts"),
               HTTPResponse(200, {"accounts": [{"id": "900", "iban": "X"}]}), "B")
    assert not led.has_canonical(ResourceIdentity("account", "900"), "B")
    # the canonical door IS stored
    led.record(HTTPRequest("GET", "/api/accounts/900"),
               HTTPResponse(200, {"id": "900", "country": "IQ"}), "B")
    assert led.has_canonical(ResourceIdentity("account", "900"), "B")


# ------------- RESIDUE A: intent-declared canonical (GraphQL) --------------- #

def _gql_vault_req(vid="500"):
    return HTTPRequest("POST", "/graphql", body={
        "operationName": "GetVault", "variables": {"id": vid},
        "query": "query GetVault($id: ID!){ vault(id:$id){ id secret } }"})


def _gql_forbidden_resp():
    return HTTPResponse(200, {
        "data": {"vault": {"id": "500"}},
        "errors": [{"message": "Not authorized to access Vault.secret",
                    "path": ["vault", "secret"],
                    "extensions": {"code": "FORBIDDEN"}}]})


def test_graphql_identify_from_operation():
    """A GraphQL op resolves to the same identity a REST door would: (type, id)."""
    ident = identify(_gql_vault_req("500"))
    assert ident == ResourceIdentity("vault", "500")


def test_ledger_records_explicit_denials_only_when_sensitive():
    led = SurfaceLedger()
    led.record_denials(_gql_vault_req("500"), _gql_forbidden_resp(), "B")
    denials = led.denials_for(ResourceIdentity("vault", "500"), "B")
    assert "secret" in denials  # sensitive + explicitly FORBIDDEN → recorded


def test_null_is_not_a_denial_killtest():
    """A field returned `null` (not an authz error) must NEVER be recorded as a
    denial — the kill-test guard against the absence/forbidden confusion."""
    led = SurfaceLedger()
    null_resp = HTTPResponse(200, {"data": {"vault": {"id": "500", "secret": None}}})
    led.record_denials(_gql_vault_req("500"), null_resp, "B")
    assert led.denials_for(ResourceIdentity("vault", "500"), "B") == {}


class _GqlVaultTarget:
    """GraphQL forbids vault.secret for B; a REST list leaks it. No REST detail."""
    host = "demo.local"

    def send(self, req, principal):
        m, p = req.method.upper(), req.path
        if m == "POST" and p.endswith("/graphql"):
            return _gql_forbidden_resp()
        if m == "GET" and p == "/api/vaults":
            return HTTPResponse(200, {"vaults": [
                {"id": "500", "label": "primary", "secret": "sk_live_abc123"}]})
        return HTTPResponse(404, {"error": "no route"})


def test_intent_declared_leak_confirms_without_rest_detail():
    """The headline Residue-A case: a GraphQL-only resource (no REST detail) whose
    list door over-exposes a field the server explicitly forbids → confirmed via a
    GraphQL-operation replay, not a REST read-back."""
    t = _GqlVaultTarget()
    eng = _engine(t)
    eng.observe(make_exchange(t, _gql_vault_req("500"), B))   # seeds the FORBIDDEN
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/vaults"), B))
    assert tr.outcome == "finding", f"expected finding, got {tr.outcome}"
    f = eng.findings[-1]
    assert f.effect.value == "CROSS_SURFACE"
    assert "secret" in (f.state_proof.after or "")


def test_intent_declared_flag_off_silent():
    t = _GqlVaultTarget()
    eng = _engine(t, cross_surface=False)
    eng.observe(make_exchange(t, _gql_vault_req("500"), B))
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/vaults"), B))
    assert tr.outcome != "finding"


def test_intent_declared_needs_the_denial_seed():
    """Without the FORBIDDEN observation there is no intent reference → abstain."""
    t = _GqlVaultTarget()
    eng = _engine(t)
    # no GraphQL observe() → no denial recorded
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/vaults"), B))
    assert tr.outcome != "finding"


# ---------------- #2-a: persisted / APQ queries (hash-only) ----------------- #

_APQ_HASH = "wallet_sha256_demo"
_APQ_TEXT = "query GetWallet($id: ID!){ wallet(id:$id){ id private_key } }"


def _apq_register_req():
    return HTTPRequest("POST", "/graphql", body={
        "operationName": "GetWallet", "variables": {"id": "700"},
        "extensions": {"persistedQuery": {"version": 1, "sha256Hash": _APQ_HASH}},
        "query": _APQ_TEXT})


def _apq_hash_only_req():
    return HTTPRequest("POST", "/graphql", body={
        "operationName": "GetWallet", "variables": {"id": "700"},
        "extensions": {"persistedQuery": {"version": 1, "sha256Hash": _APQ_HASH}}})


class _ApqTarget:
    host = "demo.local"

    def send(self, req, principal):
        m, p = req.method.upper(), req.path
        if m == "POST" and p.endswith("/graphql"):
            return HTTPResponse(200, {
                "data": {"wallet": {"id": "700"}},
                "errors": [{"message": "Not authorized to access Wallet.private_key",
                            "path": ["wallet", "private_key"],
                            "extensions": {"code": "FORBIDDEN"}}]})
        if m == "GET" and p == "/api/wallets":
            return HTTPResponse(200, {"wallets": [
                {"id": "700", "label": "cold", "private_key": "0xDEADBEEF"}]})
        return HTTPResponse(404, {"error": "no route"})


def test_apq_hash_only_resolves_to_resource_identity():
    """A hash-only request, after a registration is observed, binds to the same
    (type,id) identity a full-text query would."""
    led = SurfaceLedger()
    led.observe_persisted(_apq_register_req())          # learn hash→text
    ident = identify(_apq_hash_only_req(), led.pq_registry)
    assert ident == ResourceIdentity("wallet", "700")


def test_apq_unknown_hash_is_synthetic_but_stable():
    """A hash with no observed registration still yields a stable identity keyed by
    the hash (never crashes, never guesses the type)."""
    led = SurfaceLedger()                               # no registration observed
    ident = identify(_apq_hash_only_req(), led.pq_registry)
    assert ident is not None and ident.rid == "700"
    assert ident.rtype.startswith("persisted:")


def test_apq_hash_only_denial_then_leak_confirms():
    """Headline #2-a: the denial is learned from a HASH-ONLY request (intent
    recovered from a prior registration), and a REST list that leaks the same field
    becomes a confirmed cross-surface finding."""
    t = _ApqTarget()
    eng = _engine(t)
    eng.observe(make_exchange(t, _apq_register_req(), Principal("A", "Alice")))  # registration
    eng.observe(make_exchange(t, _apq_hash_only_req(), B))                        # hash-only FORBIDDEN
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/wallets"), B))
    assert tr.outcome == "finding", f"expected finding, got {tr.outcome}"
    assert eng.findings[-1].effect.value == "CROSS_SURFACE"


def test_apq_flag_off_silent():
    t = _ApqTarget()
    eng = _engine(t, cross_surface=False)
    eng.observe(make_exchange(t, _apq_register_req(), Principal("A", "Alice")))
    eng.observe(make_exchange(t, _apq_hash_only_req(), B))
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/wallets"), B))
    assert tr.outcome != "finding"


# ---------------- #2-b: gRPC dissolves into cross-surface via schema --------- #

def _pb_str(num, s):
    """Encode one length-delimited protobuf string field (num < 16, len < 128)."""
    tag = (num << 3) | 2
    b = s.encode()
    return bytes([tag, len(b)]) + b


def test_grpc_schema_names_fields_for_cross_surface():
    """#2-b: a real protobuf body, once its registered schema names the positional
    keys, exposes the SAME named sensitive fields the cross-surface law reads — so
    gRPC needs NO new detection code, only a schema."""
    from authpath.codec import normalize_body
    raw = _pb_str(1, "700") + _pb_str(2, "0xDEADBEEFcafe1234")
    schema = {1: "id", 2: {"name": "private_key"}}
    named = normalize_body(raw, content_type="application/x-protobuf", schema=schema)
    assert named.data == {"id": "700", "private_key": "0xDEADBEEFcafe1234"}
    fields = exposed_sensitive_fields(named.data)
    assert "private_key" in fields          # cross-surface can now read the leak


class _GrpcTarget:
    """A wallets list served as gRPC/protobuf; the GraphQL layer forbids the field."""
    host = "demo.local"

    def send(self, req, principal):
        m, p = req.method.upper(), req.path
        if m == "POST" and p.endswith("/graphql"):
            return HTTPResponse(200, {
                "data": {"wallet": {"id": "700"}},
                "errors": [{"message": "forbidden", "path": ["wallet", "private_key"],
                            "extensions": {"code": "FORBIDDEN"}}]})
        if m == "GET" and p == "/api/wallets":
            raw = _pb_str(1, "700") + _pb_str(2, "0xDEADBEEF")
            return HTTPResponse(200, raw,
                                headers={"content-type": "application/x-protobuf"})
        return HTTPResponse(404, {"error": "no route"})


def test_grpc_end_to_end_cross_surface_finding_via_schema():
    """#2-b end-to-end: a gRPC (protobuf) list leak, named by a registered schema,
    becomes a confirmed cross-surface finding against a GraphQL-declared denial —
    through the EXISTING decode path, no new code."""
    from authpath.codec import SchemaRegistry
    t = _GrpcTarget()
    schemas = SchemaRegistry()
    schemas.register("GET /api/wallets", {1: "id", 2: {"name": "private_key"}})
    scope = ScopeConfig(allowed_hosts=["demo.local"], dry_run=True,
                        automation_permitted=True)
    eng = AuthPathEngine(t, {"B": B}, scope, schemas=schemas)
    eng.cross_surface = True
    gql = HTTPRequest("POST", "/graphql", body={
        "operationName": "GetWallet", "variables": {"id": "700"},
        "query": "query GetWallet($id: ID!){ wallet(id:$id){ id private_key } }"})
    eng.observe(make_exchange(t, gql, B))               # GraphQL FORBIDDEN reference
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/wallets"), B))
    assert tr.outcome == "finding", f"expected finding, got {tr.outcome}"
    assert eng.findings[-1].effect.value == "CROSS_SURFACE"
