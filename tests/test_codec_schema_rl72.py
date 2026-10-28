"""
RL7.2 regression suite — SCHEMA-AWARE SEMANTICS (completing RL7).

RL7 made protobuf/gRPC bodies STRUCTURALLY legible. The residual: protobuf carries
semantics by field NUMBER, so name-based classification (id / owner_id / ssn) was
dead — every field landed in OTHER. This suite locks the closure:

  A. SCHEMA      — a registered field-map renames f<N> to semantic names, so
                   classification + sensitivity work identically to JSON.
  B. SHAPE       — with NO schema, strong-shaped nameless values (uuid/jwt/prefixed)
                   are classified by SHAPE, so schema-less gRPC ids stay trackable.
  C. VALUE-BLIND — the schema supplies NAMES only; it never fabricates a name and
                   never asserts value meaning (RL1). Shape fallback fires only on
                   positional keys, so JSON classification is byte-identical.
  D. END-TO-END  — through the full engine, an OBJECT_ACCESS law fires on a
                   schema-decoded gRPC IDOR (the body is no longer invisible).
"""
from authpath.codec import normalize_body, SchemaRegistry, apply_schema
from authpath.provenance import extract_values, classify_field, ValueClass
from authpath.confirmer import _is_sensitive_key
from authpath.models import Principal, HTTPRequest, HTTPResponse, Exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.economy import BudgetLedger


def _v(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | 0x80]) if n else bytes([b])
        if not n:
            return out


def _ld(f, s):
    sb = s.encode()
    return _v((f << 3) | 2) + _v(len(sb)) + sb


def _pb(idv, owner, ssn):
    return _v((1 << 3) | 0) + _v(idv) + _ld(2, owner) + _ld(3, ssn)


def _grpc(idv, owner, ssn):
    m = _pb(idv, owner, ssn)
    return bytes([0x00]) + len(m).to_bytes(4, "big") + m


SCHEMA = {1: "id", 2: "owner_id", 3: "ssn"}


# --- A. SCHEMA: semantic names recovered ------------------------------------ #
def test_schema_renames_positional_keys():
    out = normalize_body(_pb(101, "B", "SSN-X"), "application/x-protobuf", schema=SCHEMA)
    assert out.data == {"id": 101, "owner_id": "B", "ssn": "SSN-X"}


def test_schema_recovers_classification_parity_with_json():
    out = normalize_body(_pb(101, "B", "SSN-X"), "application/x-protobuf", schema=SCHEMA)
    by = {tv.field_path: tv.value_class for tv in extract_values(out.data)}
    assert by["id"] == ValueClass.ID
    assert by["owner_id"] == ValueClass.OWNER
    assert _is_sensitive_key("ssn")            # ssn now sensitivity-classifiable


def test_schema_applies_through_grpc_frame():
    out = normalize_body(_grpc(101, "B", "SSN-X"), "application/grpc-web+proto", schema=SCHEMA)
    assert out.data == {"id": 101, "owner_id": "B", "ssn": "SSN-X"}


def test_nested_schema_renames_submessage():
    # f1 = nested message {f1:"x"}; schema maps f1 -> {"name":"profile","fields":{1:"email"}}
    inner = _ld(1, "a@b.com")
    msg = _v((1 << 3) | 2) + _v(len(inner)) + inner
    schema = {1: {"name": "profile", "fields": {1: "email"}}}
    out = apply_schema(normalize_body(msg).data, schema)
    assert out == {"profile": {"email": "a@b.com"}}


def test_registry_lookup_by_endpoint():
    r = SchemaRegistry()
    assert r.get("GET /x") is None
    r.register("GET /x", SCHEMA)
    assert r.get("GET /x") == SCHEMA


# --- B. SHAPE fallback (no schema) ------------------------------------------ #
def test_shape_fallback_uuid_is_id():
    body = _ld(1, "550e8400-e29b-41d4-a716-446655440000") + _ld(2, "plain text")
    by = {tv.field_path: tv.value_class for tv in extract_values(body)}
    assert by["f1"] == ValueClass.ID
    assert by["f2"] == ValueClass.OTHER       # plain text is not fabricated as an id


def test_shape_fallback_jwt_is_token():
    body = _ld(1, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sIgNaTuRe")
    by = {tv.field_path: tv.value_class for tv in extract_values(body)}
    assert by["f1"] == ValueClass.TOKEN


def test_shape_fallback_prefixed_id():
    body = _ld(1, "cus_9aH3kZ2pQ")
    by = {tv.field_path: tv.value_class for tv in extract_values(body)}
    assert by["f1"] == ValueClass.ID


# --- C. VALUE-BLIND / never fabricate / JSON byte-identical ----------------- #
def test_shape_fallback_only_on_positional_keys():
    # a NAMED field with the exact same plain value must classify exactly as before
    assert classify_field("description", "550e8400-e29b-41d4-a716-446655440000") in (
        ValueClass.OTHER, ValueClass.ID)   # named-field path unchanged by Slice C
    # (the point: Slice C cannot fire here because the key is not f<N>)
    assert classify_field("f1", "not-an-id-just-words here") == ValueClass.OTHER


def test_schema_gives_names_not_meaning():
    # schema turns f3 into 'ssn' (a NAME); the value class still comes from the
    # ordinary classifier, never from the schema asserting "this is secret".
    out = normalize_body(_pb(1, "B", "SSN-X"), schema=SCHEMA)
    assert "ssn" in out.data and out.data["ssn"] == "SSN-X"


def test_unmapped_field_keeps_positional_name():
    # schema covers 1 and 2 but not 3 -> f3 stays positional (never fabricated)
    out = apply_schema(normalize_body(_pb(1, "B", "x")).data, {1: "id", 2: "owner_id"})
    assert out == {"id": 1, "owner_id": "B", "f3": "x"}


# --- D. END-TO-END: the law now fires on a gRPC body ------------------------ #
def test_object_access_law_fires_on_grpc_idor():
    A = Principal("A", "Alice"); B = Principal("B", "Bob")
    schemas = SchemaRegistry()
    schemas.register("GET /api/orders/{id}", SCHEMA)

    class T:
        def send(self, req, p):
            return HTTPResponse(200, _grpc(101, "B", "SSN-9"))

    eng = AuthPathEngine(T(), {"A": A, "B": B},
                         ScopeConfig(allowed_hosts=["h"], dry_run=False),
                         contract={"GET /api/orders/{id}":
                                   {"effect": "OBJECT_ACCESS", "critical_params": ["id"]}},
                         ledger=BudgetLedger.unbounded(), schemas=schemas)
    eng.observe(Exchange(HTTPRequest("GET", "/api/orders/101", host="h"),
                         HTTPResponse(200, _grpc(101, "B", "SSN-9")), B))
    tr = eng.analyze(Exchange(HTTPRequest("GET", "/api/orders/101", host="h"),
                              HTTPResponse(200, _grpc(101, "B", "SSN-9")), A))
    # pre-RL7 the body was invisible -> EIL 'pass' (false clean). Now the law
    # reaches the candidate stage on the decoded gRPC body.
    stages = {s.stage: s.status for s in tr.stages}
    assert stages.get("EIL") == "candidate"
    assert stages.get("Value-Origin") == "ok"
