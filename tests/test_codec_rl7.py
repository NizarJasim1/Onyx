"""
RL7 codec regression suite — WIRE-FORMAT NORMALIZATION.

Locks the decode boundary that unblinds ONYX on the wire formats hyperscale APIs
actually use. Every test below exercised a path that returned ZERO values (a
silent false-clean) before RL7. Properties under guard:

  1. DECODED   — protobuf / gRPC-Web / multipart / ndjson recover real structure.
  2. VALUE-BLIND (RL1) — decoding recovers shape, never asserts value meaning, and
                 never fabricates a field absent on the wire.
  3. FAIL-SAFE — a dict/list passes through UNCHANGED (JSON byte-identical).
  4. HONEST    — an undecodable body becomes an explicit opaque marker, and the
                 engine surfaces it as "opaque-unanalyzed", never silent-clean.
  5. RESOURCE  — composite resource names yield a primary id + parent chain.
"""
from authpath.codec import (
    normalize_body, is_opaque, _decode_protobuf,
)
from authpath.provenance import extract_values
from authpath.models import HTTPRequest, HTTPResponse, Exchange, Principal
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.economy import BudgetLedger


def _varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | 0x80]) if n else bytes([b])
        if not n:
            return out


def _ld(field, s):
    sb = s.encode()
    return _varint((field << 3) | 2) + _varint(len(sb)) + sb


def _pb_message(idval, owner, secret=None):
    msg = _varint((1 << 3) | 0) + _varint(idval) + _ld(2, owner)
    if secret:
        msg += _ld(3, secret)
    return msg


# --- (1) DECODED ------------------------------------------------------------ #
def test_protobuf_decodes_to_canonical_dict():
    out = normalize_body(_pb_message(101, "B", "SSN-X"), "application/x-protobuf")
    assert out.fmt == "protobuf"
    assert out.data == {"f1": 101, "f2": "B", "f3": "SSN-X"}


def test_grpc_web_frame_strips_framing_and_decodes():
    msg = _pb_message(101, "B")
    frame = bytes([0x00]) + len(msg).to_bytes(4, "big") + msg
    out = normalize_body(frame, "application/grpc-web+proto")
    assert out.fmt == "grpc_web"
    assert out.data == {"f1": 101, "f2": "B"}


def test_grpc_web_skips_trailers_frame():
    msg = _pb_message(7, "Z")
    trailer = b"grpc-status:0\r\n"
    frame = (bytes([0x00]) + len(msg).to_bytes(4, "big") + msg
             + bytes([0x80]) + len(trailer).to_bytes(4, "big") + trailer)
    out = normalize_body(frame, "application/grpc-web+proto")
    assert out.data == {"f1": 7, "f2": "Z"}      # trailers ignored


def test_ndjson_becomes_a_list():
    body = '{"id":1,"owner":"A"}\n{"id":2,"ssn":"x"}\n{"id":3}'
    out = normalize_body(body, "application/x-ndjson")
    assert out.fmt == "ndjson"
    assert out.data == [{"id": 1, "owner": "A"}, {"id": 2, "ssn": "x"}, {"id": 3}]


def test_multipart_becomes_field_map():
    body = ('--BB\r\nContent-Disposition: form-data; name="id"\r\n\r\n101\r\n'
            '--BB\r\nContent-Disposition: form-data; name="ssn"\r\n\r\nABC\r\n--BB--')
    out = normalize_body(body, 'multipart/form-data; boundary=BB')
    assert out.fmt == "multipart"
    assert out.data == {"id": "101", "ssn": "ABC"}


def test_previously_blind_formats_now_yield_values():
    """The core regression: extract_values returned [] on these before RL7."""
    assert extract_values(_pb_message(101, "B", "x"))            # protobuf
    msg = _pb_message(101, "B")
    assert extract_values(bytes([0x00]) + len(msg).to_bytes(4, "big") + msg)  # grpc
    assert extract_values('{"a":1}\n{"b":2}')                    # ndjson


# --- (2) VALUE-BLIND + NEVER FABRICATE -------------------------------------- #
def test_decode_recovers_shape_not_meaning():
    """Field numbers become positional keys; we never claim 'f1 is a user id'."""
    out = _decode_protobuf(_pb_message(101, "B"))
    assert set(out.keys()) == {"f1", "f2"}        # positional, not semantic
    assert out["f1"] == 101 and out["f2"] == "B"


def test_absent_field_stays_absent():
    out = _decode_protobuf(_pb_message(101, "B"))   # no field 3
    assert "f3" not in out                          # never fabricated


def test_garbage_is_not_claimed_as_protobuf():
    # random bytes that are not a clean protobuf message must NOT decode
    out = normalize_body(bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x99, 0xFF]))
    assert out.opaque is True


def test_repeated_field_becomes_list():
    msg = _ld(1, "a") + _ld(1, "b") + _ld(1, "c")
    out = _decode_protobuf(msg)
    assert out["f1"] == ["a", "b", "c"]


# --- (3) FAIL-SAFE: JSON unchanged ------------------------------------------ #
def test_dict_passes_through_unchanged():
    d = {"id": 1, "owner_id": "B", "nested": {"x": [1, 2, 3]}}
    out = normalize_body(d)
    assert out.fmt == "json" and out.data is d        # identity, not a copy-decode


def test_list_passes_through_unchanged():
    lst = [{"a": 1}, {"b": 2}]
    out = normalize_body(lst)
    assert out.data is lst


# --- (4) HONEST opacity ----------------------------------------------------- #
def test_opaque_marker_is_not_empty():
    out = normalize_body(bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x99, 0xFF]))
    assert is_opaque(out.data) and out.data["bytes"] == 6


def test_engine_surfaces_opaque_not_clean():
    A = Principal("A", "Alice")
    eng = AuthPathEngine(_NullTarget(), {"A": A},
                         ScopeConfig(allowed_hosts=["h"], dry_run=False),
                         contract={}, ledger=BudgetLedger.unbounded())
    blob = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x99, 0x01, 0xFF, 0x00])
    tr = eng.analyze(Exchange(HTTPRequest("GET", "/api/orders/9", host="h"),
                              HTTPResponse(200, blob), A))
    assert tr.outcome == "opaque-unanalyzed"          # NOT "clean"
    assert any(getattr(l, "kind", "") == "OPAQUE_BODY" for _t, l in eng.leads)


class _NullTarget:
    def send(self, req, p):
        return HTTPResponse(200, {})


# --- (5) RESOURCE-NAME model ------------------------------------------------ #
def test_composite_resource_name_primary_and_parents():
    pid, parents, allids = HTTPRequest(
        "GET", "/v1/projects/123/locations/us/datasets/456", host="h").resource_name()
    assert pid == "456"
    assert [(p["collection"], p["id"]) for p in parents] == [("projects", "123"), ("locations", "us")]


def test_self_alias_not_treated_as_object():
    pid, parents, _ = HTTPRequest(
        "GET", "/v1/users/me/messages/AAMkAGI2/attachments/xyz", host="h").resource_name()
    assert pid == "xyz"
    # 'me' is a self-alias, not an object id; the message is the parent
    assert any(p["id"] == "AAMkAGI2" for p in parents)


def test_simple_path_primary_unchanged():
    assert HTTPRequest("GET", "/api/orders/101", host="h").primary_object_id() == "101"
