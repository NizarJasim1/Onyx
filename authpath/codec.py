"""
authpath.codec — the WIRE-FORMAT model (RL7: WIRE-FORMAT NORMALIZATION).

ONYX's laws and SAIE consume a canonical structured form (dict / list). The engine
implicitly assumed every captured body already WAS that form — decoded JSON. On a
hyperscale target that assumption is false for most traffic: Google/Apple/MS speak
protobuf, gRPC-Web, multipart and ndjson. `extract_values` returned [] on those,
so every law silently saw an EMPTY exchange and reported "clean" — a confident
false-negative, the most dangerous output a scanner can produce.

This module is the missing peer to the structure model: a decode BOUNDARY that
normalizes diverse wire encodings into the same dict/list the laws already read,
BEFORE any law runs. Two non-negotiable properties:

  * VALUE-BLIND (RL1 preserved). Schema-free decoding recovers STRUCTURE only —
    field positions, paths, wire-types, repetition — never meaning. A protobuf
    field becomes key "f<N>"; its wire-type maps to a value SHAPE (varint→number,
    length-delimited→string/bytes/nested) by form alone. We never assert "this
    varint is a user id". The existing value-blind classifier then runs unchanged.

  * FAIL-SAFE + HONEST. A dict/list passes through UNCHANGED (the JSON path is
    byte-identical — the calibration is untouched). A body that cannot be decoded
    is returned as an explicit OPAQUE marker, never as empty/clean, so the engine
    can report "opaque body — not analyzed" instead of lying about safety.

  * NEVER FABRICATE. A field absent on the wire is absent in the canonical form.
    Ambiguous length-delimited bytes are only promoted to a nested message when
    they parse cleanly and completely; otherwise they stay a string/bytes leaf.

Deterministic and pure: no network, no clock, no randomness.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# canonical result + opaque marker                                            #
# --------------------------------------------------------------------------- #

OPAQUE_KEY = "__opaque__"


@dataclass
class Decoded:
    """Result of normalization. `data` is the canonical dict/list the laws read
    (or an opaque marker). `fmt` names the recovered wire format. `opaque` is True
    when the body could not be structurally decoded — the engine MUST surface this
    rather than treat it as a clean/empty exchange."""
    data: Any
    fmt: str
    opaque: bool = False

    @property
    def is_structured(self) -> bool:
        return isinstance(self.data, (dict, list)) and not self.opaque


def opaque_marker(reason: str, size: int) -> dict:
    return {OPAQUE_KEY: True, "reason": reason, "bytes": size}


def is_opaque(body: Any) -> bool:
    return isinstance(body, dict) and body.get(OPAQUE_KEY) is True


# --------------------------------------------------------------------------- #
# public entry — the decode boundary                                          #
# --------------------------------------------------------------------------- #

def normalize_body(body: Any, content_type: Optional[str] = None,
                   schema: Optional[dict] = None) -> Decoded:
    """Normalize an arbitrary captured body into the canonical structured form.

    Fast path (byte-identical): an already-decoded dict/list is returned UNCHANGED.
    This guarantees the JSON world — and the whole calibration — behaves exactly as
    before. Only non-JSON inputs engage a decoder.

    RL7.2: when `schema` (a field-number → name map, possibly nested) is supplied
    for a schema-encoded format (protobuf/gRPC), the positional keys f<N> are
    renamed to their SEMANTIC names so name-based classification (id / owner_id /
    ssn / …) works identically to JSON. The schema supplies NAMES only — never
    value meaning (RL1). It never invents a name it was not given."""
    if isinstance(body, (dict, list)):
        return Decoded(body, "json")
    if body is None:
        return Decoded(None, "empty")

    ct = (content_type or "").lower()
    raw = _as_bytes(body)
    if raw is None:
        return Decoded(body, "scalar")        # a bare str/number leaf — leave it

    # content-type hints first (authoritative when present), then structural sniff.
    # NOTE: pass the ORIGINAL content_type (not lowercased) to decoders that read a
    # case-sensitive parameter — a multipart boundary is case-sensitive.
    order = _decoder_order(ct, raw, content_type or "")
    for name, fn in order:
        try:
            out = fn(raw)
        except Exception:
            out = None
        if out is not None:
            if schema and name in ("protobuf", "grpc_web"):
                out = apply_schema(out, schema)
            return Decoded(out, name)

    # could not structurally decode -> HONEST opaque, never silent-empty
    return Decoded(opaque_marker("undecodable wire format", len(raw)),
                   ct or "opaque", opaque=True)


def apply_schema(node: Any, schema: dict):
    """Recursively rename positional protobuf keys (f<N>) to semantic names using
    a field-map. A field-map entry may be a plain name, or {"name": str,
    "fields": <nested-map>} for sub-messages. Keys not covered by the schema keep
    their positional name (NEVER fabricate). value-blind: only KEYS are renamed."""
    if isinstance(node, list):
        return [apply_schema(x, schema) for x in node]
    if not isinstance(node, dict):
        return node
    out: dict = {}
    for k, v in node.items():
        spec = None
        if isinstance(k, str) and k.startswith("f") and k[1:].isdigit():
            spec = schema.get(int(k[1:])) or schema.get(k[1:]) or schema.get(k)
        if isinstance(spec, dict):
            name = spec.get("name", k)
            sub = spec.get("fields")
            out[name] = apply_schema(v, sub) if sub else v
        elif isinstance(spec, str):
            out[spec] = v
        else:
            out[k] = apply_schema(v, schema) if isinstance(v, (dict, list)) else v
    return out


class SchemaRegistry:
    """RL7.2 Slice A: endpoint → protobuf field-map. Optional and additive — an
    endpoint with no registered schema falls back to schema-free decode (shape
    classification). Deterministic; pure data."""
    def __init__(self):
        self._by_endpoint: dict[str, dict] = {}

    def register(self, endpoint_key: str, field_map: dict) -> None:
        self._by_endpoint[endpoint_key] = field_map

    def get(self, endpoint_key: str):
        return self._by_endpoint.get(endpoint_key)

    def __bool__(self):
        return bool(self._by_endpoint)


def _as_bytes(body: Any) -> Optional[bytes]:
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        # a JSON string body should be parsed as JSON, not treated as wire bytes
        return body.encode("latin-1", "ignore")
    return None


def _decoder_order(ct: str, raw: bytes, raw_ct: str = ""):
    """Pick decoder priority from the content-type, falling back to a structural
    sniff. Every decoder is also tried as a fallback so a mislabelled body still
    decodes. `raw_ct` is the original (case-preserving) content-type, used where a
    parameter (multipart boundary) is case-sensitive."""
    base = [
        ("json", _try_json),
        ("ndjson", _try_ndjson),
        ("multipart", lambda b: _try_multipart(b, raw_ct or ct)),
        ("grpc_web", _try_grpc_web),
        ("protobuf", _try_protobuf),
    ]
    # hint-driven reordering
    def key(item):
        n = item[0]
        if "grpc" in ct and n == "grpc_web": return 0
        if "protobuf" in ct and n == "protobuf": return 0
        if "x-ndjson" in ct and n == "ndjson": return 0
        if "multipart" in ct and n == "multipart": return 0
        if "json" in ct and n == "json": return 0
        return 1
    return sorted(base, key=key)


# --------------------------------------------------------------------------- #
# JSON / ndjson / multipart (structural splitters)                            #
# --------------------------------------------------------------------------- #

def _try_json(raw: bytes):
    import json
    text = raw.decode("utf-8", "strict")
    val = json.loads(text)
    return val if isinstance(val, (dict, list)) else None


def _try_ndjson(raw: bytes):
    """Newline-delimited JSON (MS Graph batch, streaming). Each non-empty line is a
    JSON value; the body becomes a list of them. Requires >=2 valid JSON lines so a
    single JSON object is not mis-split."""
    import json
    text = raw.decode("utf-8", "strict")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return None
    out = []
    for ln in lines:
        out.append(json.loads(ln))      # raises -> not ndjson -> fallback
    return out


def _try_multipart(raw: bytes, content_type: str):
    """multipart/form-data -> {field_name: value}. Boundary from the content-type
    when present, else sniffed from the body's leading '--<token>' line."""
    import re as _re
    text = raw.decode("latin-1", "ignore")
    boundary = None
    if "boundary=" in content_type:
        boundary = content_type.split("boundary=", 1)[1].strip().strip('"')
    if not boundary:
        first = text.lstrip().splitlines()[0] if text.strip() else ""
        if first.startswith("--"):
            boundary = first[2:].strip()
    if not boundary:
        return None
    parts = text.split("--" + boundary)
    fields: dict = {}
    name_re = _re.compile(r'name="([^"]*)"')
    for part in parts:
        if "Content-Disposition" not in part:
            continue
        m = name_re.search(part)
        if not m:
            continue
        name = m.group(1)
        # value is everything after the blank line separating headers from body,
        # with the trailing CRLF (and any trailing boundary terminator) stripped.
        sep = part.find("\r\n\r\n")
        seplen = 4
        if sep == -1:
            sep = part.find("\n\n")
            seplen = 2
        value = part[sep + seplen:] if sep != -1 else ""
        value = value.strip().rstrip("-").strip()
        fields[name] = value
    return fields if fields else None


# --------------------------------------------------------------------------- #
# gRPC-Web framing                                                            #
# --------------------------------------------------------------------------- #

def _try_grpc_web(raw: bytes):
    """A gRPC / gRPC-Web frame is: 1 compression-flag byte + 4 big-endian length
    bytes + that many message bytes (possibly repeated, plus a trailers frame
    whose flag has bit 0x80 set). We strip the framing and protobuf-decode the
    message frame(s)."""
    if len(raw) < 5:
        return None
    frames = []
    i = 0
    while i + 5 <= len(raw):
        flag = raw[i]
        length = int.from_bytes(raw[i + 1:i + 5], "big")
        i += 5
        if i + length > len(raw):
            return None                      # not a clean frame stream
        payload = raw[i:i + length]
        i += length
        if flag & 0x80:
            continue                         # trailers frame — metadata, skip
        msg = _decode_protobuf(payload)
        if msg is None:
            return None
        frames.append(msg)
    if i != len(raw) or not frames:
        return None                          # leftover bytes -> not gRPC framing
    return frames[0] if len(frames) == 1 else frames


# --------------------------------------------------------------------------- #
# schema-free protobuf decoder (value-blind structure recovery)              #
# --------------------------------------------------------------------------- #

_WT_VARINT, _WT_64, _WT_LEN, _WT_SGROUP, _WT_EGROUP, _WT_32 = 0, 1, 2, 3, 4, 5


def _try_protobuf(raw: bytes):
    if not raw:
        return None
    msg = _decode_protobuf(raw)
    # Reject trivially-degenerate parses (a single unprintable byte etc.) so we do
    # not claim structure that is not there.
    if not isinstance(msg, dict) or not msg:
        return None
    return msg


def _read_varint(buf: bytes, pos: int):
    shift = 0
    result = 0
    while pos < len(buf):
        b = buf[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def _decode_protobuf(buf: bytes, depth: int = 0):
    """Parse a protobuf message WITHOUT its schema into a canonical dict.

    Keys are 'f<field_number>'. Repeated fields become lists. Wire-types map to
    SHAPE only (RL1):
      varint (0)      -> int
      64-bit (1)      -> {'__fixed64__': int}   (opaque fixed-width number)
      32-bit (5)      -> {'__fixed32__': int}
      length-delim (2)-> nested message if it parses cleanly & completely; else a
                         UTF-8 string if valid; else {'__bytes__': len}.
    Returns None if the buffer is not a clean, fully-consumed protobuf message
    (so we never claim a false structure — NEVER FABRICATE)."""
    if depth > 12:
        return None
    out: dict = {}
    pos = 0
    n = len(buf)
    while pos < n:
        try:
            tag, pos = _read_varint(buf, pos)
        except ValueError:
            return None
        field_no = tag >> 3
        wire = tag & 0x07
        if field_no == 0:
            return None
        key = f"f{field_no}"
        if wire == _WT_VARINT:
            try:
                val, pos = _read_varint(buf, pos)
            except ValueError:
                return None
        elif wire == _WT_64:
            if pos + 8 > n:
                return None
            val = {"__fixed64__": int.from_bytes(buf[pos:pos + 8], "little")}
            pos += 8
        elif wire == _WT_32:
            if pos + 4 > n:
                return None
            val = {"__fixed32__": int.from_bytes(buf[pos:pos + 4], "little")}
            pos += 4
        elif wire == _WT_LEN:
            try:
                ln, pos = _read_varint(buf, pos)
            except ValueError:
                return None
            if pos + ln > n:
                return None
            chunk = buf[pos:pos + ln]
            pos += ln
            val = _decode_length_delimited(chunk, depth)
        else:
            return None                       # groups / unknown wire-type -> reject
        _append(out, key, val)
    return out


def _decode_length_delimited(chunk: bytes, depth: int):
    """Disambiguate a length-delimited field by SHAPE, preferring nested structure
    only on a clean complete parse (never fabricate)."""
    if chunk == b"":
        return ""
    nested = _decode_protobuf(chunk, depth + 1)
    if isinstance(nested, dict) and nested:
        return nested
    try:
        s = chunk.decode("utf-8", "strict")
        if s.isprintable() or s.strip() == "":
            return s
    except UnicodeDecodeError:
        pass
    return {"__bytes__": len(chunk)}


def _append(out: dict, key: str, val: Any):
    if key in out:
        if isinstance(out[key], list):
            out[key].append(val)
        else:
            out[key] = [out[key], val]
    else:
        out[key] = val


# --------------------------------------------------------------------------- #
# Slice 5 — resource-name model (AIP-122 composite names)                     #
# --------------------------------------------------------------------------- #

# Collection segments that are CONTAINERS, not the addressed object. The last
# id-bearing segment is the primary object; earlier ones form the parent chain.
def parse_resource_name(path: str):
    """Split a REST/AIP-122 path into (primary_object_id, parent_chain, all_ids).

    A canonical resource path alternates collection/id: collection1/id1/collection2/
    id2/...  The PRIMARY object is the last id; its parents are the earlier ids,
    each tagged by its collection. This fixes object_ids() conflating a location
    qualifier ('us') with an object id. value-blind: we use POSITION + the
    collection word, never the id's meaning."""
    from .models import _looks_like_id  # reuse the existing id-shape oracle
    segs = [s for s in path.strip("/").split("/") if s]
    pairs = []          # (collection, id)
    i = 0
    while i < len(segs):
        collection = segs[i]
        ident = segs[i + 1] if i + 1 < len(segs) else None
        if ident is not None and _looks_like_id(ident):
            pairs.append((collection, ident))
            i += 2
        else:
            i += 1
    if not pairs:
        return (None, [], [])
    primary_collection, primary_id = pairs[-1]
    parents = [{"collection": c, "id": v} for c, v in pairs[:-1]]
    all_ids = [v for _c, v in pairs]
    return (primary_id, parents, all_ids)
