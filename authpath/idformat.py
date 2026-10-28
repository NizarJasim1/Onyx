"""
GAP 1 — id-format intelligence.

The field taxonomy (107 disclosed BOLA reports) shows 39.2% of real cases use
ENCODED identifiers (base64 GraphQL global ids, UUIDs, hex, prefixed strings), and
the GraphQL global-id decode->increment->re-encode pattern is exploited
systematically across GitLab/Shopify/HackerOne. ONYX could thread a verbatim
observed id to other principals (direct-ref BOLA) but could not ENUMERATE
neighbours in an encoded id-space.

This module DETECTS the structure of an observed id (conservatively, confidence-
ranked) and generates structure-preserving NEIGHBOUR candidates. It only PROPOSES
candidate id strings; every probe built from them is still gated by the engine's
Δstate confirmation, so it is structurally incapable of adding a false positive — it
widens REACH, not judgment. Ambiguous/unknown formats fall back to verbatim only
(today's behaviour). Output is bounded, sorted, deterministic.
"""
from __future__ import annotations

import base64
import re
import string
from dataclasses import dataclass, field


@dataclass
class IdShape:
    kind: str                 # int | padded_int | uuid | hex | b64_typed | prefixed | unknown
    confidence: int           # 0..100
    detail: dict = field(default_factory=dict)


_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{6,}$")
_PREFIX_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]*[_\-])(\d+)$")   # usr_1007, ord-42
_TYPED_B64_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]*):(\d+)$")    # decoded "Order:42"


def _try_b64(s: str):
    """Return (decoded_text, style) if s is base64 (standard OR url-safe) of printable
    text, else None. style records url-safe + padding so neighbours match exactly."""
    urlsafe = ("-" in s or "_" in s)
    padded = s.endswith("=")
    core = s.rstrip("=")
    alphabet = (r"[A-Za-z0-9\-_]" if urlsafe else r"[A-Za-z0-9+/]")
    if len(core) < 4 or not re.fullmatch(alphabet + "+", core):
        return None
    cand = core + "=" * (-len(core) % 4)
    try:
        decoder = base64.urlsafe_b64decode if urlsafe else base64.b64decode
        raw = decoder(cand)
        text = raw.decode("ascii")
    except Exception:
        return None
    if all(c in string.printable for c in text):
        return text, {"urlsafe": urlsafe, "padded": padded}
    return None


def _b64_encode(text: str, style: dict) -> str:
    enc = (base64.urlsafe_b64encode if style.get("urlsafe")
           else base64.b64encode)(text.encode()).decode()
    if not style.get("padded"):
        enc = enc.rstrip("=")
    return enc


def detect_shape(value) -> IdShape:
    """Conservatively detect an id's structure. Higher confidence == safer to mutate."""
    s = str(value)
    if s.isdigit():
        if len(s) > 1 and s[0] == "0":
            return IdShape("padded_int", 90, {"width": len(s)})
        return IdShape("int", 95, {})
    if _UUID_RE.match(s):
        return IdShape("uuid", 80, {})                  # mutable but high-entropy
    m = _PREFIX_RE.match(s)
    if m:
        return IdShape("prefixed", 90, {"prefix": m.group(1), "num": m.group(2)})
    b64 = _try_b64(s)
    if b64 is not None:
        decoded, style = b64
        tm = _TYPED_B64_RE.match(decoded)
        if tm:
            return IdShape("b64_typed", 95,
                           {"type": tm.group(1), "num": tm.group(2),
                            "decoded": decoded, "style": style})
        if decoded.isdigit():
            return IdShape("b64_typed", 85,
                           {"type": "", "num": decoded, "decoded": decoded, "style": style})
    if _HEX_RE.match(s):
        return IdShape("hex", 70, {"width": len(s)})
    return IdShape("unknown", 0, {})


def neighbours(value, *, max_neighbours: int = 6) -> list:
    """Generate structure-preserving neighbour candidate ids (deterministic, bounded).
    For an UNKNOWN/low-confidence shape, returns [] (caller falls back to verbatim)."""
    shape = detect_shape(value)
    s = str(value)
    span = max(1, max_neighbours // 2)
    out = []

    def add(v):
        if v != s and v not in out:
            out.append(v)

    if shape.kind == "int":
        n = int(s)
        for d in range(1, span + 1):
            if n - d >= 0:
                add(str(n - d))
            add(str(n + d))
    elif shape.kind == "padded_int":
        n, w = int(s), shape.detail["width"]
        for d in range(1, span + 1):
            if n - d >= 0:
                add(str(n - d).zfill(w))
            add(str(n + d).zfill(w))
    elif shape.kind == "prefixed":
        pre, num = shape.detail["prefix"], int(shape.detail["num"])
        w = len(shape.detail["num"]) if shape.detail["num"][0] == "0" else 0
        for d in range(1, span + 1):
            if num - d >= 0:
                add(pre + (str(num - d).zfill(w) if w else str(num - d)))
            add(pre + (str(num + d).zfill(w) if w else str(num + d)))
    elif shape.kind == "b64_typed":
        typ = shape.detail.get("type", "")
        num = int(shape.detail["num"])
        style = shape.detail.get("style", {"urlsafe": False, "padded": True})
        for d in range(1, span + 1):
            for cand in ((num - d) if num - d >= 0 else None, num + d):
                if cand is None:
                    continue
                decoded = f"{typ}:{cand}" if typ else str(cand)
                add(_b64_encode(decoded, style))
    # uuid / hex / unknown -> no safe sequential neighbour: return [] (verbatim only)
    return out[:max_neighbours]


def expand_ids(observed_id, *, enabled: bool, max_neighbours: int = 6) -> list:
    """The matrix entry point. enabled=False (default) => [observed] only (today's
    behaviour, byte-identical). enabled=True => observed + structure-preserving
    neighbours (still each Δstate-gated downstream)."""
    base = [str(observed_id)]
    if not enabled:
        return base
    return base + neighbours(observed_id, max_neighbours=max_neighbours)
