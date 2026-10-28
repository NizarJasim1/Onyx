"""
authpath.frontend_contract — FRONTEND CONTRACT EXTRACTOR (FCX).

WHAT THIS IS, EPISTEMICALLY (read this before the code — RL1 lives or dies here)
--------------------------------------------------------------------------------
`discovery.py` closes its own docstring with an honest boundary:

    "HONEST BOUNDARY: this finds DECLARED endpoints. Hidden/undocumented
     endpoints need JS/source-map mining + fuzzing (noisier, separate) —
     not claimed here."

This module addresses the FIRST half of that sentence and explicitly REFUSES the
second. It mines JS. It does not fuzz, does not guess, and does not execute.

The load-bearing distinction is between two things that look alike and are not:

  (A) "a string in a bundle that LOOKS LIKE a path"      -> INDUCTION. Forbidden.
  (B) "a string literal occupying a parameter position   -> TRANSCRIPTION.
       whose meaning is fixed by a published standard"       Permitted.

(A) is `re.findall(r"/api/[\\w/]+", bundle)`. That is the shape-matching that RL1
exists to forbid: it asserts "this is an endpoint" because it resembles one. We
do not do it, anywhere, at any confidence level.

(B) is: the Fetch standard defines `fetch()`'s first argument as the request
resource. `XMLHttpRequest.open()`'s signature is `(method, url)`. axios documents
`axios.get(url)`. When a *literal* sits in one of those positions, the source is
not resembling a declaration — it IS one, in the same sense an OpenAPI `paths`
key is one. We read it and we record the file and line it was read from, so every
extracted fact is falsifiable by opening the file.

This is exactly the EIL's own epistemology one layer out: a law is true *by the
definition of its effect class*; a call-site meaning is true *by the definition of
the API being called*. Neither is learned. The allow-list of call sites is CLOSED
and enumerated below (`_CALL_SITES`), mirroring the closed sensitivity lexicon in
`intrinsic.py`, which the project already accepts as "a CLOSED vocabulary, never
learned".

WHAT A FRONTEND GUARD IS, AND WHAT IT IS NOT (D4 — this is the FP question)
---------------------------------------------------------------------------
`if (user.role === 'admin') { fetch('/api/admin/users') }` is NOT a vulnerability,
NOT evidence the server checks the role, and NOT evidence it doesn't. It is the
target BROADCASTING an intended policy. Under D4 the target's contract is a source
of "what this endpoint is", never of "what is forbidden" — and a bundle is a far
weaker source than an OpenAPI doc, because it describes the CLIENT's behaviour.

Therefore, by construction:

  * this module emits NO Candidate, NO Finding, NO verdict, and imports nothing
    from `eil`, `confirmer`, or `engine`;
  * a guard is a DECLARED-authority statement of the same family `broadcast.py`
    already models, and it becomes interesting only when Δstate CONTRADICTS it
    (`act_confront`). The finding still comes from the read-back. Always.
  * the FP surface added is therefore structurally zero: this module can only
    change WHAT gets tested, never WHETHER something is reported.

FIVE RED LINES — how each is held
----------------------------------
RL1  No induction. Every emitted fact is a literal at a standard-defined position,
     carried with `source_file:line`. Anything requiring evaluation of a variable,
     a base URL, or control flow is DROPPED and counted in `dropped_unresolvable`,
     never approximated. Low recall is accepted; a guess is not.
RL2  No model anywhere. A single-pass character lexer plus token-pattern matching.
RL3  Untouched: this module cannot promote anything. Confirmation stays in
     `confirmer.py`. A frontend "guard" never becomes a finding on its own.
RL4  Untouched: it emits no findings, so it owes no PoC.
RL5  Fail-safe to inaction, in four places: (a) unlexable source -> empty contract
     + an explicit unanalyzable record; (b) any unresolvable literal -> dropped;
     (c) an identifier matching two vocabularies at once -> BOTH suppressed;
     (d) JS assets are filtered through the real `ScopeGuard`, so an empty scope
     analyses nothing.

ADVERSARIAL INPUT (the bundle is attacker-controlled — treat it as hostile data)
--------------------------------------------------------------------------------
  * Minified / obfuscated: lexes fine, yields few or zero literals. That is a
    RECALL fact, reported in the counters. This module never labels code
    "minified" — that would be a judgment about what normal code looks like.
  * String-array obfuscation (`_0x1a[42]`): yields nothing. Correct.
  * DELIBERATELY MISLEADING bundle (a planted `/api/wipe-all`): mitigated
    structurally, not by trust — extracted endpoints ride `discovery.py`'s
    existing rails, where auto-probing is GET-only AND requires an id the CAPTURE
    observed for that template. A never-observed planted path therefore produces
    no probe at all, and `ScopeGuard` still gates every request.
  * ReDoS: NO regex is ever applied to unbounded input. Lexing is an O(n)
    character scan; the only regexes in the module run on already-bounded slices
    (<= `_MAX_EXPR_LEN`).
  * Resource exhaustion: hard byte/token/output caps, all fail-safe to "skip and
    report", never to a partial-but-unlabelled result. Zero network. No child
    process is ever spawned. `economy.py` is untouched because spend is exactly 0.

DETERMINISM
-----------
Same bytes in => same object out, always. Every collection that leaves this module
is sorted; no set iteration reaches the output; no wall-clock, no randomness, no
hashing of memory addresses.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# Budgets — every one fails safe to "skip this source and say so"              #
# --------------------------------------------------------------------------- #
_MAX_SOURCE_BYTES = 4_000_000        # per JS source
_MAX_TOTAL_BYTES = 32_000_000        # across a whole capture
_MAX_TOKENS = 1_500_000              # per source
_MAX_STRING_LEN = 2048               # a literal longer than this is not a URL
_MAX_EXPR_LEN = 200                  # bound for the ONLY regexes in this module
_MAX_CONCAT_OPERANDS = 8             # "/a/" + x + "/b" + y ...
_MAX_ENDPOINTS = 5000
_MAX_GUARDS = 2000
_MAX_OBJECT_KEYS = 500               # per extracted map (state machine / visibility)
_MAX_SCAN_SPAN = 400                 # token look-ahead cap for any single pattern
_MAX_GUARD_BODY_SPAN = 4000          # `if` body span considered for guard containment
_MAX_MAP_SPAN = 4000                 # span for a NAMED declared map (rare, anchored)

# Why a source produced nothing. All four are MEASURED facts, never judgments
# about what the code "looks like".
UNLEXABLE = "LEX_ERROR"              # the scan hit a malformed/unterminated form
OVER_BUDGET = "OVER_BUDGET"          # exceeded a hard cap above
EMPTY_SOURCE = "EMPTY"               # zero bytes
OUT_OF_SCOPE = "OUT_OF_SCOPE"        # ScopeGuard HALTed on the asset's host


# --------------------------------------------------------------------------- #
# CLOSED VOCABULARIES.                                                         #
# Each entry is a published API whose parameter positions are DEFINED, or a    #
# name enumerated here by hand. Nothing is learned, inferred, or extended at   #
# runtime. Adding an entry is a source-code change, reviewable as such.        #
# --------------------------------------------------------------------------- #

# call-site -> (arg index of the URL, arg index of the method or None,
#               method fixed by the standard or None)
# `fetch(resource, init)`      — Fetch Standard §5.4; method defaults to GET when
#                                no init.method is given. That default is part of
#                                the STANDARD, so reading it is derivation.
# `xhr.open(method, url)`      — XMLHttpRequest Standard §4.5.1.
# `navigator.sendBeacon(url)`  — Beacon API; the standard fixes the method to POST.
_CALL_SITES: dict[str, tuple[int, Optional[int], Optional[str]]] = {
    "fetch": (0, None, None),                 # method read from init, else GET
    "open": (1, 0, None),                     # XHR — only when receiver-qualified
    "sendBeacon": (0, None, "POST"),
    "axios": (0, None, None),                 # axios(url|config)
    "axios.get": (0, None, "GET"),
    "axios.post": (0, None, "POST"),
    "axios.put": (0, None, "PUT"),
    "axios.patch": (0, None, "PATCH"),
    "axios.delete": (0, None, "DELETE"),
    "axios.head": (0, None, "HEAD"),
    "axios.request": (0, None, None),
    "$.get": (0, None, "GET"),
    "$.post": (0, None, "POST"),
    "$.getJSON": (0, None, "GET"),
    "$.ajax": (0, None, None),                # config object
    "jQuery.ajax": (0, None, None),
    "superagent.get": (0, None, "GET"),
    "superagent.post": (0, None, "POST"),
    "request.get": (0, None, "GET"),
    "request.post": (0, None, "POST"),
    "got.get": (0, None, "GET"),
    "got.post": (0, None, "POST"),
    "ky.get": (0, None, "GET"),
    "ky.post": (0, None, "POST"),
}

# Config-object call sites: the URL/method live in an object literal, per each
# library's documented option names.
_CONFIG_URL_KEYS = ("url", "uri")
_CONFIG_METHOD_KEYS = ("method", "type")      # jQuery uses `type`, axios `method`

_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

# A property/identifier name that DECLARES a role. Tight on purpose: `scope`,
# `permission`, `tier` and friends are deliberately EXCLUDED — they are adjacent
# concepts, and widening this list would be the first step back toward "a word
# that feels privileged", which is the RL1 failure mode.
_ROLE_NAMES = frozenset({
    "role", "roles", "userrole", "userroles", "currentrole", "requiredrole",
    "requiredroles", "allowedroles", "rolename", "memberrole", "accountrole",
})

# Identifier names that DECLARE a state machine.
_STATE_MAP_NAMES = frozenset({
    "states", "statemachine", "statemachines", "transitions", "statetransitions",
    "allowedtransitions", "nextstates", "fsm", "workflow", "workflows",
})

# Identifier names that DECLARE per-role field visibility.
_VISIBILITY_MAP_NAMES = frozenset({
    "fieldvisibility", "visiblefields", "fieldpermissions", "fieldacl",
    "fieldaccess", "visibilitybyrole", "fieldsbyrole", "fieldroles",
})

# Route-config declarations: `{ path: "/admin", roles: ["admin"] }`.
_ROUTE_PATH_KEYS = frozenset({"path", "route"})

# Keywords after which a `/` begins a regex literal rather than a division.
_REGEX_PRECEDERS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await",
})

_PUNCT3 = ("===", "!==", "**=", "...", "<<=", ">>=", "&&=", "||=", "??=")
_PUNCT2 = ("==", "!=", "<=", ">=", "&&", "||", "??", "?.", "=>", "++", "--",
           "+=", "-=", "*=", "/=", "%=", "**", "<<", ">>", "|=", "&=", "^=")

# The ONLY regexes in this module. Both are applied exclusively to slices already
# bounded by _MAX_EXPR_LEN, so neither can be driven into pathological time.
_SIMPLE_REF = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$")
_PARAM_SEG = re.compile(r"^\{[^{}]*\}$")


def _norm_name(name: str) -> str:
    """Vocabulary lookup key: case-folded, separators removed. Purely mechanical."""
    return "".join(ch for ch in name.lower() if ch.isalnum())


def _vocab_match(name: str, vocab: frozenset) -> bool:
    """Exact match, or a vocabulary term as a SUFFIX (`ORDER_STATES` -> `states`).

    Real code names a map `ORDER_STATES`, not `states`, so exact-only matching had
    near-zero recall. Suffix matching is still a mechanical operation over a
    CLOSED, hand-enumerated list — nothing is learned and nothing is added at
    runtime — and it is the same shape as the substring checks `intrinsic.py`
    already performs against its closed sensitivity lexicon.

    The blast radius of a wrong match is deliberately tiny: a declared map is
    REPORTED data only. It reaches no law, no candidate and no confirmer, so an
    over-match costs a stray line in a report and can never cost a false finding.

    Short terms match exactly only, so `fsm` cannot swallow every name ending
    in those three letters.
    """
    n = _norm_name(name)
    if n in vocab:
        return True
    return any(len(term) >= 5 and n.endswith(term) and n != term for term in vocab)


# --------------------------------------------------------------------------- #
# The lexer — a single-pass character scan. No regex, no backtracking, O(n).   #
# --------------------------------------------------------------------------- #

class _LexError(Exception):
    """Raised on a malformed/unterminated form. Caller records UNLEXABLE and
    emits NOTHING for that source (RL5: a half-read bundle is not a contract)."""


@dataclass(frozen=True)
class _Tok:
    kind: str          # IDENT | STR | TPL | NUM | PUNCT | REGEX
    value: Any         # str, or for TPL a tuple of ("s", text) / ("e", raw)
    line: int
    oversized: bool = False   # STR longer than _MAX_STRING_LEN: never a URL


def _is_ident_start(c: str) -> bool:
    return c.isalpha() or c in "_$" or ord(c) > 127


def _is_ident_part(c: str) -> bool:
    return c.isalnum() or c in "_$" or ord(c) > 127


def _lex(src: str) -> list[_Tok]:
    """Tokenise JavaScript well enough to locate declaration sites, and no further.

    This is deliberately NOT a parser. It exists to make three things impossible:
    reading a path out of a comment, reading a path out of the middle of another
    string, and mistaking a regex body for code. Anything it cannot lex cleanly
    raises, and the whole source is then reported unanalyzable rather than
    partially trusted.
    """
    toks: list[_Tok] = []
    i, n, line = 0, len(src), 1
    prev: Optional[_Tok] = None

    while i < n:
        if len(toks) > _MAX_TOKENS:
            raise _LexError("token budget exceeded")
        c = src[i]

        # whitespace
        if c in " \t\r\v\f\u00a0\ufeff":
            i += 1
            continue
        if c == "\n":
            line += 1
            i += 1
            continue

        # comments
        if c == "/" and i + 1 < n:
            nxt = src[i + 1]
            if nxt == "/":
                j = src.find("\n", i)
                i = n if j < 0 else j
                continue
            if nxt == "*":
                j = src.find("*/", i + 2)
                if j < 0:
                    raise _LexError("unterminated block comment")
                line += src.count("\n", i, j)
                i = j + 2
                continue

        # regex literal vs division
        if c == "/":
            starts_regex = (
                prev is None
                or (prev.kind == "PUNCT" and prev.value not in (")", "]", "}", "++", "--"))
                or (prev.kind == "IDENT" and prev.value in _REGEX_PRECEDERS)
            )
            if starts_regex:
                j, in_class = i + 1, False
                while j < n:
                    ch = src[j]
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == "\n":
                        raise _LexError("unterminated regex literal")
                    if ch == "[":
                        in_class = True
                    elif ch == "]":
                        in_class = False
                    elif ch == "/" and not in_class:
                        break
                    j += 1
                if j >= n:
                    raise _LexError("unterminated regex literal")
                j += 1
                while j < n and _is_ident_part(src[j]):    # flags
                    j += 1
                prev = _Tok("REGEX", src[i:j], line)
                toks.append(prev)
                i = j
                continue

        # string literals
        if c in "'\"":
            val, i, line = _scan_string(src, i, line, c)
            over = len(val) > _MAX_STRING_LEN
            prev = _Tok("STR", "" if over else val, line, oversized=over)
            toks.append(prev)
            continue

        # template literals
        if c == "`":
            parts, i, line = _scan_template(src, i, line)
            prev = _Tok("TPL", tuple(parts), line)
            toks.append(prev)
            continue

        # numbers
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            j = i
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            prev = _Tok("NUM", src[i:j], line)
            toks.append(prev)
            i = j
            continue

        # identifiers
        if _is_ident_start(c):
            j = i
            while j < n and _is_ident_part(src[j]):
                j += 1
            prev = _Tok("IDENT", src[i:j], line)
            toks.append(prev)
            i = j
            continue

        # punctuators, longest match first
        three, two = src[i:i + 3], src[i:i + 2]
        if three in _PUNCT3:
            prev = _Tok("PUNCT", three, line); toks.append(prev); i += 3; continue
        if two in _PUNCT2:
            prev = _Tok("PUNCT", two, line); toks.append(prev); i += 2; continue
        prev = _Tok("PUNCT", c, line)
        toks.append(prev)
        i += 1

    return toks


def _scan_string(src: str, i: int, line: int, quote: str) -> tuple[str, int, int]:
    out: list[str] = []
    n = len(src)
    j = i + 1
    while j < n:
        ch = src[j]
        if ch == "\\":
            if j + 1 >= n:
                raise _LexError("unterminated string escape")
            esc = src[j + 1]
            if esc == "\n":
                line += 1
                j += 2
                continue
            out.append(_UNESCAPE.get(esc, esc))
            j += 2
            continue
        if ch == quote:
            return "".join(out), j + 1, line
        if ch == "\n":
            raise _LexError("unterminated string literal")
        out.append(ch)
        j += 1
    raise _LexError("unterminated string literal")


_UNESCAPE = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
             "0": "\0", "\\": "\\", "'": "'", '"': '"', "`": "`"}


def _scan_template(src: str, i: int, line: int) -> tuple[list[tuple[str, str]], int, int]:
    """Return the template's alternating static chunks and substitution sources.

    A substitution's SOURCE TEXT is captured verbatim; it is never evaluated.
    Nested templates and nested braces inside `${...}` are tracked so the scan
    cannot desynchronise.
    """
    parts: list[tuple[str, str]] = []
    buf: list[str] = []
    n = len(src)
    j = i + 1
    while j < n:
        ch = src[j]
        if ch == "\\":
            if j + 1 >= n:
                raise _LexError("unterminated template escape")
            buf.append(_UNESCAPE.get(src[j + 1], src[j + 1]))
            j += 2
            continue
        if ch == "`":
            parts.append(("s", "".join(buf)))
            return parts, j + 1, line
        if ch == "$" and j + 1 < n and src[j + 1] == "{":
            parts.append(("s", "".join(buf)))
            buf = []
            depth, k = 1, j + 2
            while k < n and depth:
                cc = src[k]
                if cc == "{":
                    depth += 1
                elif cc == "}":
                    depth -= 1
                elif cc == "\n":
                    line += 1
                elif cc in "'\"":
                    _, k, line = _scan_string(src, k, line, cc)
                    continue
                elif cc == "`":
                    _, k, line = _scan_template(src, k, line)
                    continue
                k += 1
            if depth:
                raise _LexError("unterminated template substitution")
            parts.append(("e", src[j + 2:k - 1]))
            j = k
            continue
        if ch == "\n":
            line += 1
        buf.append(ch)
        j += 1
    raise _LexError("unterminated template literal")


# --------------------------------------------------------------------------- #
# Static string-expression folding.                                            #
# This is CONSTANT FOLDING OF LITERALS — a syntactic rewrite — not evaluation. #
# It returns None the instant anything is not literally written down.          #
# --------------------------------------------------------------------------- #

def _param_name(expr: str) -> str:
    """Transcribe a substitution into a path parameter name.

    `${id}` -> `{id}`, `${order.id}` -> `{id}` (the written last segment).
    Anything else -> `{expr}`: honest for "a value goes here, computed elsewhere".
    Never invents a name that is not present in the source.
    """
    e = expr.strip()
    if len(e) > _MAX_EXPR_LEN:
        return "{expr}"
    if _SIMPLE_REF.match(e):
        return "{" + e.split(".")[-1] + "}"
    return "{expr}"


def _fold(toks: list[_Tok], i: int, stop: tuple[str, ...] = (",", ")")) -> Optional[tuple[str, list[str], int]]:
    """Fold `STR`, a static/parameterised `TPL`, and `+` chains of them into a
    single path template. Returns (template, params, next_index) or None.

    None is returned — and the site DROPPED — whenever any operand is not a
    literal or a bare reference. There is no partial credit and no best guess.
    """
    text: list[str] = []
    params: list[str] = []
    operands = 0
    j = i
    n = len(toks)
    while j < n:
        if operands >= _MAX_CONCAT_OPERANDS:
            return None
        t = toks[j]
        if t.kind == "STR":
            if t.oversized:
                return None
            text.append(t.value)
        elif t.kind == "TPL":
            for kind, val in t.value:
                if kind == "s":
                    text.append(val)
                else:
                    p = _param_name(val)
                    text.append(p)
                    params.append(p.strip("{}"))
        elif t.kind == "IDENT" and operands > 0:
            # a bare reference operand in a `+` chain: its VALUE is unknown, its
            # POSITION in the template is written down. Transcribe the position.
            ref = [t.value]
            j += 1
            while (j + 1 < n and toks[j].kind == "PUNCT" and toks[j].value == "."
                   and toks[j + 1].kind == "IDENT"):
                ref.append(toks[j + 1].value)
                j += 2
            p = _param_name(".".join(ref))
            text.append(p)
            params.append(p.strip("{}"))
            operands += 1
            if j < n and toks[j].kind == "PUNCT" and toks[j].value == "+":
                j += 1
                continue
            if j < n and toks[j].kind == "PUNCT" and toks[j].value in stop:
                return ("".join(text), params, j)
            return None
        else:
            return None

        operands += 1
        j += 1
        if j < n and toks[j].kind == "PUNCT" and toks[j].value == "+":
            j += 1
            continue
        if j < n and toks[j].kind == "PUNCT" and toks[j].value in stop:
            return ("".join(text), params, j)
        if j >= n:
            return None
        return None
    return None


# --------------------------------------------------------------------------- #
# Object-literal reading (config objects, route configs, declared maps)        #
# --------------------------------------------------------------------------- #

def _read_object(toks: list[_Tok], i: int,
                 max_span: int = _MAX_SCAN_SPAN) -> tuple[dict[str, tuple[str, Any]], int]:
    """Read `{ k: v, ... }` starting at `toks[i] == "{"`.

    Only literal keys with literal values are recorded, as ("str", s) or
    ("arr", [s, ...]). Every other value is recorded as ("other", None) so the
    key's PRESENCE is known while its value is honestly unknown. Returns
    (props, index_after_close). Depth-tracked, so nesting cannot desynchronise it.

    `max_span` bounds the scan. Without it, running this at every `{` in a large
    minified bundle is O(n^2) — a self-inflicted denial of service on hostile
    input, which is exactly the failure mode this module is supposed to survive.
    """
    props: dict[str, tuple[str, Any]] = {}
    n = min(len(toks), i + max_span)
    if i >= len(toks) or toks[i].value != "{":
        return props, i
    j = i + 1
    depth = 1
    while j < n and depth:
        t = toks[j]
        if t.kind == "PUNCT" and t.value in "{[(":
            depth += 1
            j += 1
            continue
        if t.kind == "PUNCT" and t.value in "}])":
            depth -= 1
            j += 1
            continue
        if depth != 1:
            j += 1
            continue
        # key : value, at the object's own depth
        if t.kind in ("IDENT", "STR") and j + 1 < n and toks[j + 1].value == ":":
            key = t.value
            if len(props) >= _MAX_OBJECT_KEYS:
                return props, _skip_balanced(toks, i)
            v = j + 2
            if v < n and toks[v].kind == "STR" and not toks[v].oversized:
                props[key] = ("str", toks[v].value)
                j = v + 1
                continue
            if v < n and toks[v].kind == "TPL" and all(k == "s" for k, _ in toks[v].value):
                props[key] = ("str", "".join(val for _, val in toks[v].value))
                j = v + 1
                continue
            if v < n and toks[v].kind == "PUNCT" and toks[v].value == "[":
                arr, after = _read_string_array(toks, v)
                if arr is not None:
                    props[key] = ("arr", arr)
                    j = after
                    continue
                props[key] = ("other", None)
                j = v
                continue
            props[key] = ("other", None)
            j = v
            continue
        j += 1
    return props, j


def _read_string_array(toks: list[_Tok], i: int) -> tuple[Optional[list[str]], int]:
    """Read `[ "a", "b" ]` — string literals ONLY. Any other element => None."""
    n = len(toks)
    if i >= n or toks[i].value != "[":
        return None, i
    out: list[str] = []
    j = i + 1
    while j < n:
        t = toks[j]
        if t.kind == "PUNCT" and t.value == "]":
            return out, j + 1
        if t.kind == "STR" and not t.oversized:
            out.append(t.value)
            j += 1
        elif t.kind == "TPL" and all(k == "s" for k, _ in t.value):
            out.append("".join(v for _, v in t.value))
            j += 1
        elif t.kind == "PUNCT" and t.value == ",":
            j += 1
        else:
            return None, j
        if len(out) > _MAX_OBJECT_KEYS:
            return None, j
    return None, j


def _skip_balanced(toks: list[_Tok], i: int, limit: int = 0) -> int:
    """Index just past the bracket group opened at i. Total; never raises.
    `limit` bounds the scan so per-token use stays linear overall."""
    n = len(toks) if limit <= 0 else min(len(toks), i + limit)
    if i >= len(toks):
        return len(toks)
    opens, closes = "{[(", "}])"
    if toks[i].kind != "PUNCT" or toks[i].value not in opens:
        return i + 1
    depth, j = 0, i
    while j < n:
        t = toks[j]
        if t.kind == "PUNCT" and t.value in opens:
            depth += 1
        elif t.kind == "PUNCT" and t.value in closes:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return n


# --------------------------------------------------------------------------- #
# The extracted contract — pure data, no verdicts                              #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class EndpointDecl:
    """One request the bundle declares it can issue. `found_in` makes it
    falsifiable: open that file at that line and the literal is there."""
    method: str                 # or "UNKNOWN" when the standard does not fix it
    path: str                   # absolute path, params as `{name}`
    source: str                 # e.g. "js_fetch_call"
    found_in: str               # "bundle.js:1423"
    params: tuple[str, ...] = ()
    host: str = ""              # non-empty only for absolute-URL literals
    out_of_scope: bool = False  # absolute URL to a host outside the declared scope

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"


@dataclass(frozen=True)
class GuardDecl:
    """A CLIENT-SIDE claim about required authority. Never a finding, never a
    candidate. `kind` separates an API call gated in the client (`api_call`) from
    a UI route declaration (`ui_route`) — conflating those two is a classic
    false-positive source, so they are kept apart at the type level."""
    target: str                 # endpoint key, or the UI route path
    required_role: str
    source: str                 # "js_conditional" | "js_route_config"
    found_in: str
    kind: str = "api_call"      # "api_call" | "ui_route"


@dataclass
class SourceReport:
    """Per-source, measured. Note `reason` is only ever one of the four constants
    at the top of this file — all measurements, never a judgment about the code."""
    name: str
    bytes: int = 0
    tokens: int = 0
    string_literals: int = 0
    call_sites: int = 0
    dropped_unresolvable: int = 0
    analyzed: bool = False
    reason: str = ""


@dataclass
class FrontendContract:
    endpoints: list = field(default_factory=list)
    roles: list = field(default_factory=list)
    guards: list = field(default_factory=list)
    state_machines: dict = field(default_factory=dict)
    field_visibility: dict = field(default_factory=dict)
    sources: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def analyzable(self) -> bool:
        return any(s.analyzed for s in self.sources)

    def to_dict(self) -> dict:
        """Deterministic, JSON-serialisable. Every collection sorted."""
        return {
            "endpoints": [
                {"method": e.method, "path": e.path, "source": e.source,
                 "found_in": e.found_in,
                 **({"params": list(e.params)} if e.params else {}),
                 **({"host": e.host} if e.host else {}),
                 **({"out_of_scope": True} if e.out_of_scope else {})}
                for e in self.endpoints
            ],
            "roles": list(self.roles),
            "guards": [
                {"target": g.target, "required_role": g.required_role,
                 "kind": g.kind, "source": g.source, "found_in": g.found_in}
                for g in self.guards
            ],
            "state_machines": {k: {kk: list(vv) for kk, vv in sorted(v.items())}
                               for k, v in sorted(self.state_machines.items())},
            "field_visibility": {k: list(v) for k, v in sorted(self.field_visibility.items())},
            "analysis": {
                "analyzable": self.analyzable,
                "sources": [
                    {"name": s.name, "analyzed": s.analyzed, "reason": s.reason,
                     "bytes": s.bytes, "tokens": s.tokens,
                     "string_literals": s.string_literals,
                     "call_sites": s.call_sites,
                     "dropped_unresolvable": s.dropped_unresolvable}
                    for s in self.sources
                ],
                "unanalyzable": [
                    {"name": s.name, "reason": s.reason}
                    for s in self.sources if not s.analyzed
                ],
            },
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# URL literal -> (host, path) or None. Definitional, and it can only DROP.     #
# --------------------------------------------------------------------------- #

def _resolve_path(literal: str) -> Optional[tuple[str, str]]:
    """The Fetch/XHR standards require this argument to be a valid URL. A literal
    that is not one is therefore not a resource declaration — dropped.

    A BASE-RELATIVE literal (`"users/1"`) is also dropped: resolving it needs the
    document's base URL, which is a runtime value. Guessing a base would be
    exactly the inference RL1 forbids. This costs recall on some bundles; that
    cost is reported in `dropped_unresolvable` rather than papered over.
    """
    if not literal or len(literal) > _MAX_STRING_LEN:
        return None
    lit = literal.strip()
    if not lit:
        return None
    if lit.startswith("//"):                    # protocol-relative: host unknown scheme
        try:
            u = urlparse("https:" + lit)
        except ValueError:
            return None
        return (u.netloc, u.path or "/") if u.netloc else None
    if lit.startswith("/"):
        try:
            u = urlparse(lit)
        except ValueError:
            return None
        return ("", u.path or "/")
    if "://" in lit[:12]:
        try:
            u = urlparse(lit)
        except ValueError:
            return None
        if u.scheme in ("http", "https") and u.netloc:
            return (u.netloc, u.path or "/")
        return None
    return None                                  # base-relative -> unresolvable


def _normalise_template(path: str) -> str:
    """Normalise a declared path into the engine's OWN `endpoint_key()` form.

    Declared parameters are first substituted with a concrete id-shaped segment,
    then the engine's normaliser is applied. This matters: a bundle may write the
    path either as `/api/orders/${id}` or as a hard-coded `/api/orders/1`, and
    both must land on the engine's `/api/orders/{id}` or the undeclared-endpoint
    diff produces phantom "new" endpoints that were observed all along.

    Reusing `HTTPRequest.endpoint_key()` rather than re-implementing it is the
    point — a second normaliser would drift from the first, and the drift would
    show up as false novelty.
    """
    from .models import HTTPRequest
    segs = ["1" if _PARAM_SEG.match(s) else s for s in path.split("/")]
    probe = "/".join(segs) or "/"
    try:
        key = HTTPRequest("GET", probe).endpoint_key()
        return key.split(" ", 1)[1] if " " in key else probe
    except Exception:                                    # noqa: BLE001
        return probe


# --------------------------------------------------------------------------- #
# Extraction passes                                                            #
# --------------------------------------------------------------------------- #

def _callee_name(toks: list[_Tok], i: int) -> tuple[Optional[str], bool]:
    """Name of the callee whose `(` is at index i, plus whether it was
    receiver-qualified (`x.open(` vs bare `open(`). Reads at most two segments —
    enough for the closed call-site table, and no more."""
    if i == 0 or toks[i].value != "(":
        return None, False
    if toks[i - 1].kind != "IDENT":
        return None, False
    name = toks[i - 1].value
    qualified = False
    if i >= 3 and toks[i - 2].value == "." and toks[i - 3].kind == "IDENT":
        qualified = True
        return f"{toks[i - 3].value}.{name}", True
    return name, qualified


def _extract_calls(toks: list[_Tok], src_name: str,
                   rep: SourceReport) -> list[tuple[int, EndpointDecl]]:
    """Return (call_site_token_index, EndpointDecl) pairs.

    The index is carried out with the declaration so guard-containment is decided
    by real token positions rather than by re-deriving the association later —
    a re-derivation would be a second, silently-diverging source of truth.
    """
    out: list[tuple[int, EndpointDecl]] = []
    n = len(toks)
    for i in range(n):
        if len(out) >= _MAX_ENDPOINTS:
            break
        t = toks[i]
        if t.kind != "PUNCT" or t.value != "(":
            continue
        qualified_name, qualified = _callee_name(toks, i)
        if qualified_name is None:
            continue

        bare = qualified_name.split(".")[-1]
        spec = _CALL_SITES.get(qualified_name)
        if spec is None and qualified:
            # `this.axios.get(...)` / `window.fetch(...)`: the receiver differs but
            # the API being called is the standard one. Only the CLOSED table's own
            # names qualify — `foo.get(...)` never does.
            spec = _CALL_SITES.get(bare)
        if spec is None:
            continue
        # `open(` is the XHR API only when receiver-qualified (`xhr.open(...)`).
        # A bare `open(` is `window.open` — a navigation, not a request. Dropped.
        if bare == "open" and not qualified:
            continue

        rep.call_sites += 1
        url_idx, method_idx, fixed_method = spec
        decl = _read_call(toks, i, url_idx, method_idx, fixed_method,
                          qualified_name, src_name, rep)
        if decl is not None:
            out.append((i, decl))
        else:
            rep.dropped_unresolvable += 1
    return out


def _read_call(toks: list[_Tok], lparen: int, url_idx: int, method_idx: Optional[int],
               fixed_method: Optional[str], callee: str, src_name: str,
               rep: SourceReport) -> Optional[EndpointDecl]:
    n = len(toks)
    args_start = lparen + 1
    if args_start >= n:
        return None
    line = toks[args_start].line

    # config-object form: fetch({url: ...}) / $.ajax({url, type}) / axios({...})
    if toks[args_start].kind == "PUNCT" and toks[args_start].value == "{":
        props, _ = _read_object(toks, args_start)
        url_val = None
        for k in _CONFIG_URL_KEYS:
            v = props.get(k)
            if v and v[0] == "str":
                url_val = v[1]
                break
        if url_val is None:
            return None
        method = fixed_method
        for k in _CONFIG_METHOD_KEYS:
            v = props.get(k)
            if v and v[0] == "str" and v[1].upper() in _HTTP_METHODS:
                method = v[1].upper()
                break
        resolved = _resolve_path(url_val)
        if resolved is None:
            return None
        host, path = resolved
        return EndpointDecl(method or "UNKNOWN", path, f"js_{_site_tag(callee)}_config",
                            f"{src_name}:{line}", (), host)

    # positional form
    args = _split_args(toks, lparen)
    if args is None or url_idx >= len(args):
        return None

    method = fixed_method
    if method_idx is not None and method_idx < len(args):
        mstart = args[method_idx]
        mt = toks[mstart]
        if mt.kind == "STR" and mt.value.upper() in _HTTP_METHODS:
            method = mt.value.upper()
        else:
            return None                     # XHR method not literal -> drop

    folded = _fold(toks, args[url_idx])
    if folded is None:
        return None
    template, params, _ = folded
    resolved = _resolve_path(template)
    if resolved is None:
        return None
    host, path = resolved

    # fetch(resource, init): the Fetch Standard fixes the default method to GET
    # when no init.method is supplied. Read init.method when literal; when an init
    # object exists but its method is not literal, the method is UNKNOWN — we do
    # not fall back to GET, because that would be a guess about runtime behaviour.
    if callee.split(".")[-1] == "fetch":
        if len(args) == 1:
            method = "GET"
        else:
            init = args[1]
            if toks[init].kind == "PUNCT" and toks[init].value == "{":
                props, _ = _read_object(toks, init)
                mv = props.get("method")
                if mv is None:
                    method = "GET"
                elif mv[0] == "str" and mv[1].upper() in _HTTP_METHODS:
                    method = mv[1].upper()
                else:
                    method = "UNKNOWN"
            else:
                method = "UNKNOWN"

    return EndpointDecl(method or "UNKNOWN", path, f"js_{_site_tag(callee)}_call",
                        f"{src_name}:{line}", tuple(params), host)


def _site_tag(callee: str) -> str:
    """Stable provenance tag: `fetch` -> `fetch`, `$.ajax` -> `jquery_ajax`."""
    return callee.replace("$", "jquery").replace(".", "_").lower()


def _split_args(toks: list[_Tok], lparen: int) -> Optional[list[int]]:
    """Token indices where each top-level argument begins. Bounded look-ahead."""
    n = len(toks)
    starts = [lparen + 1]
    depth, j = 1, lparen + 1
    limit = min(n, lparen + _MAX_SCAN_SPAN)
    while j < limit:
        t = toks[j]
        if t.kind == "PUNCT":
            if t.value in "{[(":
                depth += 1
            elif t.value in "}])":
                depth -= 1
                if depth == 0:
                    return starts
            elif t.value == "," and depth == 1:
                starts.append(j + 1)
        j += 1
    return None


def _member_head(toks: list[_Tok], i: int) -> int:
    """Index of the head of the member expression ending at i.

    `u.role` reached at `role` has its head at `u`, so a comparison written the
    other way round (`"editor" === u.role`) is still found. Without this the
    extractor silently sees only one of the two orders — an invisible recall hole
    rather than a visible one, which is the worse kind.
    """
    j = i
    while j >= 2 and toks[j - 1].kind == "PUNCT" and toks[j - 1].value == "." \
            and toks[j - 2].kind == "IDENT":
        j -= 2
    return j


def _is_role_ref(toks: list[_Tok], i: int) -> bool:
    """True iff toks[i] is an identifier in the CLOSED role vocabulary. Used only
    as the anchor of a literal comparison; it never stands alone as evidence."""
    return toks[i].kind == "IDENT" and _norm_name(toks[i].value) in _ROLE_NAMES


def _extract_roles(toks: list[_Tok]) -> list[str]:
    """Role names literally written next to a role-declaring identifier.

    Two shapes only: `<roleName> <==|===|!=|!==> "literal"` (either order), and
    `<roleName> = [ "a", "b" ]`. Everything else is ignored.
    """
    roles: set[str] = set()
    n = len(toks)
    for i in range(n):
        if not _is_role_ref(toks, i):
            continue
        # comparison, role on the left
        if i + 2 < n and toks[i + 1].kind == "PUNCT" and toks[i + 1].value in ("==", "===", "!=", "!=="):
            t = toks[i + 2]
            if t.kind == "STR" and t.value and not t.oversized:
                roles.add(t.value)
        # comparison, role on the right (behind any member chain)
        h = _member_head(toks, i)
        if h >= 2 and toks[h - 1].kind == "PUNCT" and toks[h - 1].value in ("==", "===", "!=", "!==") \
                and toks[h - 2].kind == "STR" and toks[h - 2].value and not toks[h - 2].oversized:
            roles.add(toks[h - 2].value)
        # array assignment / property value
        if i + 2 < n and toks[i + 1].kind == "PUNCT" and toks[i + 1].value in ("=", ":") \
                and toks[i + 2].kind == "PUNCT" and toks[i + 2].value == "[":
            arr, _ = _read_string_array(toks, i + 2)
            for v in arr or []:
                if v:
                    roles.add(v)
        # `roles.includes("admin")` / `roles.indexOf("admin")`
        if i + 4 < n and toks[i + 1].value == "." and toks[i + 2].kind == "IDENT" \
                and toks[i + 2].value in ("includes", "indexOf", "has", "contains") \
                and toks[i + 3].value == "(" and toks[i + 4].kind == "STR" \
                and toks[i + 4].value and not toks[i + 4].oversized:
            roles.add(toks[i + 4].value)
    return sorted(roles)


def _condition_role(toks: list[_Tok], start: int, end: int) -> Optional[str]:
    """The single role literal a condition tests for, or None.

    Deliberately returns None when a condition mentions MORE THAN ONE role: a
    compound condition is a policy we would have to interpret, and interpreting
    is the thing we do not do (RL5 -> abstain).
    """
    found: set[str] = set()
    for i in range(start, end):
        if not _is_role_ref(toks, i):
            continue
        if i + 2 < end and toks[i + 1].value in ("==", "===") and toks[i + 2].kind == "STR" \
                and toks[i + 2].value:
            found.add(toks[i + 2].value)
        h = _member_head(toks, i)
        if h >= start + 2 and toks[h - 1].value in ("==", "===") and toks[h - 2].kind == "STR" \
                and toks[h - 2].value:
            found.add(toks[h - 2].value)
        if i + 4 < end and toks[i + 1].value == "." and toks[i + 2].kind == "IDENT" \
                and toks[i + 2].value in ("includes", "has", "contains") \
                and toks[i + 3].value == "(" and toks[i + 4].kind == "STR" \
                and toks[i + 4].value:
            found.add(toks[i + 4].value)
    return next(iter(found)) if len(found) == 1 else None


def _extract_conditional_guards(toks: list[_Tok], src_name: str,
                                calls_by_index: dict[int, EndpointDecl]) -> list[GuardDecl]:
    """Link a role test to a request ONLY by syntactic containment:
    `if (<single role literal>) { ... <request call> ... }`.

    There is NO control-flow analysis and NO data-flow analysis here. A request
    outside the braces is never attributed to the guard, even if a human would
    say it obviously belongs. Under-linking is the correct failure direction: a
    missing guard costs recall, an invented one would be a claim about the
    server's policy that we cannot support.
    """
    out: list[GuardDecl] = []
    n = len(toks)
    for i in range(n):
        if len(out) >= _MAX_GUARDS:
            break
        t = toks[i]
        if t.kind != "IDENT" or t.value != "if":
            continue
        if i + 1 >= n or toks[i + 1].value != "(":
            continue
        cond_end = _skip_balanced(toks, i + 1, _MAX_SCAN_SPAN)
        role = _condition_role(toks, i + 2, cond_end - 1)
        if role is None:
            continue
        if cond_end >= n or toks[cond_end].value != "{":
            continue                       # brace-less `if` -> abstain
        body_end = _skip_balanced(toks, cond_end, _MAX_GUARD_BODY_SPAN)
        for idx in range(cond_end, body_end):
            decl = calls_by_index.get(idx)
            if decl is None:
                continue
            out.append(GuardDecl(decl.key, role, "js_conditional",
                                 f"{src_name}:{toks[i].line}", "api_call"))
    return out


def _extract_route_guards(toks: list[_Tok], src_name: str) -> list[GuardDecl]:
    """Route-config declarations: `{ path: "/admin", roles: ["admin"] }`.

    These are UI ROUTES, not API endpoints — a router path and a server path are
    different namespaces, and treating them as one is a well-known way to invent
    endpoints that do not exist. They are therefore emitted as guards with
    kind="ui_route" and are NEVER added to `endpoints`.
    """
    out: list[GuardDecl] = []
    n = len(toks)
    for i in range(n):
        if len(out) >= _MAX_GUARDS:
            break
        if toks[i].kind != "PUNCT" or toks[i].value != "{":
            continue
        props, _ = _read_object(toks, i)
        if not props:
            continue
        path_val = None
        for k, v in props.items():
            if _norm_name(k) in _ROUTE_PATH_KEYS and v[0] == "str" and v[1].startswith("/"):
                path_val = v[1]
                break
        if path_val is None:
            continue
        roles: list[str] = []
        for k, v in props.items():
            if _norm_name(k) not in _ROLE_NAMES:
                continue
            if v[0] == "str" and v[1]:
                roles.append(v[1])
            elif v[0] == "arr":
                roles.extend(x for x in v[1] if x)
        for r in sorted(set(roles)):
            out.append(GuardDecl(path_val, r, "js_route_config",
                                 f"{src_name}:{toks[i].line}", "ui_route"))
    return out


def _extract_declared_maps(toks: list[_Tok]) -> tuple[dict, dict, list[str]]:
    """Extract state machines and field-visibility maps, by DECLARED NAME only.

    The two have an identical shape (`{key: [strings]}`), so they are told apart
    by the name the author gave them — never by inspecting the values, which
    would be exactly the "this looks like a state" inference we refuse. An
    identifier that matches BOTH vocabularies yields NEITHER, and says so.
    """
    states: dict[str, dict[str, list[str]]] = {}
    visibility: dict[str, list[str]] = {}
    notes: list[str] = []
    n = len(toks)
    for i in range(n):
        if toks[i].kind != "IDENT":
            continue
        is_state = _vocab_match(toks[i].value, _STATE_MAP_NAMES)
        is_vis = _vocab_match(toks[i].value, _VISIBILITY_MAP_NAMES)
        if not (is_state or is_vis):
            continue
        if is_state and is_vis:
            notes.append(f"identifier '{toks[i].value}' matches two declared "
                         f"vocabularies at once — both suppressed (fail-safe)")
            continue
        if i + 2 >= n or toks[i + 1].value not in ("=", ":") or toks[i + 2].value != "{":
            continue
        props, _ = _read_object(toks, i + 2, _MAX_MAP_SPAN)
        clean = {k: sorted(v[1]) for k, v in props.items() if v[0] == "arr"}
        if not clean or len(clean) != len(props):
            continue                       # any non-literal member -> take none
        if is_state:
            states[toks[i].value] = clean
        else:
            for fname, roles in clean.items():
                visibility[fname] = sorted(set(visibility.get(fname, []) + roles))
    return states, visibility, notes


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class JSSource:
    """One JavaScript asset. `name` is what appears in `found_in`, so it must be
    stable across runs for determinism (a URL path, not a temp filename)."""
    name: str
    text: str
    host: str = ""


def extract(sources: list, allowed_hosts: Optional[list] = None) -> FrontendContract:
    """Extract a frontend contract from JS sources. No I/O, no execution.

    `allowed_hosts` (when given) marks absolute-URL endpoints pointing elsewhere
    as `out_of_scope=True`; they are retained for the operator's visibility but
    excluded from `to_endpoints()`, so nothing out of scope can ever be probed.
    """
    import fnmatch

    fc = FrontendContract()
    all_roles: set[str] = set()
    total_bytes = 0
    seen_names: set[str] = set()

    for s in sorted(sources, key=lambda x: (x.name, x.host)):
        name = s.name
        if name in seen_names:                # stable, unique `found_in` labels
            k = 2
            while f"{name}#{k}" in seen_names:
                k += 1
            name = f"{name}#{k}"
        seen_names.add(name)

        rep = SourceReport(name=name, bytes=len(s.text or ""))
        fc.sources.append(rep)

        if not s.text:
            rep.reason = EMPTY_SOURCE
            continue
        if rep.bytes > _MAX_SOURCE_BYTES or total_bytes + rep.bytes > _MAX_TOTAL_BYTES:
            rep.reason = OVER_BUDGET
            continue
        total_bytes += rep.bytes

        try:
            toks = _lex(s.text)
        except _LexError:
            # RL5: a source we cannot read cleanly contributes NOTHING. We never
            # keep the tokens we managed to get — a half-read bundle is not a
            # contract, and reporting it as one would be the exact over-claim
            # this project exists to refuse.
            rep.reason = UNLEXABLE
            continue
        except RecursionError:
            rep.reason = UNLEXABLE
            continue

        rep.tokens = len(toks)
        rep.string_literals = sum(1 for t in toks if t.kind in ("STR", "TPL"))
        rep.analyzed = True

        pairs = _extract_calls(toks, name, rep)
        by_index: dict[int, EndpointDecl] = dict(pairs)

        for _idx, d in pairs:
            if d.host and allowed_hosts is not None:
                h = d.host.lower()
                if not any(fnmatch.fnmatch(h, p.lower()) for p in allowed_hosts):
                    d = EndpointDecl(d.method, d.path, d.source, d.found_in,
                                     d.params, d.host, True)
            fc.endpoints.append(d)

        all_roles.update(_extract_roles(toks))
        fc.guards.extend(_extract_conditional_guards(toks, name, by_index))
        fc.guards.extend(_extract_route_guards(toks, name))

        st, vis, notes = _extract_declared_maps(toks)
        for k, v in st.items():
            fc.state_machines[k] = v
        for k, v in vis.items():
            fc.field_visibility[k] = sorted(set(fc.field_visibility.get(k, []) + v))
        fc.notes.extend(notes)

    fc.roles = sorted(all_roles)
    fc.endpoints = sorted(set(fc.endpoints), key=lambda e: (e.method, e.path, e.found_in))
    fc.guards = sorted(set(fc.guards), key=lambda g: (g.kind, g.target, g.required_role, g.found_in))
    fc.notes = sorted(set(fc.notes))
    if not fc.analyzable and fc.sources:
        fc.notes.append("no source was analyzable — empty contract emitted "
                        "(fail-safe); absence of endpoints is NOT evidence of absence")
        fc.notes = sorted(set(fc.notes))
    return fc


# --------------------------------------------------------------------------- #
# HAR bridge (integration with harimport + scope_guard)                        #
# --------------------------------------------------------------------------- #

_JS_MIMES = ("javascript", "ecmascript", "text/jsx", "application/x-javascript")


def js_sources_from_har(har: dict, scope=None, in_scope_hosts: Optional[list] = None,
                        excluded: Optional[list] = None) -> list:
    """Collect JS assets already present in a HAR. Reads captured bytes only —
    no network, ever (an absent response body is simply skipped, never fetched).

    When `scope` is a ScopeConfig, each asset is put through the REAL
    `ScopeGuard.check`, so an empty allow-list analyses nothing — the same
    fail-safe every other component inherits, not a private re-implementation.
    """
    from .models import HTTPRequest
    out: list[JSSource] = []
    entries = (har.get("log") or {}).get("entries") or []

    guard = None
    if scope is not None:
        from .scope_guard import ScopeGuard
        guard = ScopeGuard(scope)

    for e in entries:
        req = (e or {}).get("request") or {}
        url = req.get("url") or ""
        u = urlparse(url)
        host = u.netloc.split("@")[-1]
        resp = (e or {}).get("response") or {}
        content = resp.get("content") or {}
        mime = (content.get("mimeType") or "").lower()
        path = u.path or "/"
        is_js = any(m in mime for m in _JS_MIMES) or path.endswith((".js", ".mjs", ".cjs"))
        if not is_js:
            continue
        if in_scope_hosts and host not in set(in_scope_hosts):
            if excluded is not None:
                excluded.append(f"{host}{path}")
            continue
        if guard is not None:
            from .models import ScopeVerdict
            d = guard.check(HTTPRequest("GET", path, host=host))
            if d.verdict is not ScopeVerdict.ALLOW:
                # RL5 inherited, not re-implemented: an empty allow-list HALTs, so
                # an unconfigured scope analyses nothing at all.
                if excluded is not None:
                    excluded.append(f"{host}{path}")
                continue
        text = content.get("text")
        if not text:
            continue
        if (content.get("encoding") or "").lower() == "base64":
            import base64
            try:
                text = base64.b64decode(text).decode("utf-8", "replace")
            except Exception:
                continue
        out.append(JSSource(name=path, text=text, host=host))
    return out


def from_har(har: dict, scope=None, in_scope_hosts: Optional[list] = None) -> FrontendContract:
    """HAR -> FrontendContract. Zero network, zero execution, zero budget spend."""
    allowed = None
    if scope is not None and getattr(scope, "allowed_hosts", None):
        allowed = list(scope.allowed_hosts)
    elif in_scope_hosts:
        allowed = list(in_scope_hosts)
    excluded: list = []
    sources = js_sources_from_har(har, scope, in_scope_hosts, excluded)
    fc = extract(sources, allowed_hosts=allowed)
    if excluded:
        # Silence would be the dangerous outcome: an operator seeing an empty
        # contract must be able to tell "the bundle declared nothing" apart from
        # "scope excluded every bundle".
        fc.notes.append(f"{len(excluded)} JS asset(s) excluded by scope: "
                        + ", ".join(sorted(excluded)[:10]))
        fc.notes = sorted(set(fc.notes))
    return fc


# --------------------------------------------------------------------------- #
# Adapters into the EXISTING machinery (no new classification logic anywhere)  #
# --------------------------------------------------------------------------- #

def to_endpoints(fc: FrontendContract) -> list:
    """Convert to `discovery.Endpoint` so frontend-declared routes flow through
    the SAME merge / ranking / probe-generation path as OpenAPI ones.

    Effect class and IDOR score are computed by calling `discovery`'s OWN
    functions — this module adds no second classifier, so it cannot disagree with
    the existing one and cannot become a new probabilistic step (D5).

    Endpoints with `method == "UNKNOWN"` are excluded: an endpoint whose verb we
    cannot read is not testable knowledge, and inventing GET would be a guess.
    """
    from .discovery import Endpoint, _infer_effect, _idor_score, _PARAM, _dedup_sorted

    out = []
    for e in fc.endpoints:
        if e.out_of_scope or e.method == "UNKNOWN":
            continue
        if e.host and e.method not in _HTTP_METHODS:
            continue
        path = _normalise_template(e.path)
        has_param = bool(_PARAM.search(path))
        out.append(Endpoint(
            method=e.method, path=path, params=_PARAM.findall(path),
            effect=_infer_effect(e.method, path, has_param),
            source="frontend_js",
            idor_score=_idor_score(e.method, path, has_param),
        ))
    return _dedup_sorted(out)


def to_contract(fc: FrontendContract) -> dict:
    """Engine-consumable `{endpoint_key: {"effect": ...}}` via discovery's own
    `build_contract`.

    CAUTION, stated where it belongs: `contract.py` stamps anything it is handed
    as `ClassificationSource.CONTRACT` with `high_caution=False`. A bundle is a
    much weaker declaration than an OpenAPI document, so passing this in silently
    UPGRADES its epistemic standing. Callers that care should merge this only
    where no stronger declaration exists. It remains sound either way — D4 means
    the contract can only route to a law, never assert forbiddenness — but the
    honest default is: use `to_endpoints()` for discovery, and reach for this
    only deliberately.
    """
    from .discovery import build_contract
    return build_contract(to_endpoints(fc))


def undeclared_endpoints(fc: FrontendContract, known_keys) -> list:
    """The actual product of this module: endpoints the BUNDLE declares that
    neither the capture exercised nor the spec documented.

    This is the set `discovery.py` explicitly disclaims. Comparison is on the
    normalised template, so `/api/orders/{orderId}` matches the engine's
    `GET /api/orders/{id}`.
    """
    known = {str(k).upper().strip() for k in (known_keys or set())}
    out = []
    for e in fc.endpoints:
        if e.out_of_scope or e.method == "UNKNOWN":
            continue
        key = f"{e.method} {_normalise_template(e.path)}"
        if key.upper() in known:
            continue
        out.append({"method": e.method, "path": _normalise_template(e.path),
                    "key": key, "found_in": e.found_in, "source": e.source})
    out.sort(key=lambda d: (d["method"], d["path"], d["found_in"]))
    return out


def enrich_surface_map(fc: FrontendContract, ledger=None) -> dict:
    """Read-only projection for `surface_map`: declared resource templates keyed
    by normalised path. Returns data; mutates nothing, ever. The ledger argument
    is accepted for call-site symmetry and is intentionally not written to —
    `surface_map`'s identities must come from MEASURED traffic, never from a
    client-side claim (RL1)."""
    doors: dict[str, list[str]] = {}
    for e in fc.endpoints:
        if e.out_of_scope:
            continue
        doors.setdefault(_normalise_template(e.path), []).append(e.method)
    return {p: sorted(set(m)) for p, m in sorted(doors.items())}


def contradiction_probes(fc: FrontendContract) -> list:
    """The ONE genuinely new test idea a frontend contract licenses.

    A client-side guard is the target BROADCASTING "this needs role X". That is a
    declaration, and `act_confront.py` already knows what to do with a
    declaration: confront it with Δstate. So we emit, for each `api_call` guard,
    the probe description that would CONTRADICT it — a principal WITHOUT role X
    reaching the endpoint anyway.

    These are PROBE SUGGESTIONS, not candidates. Nothing here is a finding, and
    nothing here can become one without the confirmer's read-back (RL3).
    """
    out = []
    for g in fc.guards:
        if g.kind != "api_call":
            continue
        out.append({
            "target": g.target,
            "declared_required_role": g.required_role,
            "declared_at": g.found_in,
            "probe": (f"as a principal whose role is NOT '{g.required_role}', issue "
                      f"{g.target}; a 2xx carrying the substantive object CONTRADICTS "
                      f"the client-side declaration and is a BFLA candidate — confirm "
                      f"by Δstate read-back, never by the status code alone"),
            "epistemic_status": ("client-side declaration only; it is NOT evidence the "
                                 "server enforces (or fails to enforce) this role"),
        })
    out.sort(key=lambda d: (d["target"], d["declared_required_role"]))
    return out


# --------------------------------------------------------------------------- #
# CROSS-OPERATION BRIDGE (FCE) — ADDITIVE, DEFAULT OFF                         #
# Nothing above this line is modified.                                         #
# --------------------------------------------------------------------------- #

def extract_cross_operation_contract(har: dict, scope=None, in_scope_hosts=None,
                                     operation_families=None, introspection=None,
                                     enabled: bool = False):
    """Read the GraphQL OPERATION BINDINGS the bundle declares, and confront them
    with the field refusals the same capture recorded.

    FCX reads call sites; this reads operation bindings — the third declared
    source. DEFAULT OFF: disabled, it returns an empty contract without importing
    the extractor, so the disabled path is free and identical.

    It synthesises no operation equivalence. A probe is emitted only where the
    server itself refused a leaf that another declared operation selects, joined
    on the literal field name, never on how the operations are named.
    """
    if not enabled:
        from .cross_operation import CrossOperationContract
        return CrossOperationContract()
    from .cross_operation import from_har as _from_har
    return _from_har(har, scope, in_scope_hosts, operation_families,
                     introspection, enabled=True)
