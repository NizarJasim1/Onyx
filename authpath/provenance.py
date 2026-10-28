"""
③ Value-Origin Provenance — Axis 1 (§4.1).

Every structurally-significant value in a response is tagged with where it
provably came from.  Because HTTP payloads are structured and NO model
paraphrases them, this is parsing + table lookup — proven, not inferred (RL1/RL2).

The security question this answers: given a value appearing in a *request*, which
response did it come from, and which principal legitimately received it?  That is
what makes "object_id ∈ self_envelope" checkable rather than guessed.

NB: value-*class* recognition (is this an id? an amount?) uses field-name + shape
heuristics. This selects WHICH values to track — it is cosmetic routing, never a
security verdict. The verdict (effect ⊆ authority) is made later, deterministically.

EXTENDED CARRIERS (improvement #3):
  Object-ids may live in places other than the JSON body:
    * Path segments (already handled in HTTPRequest.object_ids)
    * Query string parameters
    * Identity-bearing headers (X-Customer-ID, X-Tenant-ID, ...)
    * JWT claims (sub, user_id, tenant_id, org_id, ...)
  Each extraction stays deterministic and fail-safe — when in doubt, omit.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterator, Optional
import re as _re

from .models import Exchange, ValueOrigin

# RL7.2 Slice C — value-blind shape recognisers for schema-less protobuf fields.
_UUID_SHAPE = _re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                          r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_B64URL = _re.compile(r"^[A-Za-z0-9_\-]+$")
_ID_PREFIX = _re.compile(r"^[a-z]{2,8}_[A-Za-z0-9]{6,}$")   # usr_…, ord_…, cus_…


# Field-name fragments that mark a value as structurally significant (extraction
# routing only — see module docstring).
ID_HINTS = ("id", "uuid", "guid", "ref", "number", "no", "key")
OWNER_HINTS = ("owner", "user", "account", "customer", "author", "principal")
AMOUNT_HINTS = ("amount", "price", "total", "cost", "balance", "fee", "due", "paid", "sum")
QTY_HINTS = ("qty", "quantity", "count", "stock", "inventory", "units")
STATE_HINTS = ("status", "state", "stage", "phase", "fulfilled", "shipped", "settled", "paid_state")
TOKEN_HINTS = ("token", "coupon", "promo", "voucher", "discount", "code", "session")
ROLE_HINTS = ("role", "isadmin", "is_admin", "admin", "privilege", "verified", "scope", "permission")


class ValueClass:
    ID = "id"
    OWNER = "owner"
    AMOUNT = "amount"
    QTY = "qty"
    STATE = "state"
    TOKEN = "token"
    ROLE = "role"
    URL = "url"
    OTHER = "other"


def classify_field(name: str, value: Any) -> str:
    n = name.lower()
    if any(h in n for h in ROLE_HINTS):
        return ValueClass.ROLE
    if any(h in n for h in TOKEN_HINTS):
        return ValueClass.TOKEN
    if any(h in n for h in OWNER_HINTS) and any(h in n for h in ID_HINTS):
        return ValueClass.OWNER
    if any(h in n for h in AMOUNT_HINTS):
        return ValueClass.AMOUNT
    if any(h in n for h in QTY_HINTS):
        return ValueClass.QTY
    if any(h in n for h in STATE_HINTS):
        return ValueClass.STATE
    if any(h in n for h in OWNER_HINTS):
        return ValueClass.OWNER
    if any(n == h or n.endswith("_" + h) or n.endswith(h) for h in ID_HINTS):
        return ValueClass.ID
    if isinstance(value, str) and value.startswith(("http://", "https://", "//")):
        return ValueClass.URL
    # RL7.2 Slice C — shape fallback for SCHEMA-LESS protobuf. Only fires when the
    # field name is a positional protobuf key (f<N>), so named JSON fields are
    # never touched (byte-identical). A strong-shaped nameless value (uuid / long
    # hex / JWT) is classified by SHAPE so a schema-less gRPC IDOR is still
    # value-trackable. value-blind: we read SHAPE, not meaning.
    if _is_positional_key(n):
        shaped = _classify_by_shape(value)
        if shaped is not None:
            return shaped
    return ValueClass.OTHER


def _is_positional_key(name: str) -> bool:
    return len(name) >= 2 and name[0] == "f" and name[1:].isdigit()


def _classify_by_shape(value: Any) -> Optional[str]:
    """Schema-less, value-blind shape recogniser: returns a ValueClass for values
    whose FORM is an unmistakable identifier/token, else None. Conservative — only
    high-confidence shapes, so it never reclassifies ordinary scalars."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    if _UUID_SHAPE.match(s):
        return ValueClass.ID
    if len(s) >= 24 and all(c in "0123456789abcdefABCDEF" for c in s):
        return ValueClass.ID                       # long hex (mongo/sha-style id)
    if s.count(".") == 2 and all(seg and _B64URL.match(seg) for seg in s.split(".")):
        return ValueClass.TOKEN                     # JWT-shaped
    if _ID_PREFIX.match(s):
        return ValueClass.ID                        # stripe-style prefixed id: usr_…, ord_…
    return None


@dataclass
class TaggedValue:
    value: Any
    field_path: str
    value_class: str


_MAX_DEPTH = 64   # defect R5: bound recursion so a pathological deep body cannot DoS

def _walk(node: Any, prefix: str = "", _depth: int = 0) -> Iterator[tuple[str, str, Any]]:
    """Yield (field_name, field_path, value) for every scalar in a JSON-ish tree.
    Depth-bounded (RL5: a hostile/pathological body fails safe, never crashes)."""
    if _depth > _MAX_DEPTH:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                yield from _walk(v, path, _depth + 1)
            else:
                yield k, path, v
    elif isinstance(node, list):
        for i, v in enumerate(node):
            path = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                yield from _walk(v, path, _depth + 1)
            else:
                # use the parent key as the field name for list scalars
                pk = prefix.split(".")[-1] if prefix else "item"
                yield pk, path, v


def extract_values(body: Any) -> list[TaggedValue]:
    """Pull every structurally-significant scalar out of a response/request body.

    RL7 (wire-format): a dict/list is walked directly (the JSON path is unchanged
    and byte-identical). A non-JSON body (protobuf, gRPC-Web frame, multipart,
    ndjson) is first normalized into the canonical structured form by the codec
    boundary, so the laws are no longer blind to hyperscale wire formats. An
    undecodable body normalizes to an opaque marker, which carries no structurally-
    significant scalars (the engine surfaces the opacity separately — it is never
    silently treated as a clean exchange)."""
    if not isinstance(body, (dict, list)) and body is not None:
        from .codec import normalize_body
        body = normalize_body(body).data
    out: list[TaggedValue] = []
    for name, path, value in _walk(body or {}):
        if value is None or isinstance(value, bool):
            continue
        vc = classify_field(name, value)
        if vc == ValueClass.OTHER and not _looks_significant(value):
            continue
        out.append(TaggedValue(value=value, field_path=path, value_class=vc))
    return out


def _looks_significant(value: Any) -> bool:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return True
    if isinstance(value, str) and 1 <= len(value) <= 256:
        return True
    return False


class ProvenanceStore:
    """
    The Axis-1 table.  Keyed by the *value itself* so a value appearing in a later
    request can be traced to the response(s) it provably came from.
    Grows with #endpoints/values, not #requests of raw payload (D10 spirit).
    """

    def __init__(self) -> None:
        # value (stringified) -> list[ValueOrigin]
        self._by_value: dict[str, list[ValueOrigin]] = defaultdict(list)
        # quick index: which principals have legitimately *seen* a value
        self._seen_by: dict[str, set[str]] = defaultdict(set)
        # D-ENVELOPE-OVERBROAD fix: which principals have legitimately HELD a value
        # as an AUTHORITATIVE OBJECT — i.e. the value is the resource the actor
        # explicitly addressed (∈ request.object_ids) and received. This is a
        # STRICT subset of _seen_by: an id merely glimpsed as a LIST ELEMENT is
        # "seen" but NOT "held". The OBJECT_ACCESS law suppresses on HELD (true
        # authorisation), not on mere presence — so a list→item pivot is no longer
        # silently cleared just because the attacker saw the id in a listing.
        self._held_by: dict[str, set[str]] = defaultdict(set)
        # RL9 (host-scoped authority): seen/held indexed by (value, host). A value
        # seen/held on service X does not count as authority on service Y.
        self._seen_by_host: dict[tuple, set[str]] = defaultdict(set)
        self._held_by_host: dict[tuple, set[str]] = defaultdict(set)

    def observe_response(self, ex: Exchange, legitimate: bool = True) -> list[ValueOrigin]:
        """
        Tag every significant value in a response with its origin. Hot path.

        legitimate=True  (observe phase): the principal LEGITIMATELY received these
                         values, so they enter both the origin table AND the
                         "seen-by" legitimacy index.
        legitimate=False (analyze phase, a probe): we still record the origin so
                         cross-exchange value counting (e.g. coupon redemptions)
                         works, but we MUST NOT mark them as legitimately received —
                         a probe response can never grant its own actor authority.
        """
        origins: list[ValueOrigin] = []
        # ids the actor EXPLICITLY ADDRESSED in this request (path/header/jwt). A
        # value received that equals an addressed id is an authoritative hold; a
        # value that only appears incidentally in the body (e.g. a list element)
        # is not. This is what separates "I fetched object 701" from "701 showed
        # up in a list I was allowed to read".
        addressed = {str(o) for o in ex.request.object_ids()} if legitimate else set()
        host = (ex.request.host or "").strip().lower()
        for tv in extract_values(ex.response.body):
            origin = ValueOrigin(
                value=tv.value,
                response_id=ex.rid,
                principal_id=ex.principal.pid,
                endpoint=ex.request.endpoint_key(),
                field_path=tv.field_path,
                session_id=ex.session_id,
                observed_at=ex.observed_at,
            )
            key = _vkey(tv.value)
            self._by_value[key].append(origin)
            if legitimate:
                self._seen_by[key].add(ex.principal.pid)
                self._seen_by_host[(key, host)].add(ex.principal.pid)
                if str(tv.value) in addressed:
                    self._held_by[key].add(ex.principal.pid)
                    self._held_by_host[(key, host)].add(ex.principal.pid)
            origins.append(origin)
        return origins

    def tag_only(self, ex: Exchange) -> int:
        """Count structurally-significant values without mutating the store
        (used for the analyze-phase trace display)."""
        return len(extract_values(ex.response.body))

    # -- the proof queries the laws lean on -------------------------------- #
    def legitimate_hold_hosts(self, value: Any, principal_id: str) -> frozenset:
        """The hosts on which `principal_id` legitimately HELD this value. Lets the
        conservation law tell a same-service leak (property coordinate) from a
        cross-SERVICE one (authority held on host X surfaced on host Y) — a coordinate
        a spec-snapshot permutation tester cannot express."""
        out = {h for (k, h), pids in self._held_by_host.items()
               if k == _vkey(value) and principal_id in pids}
        return frozenset(out)

    def legitimate_holders(self, value: Any) -> frozenset:
        """Principals who LEGITIMATELY HELD this value (addressed it in a 2xx during
        the observe phase). Order-independent set membership — never 'who saw it
        first'. Attack-phase responses never enter this set, so it cannot be
        laundered. This is the measured ownership signal for id/owner-class values."""
        return frozenset(self._held_by.get(_vkey(value), set()))

    def legitimate_seers(self, value: Any) -> frozenset:
        """Principals who LEGITIMATELY received this value in a response body during
        the observe phase. For a secret/token (never 'addressed', so never HELD) a
        single non-anon seer is its owner. Attack responses are excluded by design."""
        return frozenset(self._seen_by.get(_vkey(value), set()))

    def origins_of(self, value: Any) -> list[ValueOrigin]:
        return list(self._by_value.get(_vkey(value), []))

    def seen_by_principal(self, value: Any, principal_id: str, host=None) -> bool:
        """Did this principal legitimately receive this value in a response? With
        `host`, scoped to that service (RL9) — a value seen on service X does not
        count as seen on service Y."""
        if host is not None:
            h = (host or "").strip().lower()
            return principal_id in self._seen_by_host.get((_vkey(value), h), set())
        return principal_id in self._seen_by.get(_vkey(value), set())

    def held_object_by_principal(self, value: Any, principal_id: str, host=None) -> bool:
        """Did this principal legitimately HOLD this value as an AUTHORITATIVE
        object (addressed + received)? With `host`, scoped to that service (RL9)."""
        if host is not None:
            h = (host or "").strip().lower()
            return principal_id in self._held_by_host.get((_vkey(value), h), set())
        return principal_id in self._held_by.get(_vkey(value), set())

    def first_seen_for_other_principal(self, value: Any, acting_pid: str) -> ValueOrigin | None:
        """The smoking gun: a value that only ever appeared in *another*
        principal's response — i.e. it was laundered across an authority boundary."""
        for o in self._by_value.get(_vkey(value), []):
            if o.principal_id != acting_pid:
                return o

    def owner_of_value(self, value: Any) -> str | None:
        """The principal of the EARLIEST recorded origin of `value`. Ownership is
        established during the observe phase (each principal reads its own identity
        first), so the earliest origin is chaos-robust: a later cache-bleed that makes
        a second principal 'see' the value cannot rewrite who owned it first. Laws that
        attribute private data use THIS, not the pollutable seers set."""
        origins = self._by_value.get(_vkey(value), [])
        return origins[0].principal_id if origins else None

    def unambiguous_owner(self, value: Any) -> str | None:
        """Collision-proof owner attribution for GIANT VOLUME (protocol [21], G3). At 10^6
        scale the birthday paradox guarantees coincidental value collisions: two different
        principals independently holding the same value (a common name, a default, an enum).
        Attributing such a value would be a scale-only FALSE POSITIVE. This resolver returns
        an owner ONLY if the value legitimately originated under EXACTLY ONE distinct
        principal; if two or more legitimate principals originated it, the value is shared/
        common -> None (abstain). Combined with the entropy gate, coincidental misattribution
        becomes impossible by construction: a low-entropy value is caught here (multi-origin),
        and a high-entropy value colliding across principals by chance is ~2^-100. This only
        ABSTAINS more than owner_of_value; it can never attribute where the base did not, so
        it cannot lower precision — it removes a scale-only FP vector."""
        origins = self._by_value.get(_vkey(value), [])
        if not origins:
            return None
        distinct = {o.principal_id for o in origins}
        if len(distinct) != 1:
            return None                          # shared/colliding value -> abstain
        return origins[0].principal_id
        return None


def _vkey(value: Any) -> str:
    return f"{type(value).__name__}:{value}"


# --------------------------------------------------------------------------- #
# Extended carriers — JWT, identity headers, query params (improvement #3)    #
# --------------------------------------------------------------------------- #
# Headers whose VALUES carry principal identity / scope-bearing ids.
# A narrow list + a suffix pattern keeps false positives out (trace/request ids
# explicitly excluded).
IDENTITY_HEADER_EXACT = {
    "x-customer-id", "x-user-id", "x-account-id", "x-tenant-id",
    "x-org-id", "x-organization-id", "x-workspace-id",
}
IDENTITY_HEADER_SUFFIX = ("-customer-id", "-user-id", "-account-id",
                          "-tenant-id", "-org-id")
# Headers that LOOK like id but are NOT identity (extracted as IDs would be noise).
IDENTITY_HEADER_DENY = {"x-request-id", "x-trace-id", "x-correlation-id",
                        "x-amzn-trace-id", "traceparent", "x-span-id"}

# JWT claim names that carry principal identity / authority scope.
JWT_IDENTITY_CLAIMS = ("sub", "user_id", "uid", "userid", "account_id",
                       "customer_id", "tenant_id", "tid", "org_id",
                       "organization_id", "workspace_id", "principal")
JWT_AUTHORITY_CLAIMS = ("role", "roles", "scope", "scopes", "permissions",
                        "is_admin", "admin")


@dataclass
class JWTInspection:
    """Result of inspecting an Authorization JWT. All fields optional/best-effort."""
    identity_claims: dict[str, Any]    # sub, tenant_id, org_id, ...
    authority_claims: dict[str, Any]    # role, scope, ...
    alg: str | None                    # signature alg, or None if unparseable
    none_alg: bool                     # signature alg literally "none" → red flag
    empty_signature: bool              # signature segment empty/missing
    raw_claims: dict[str, Any]


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    try:
        return base64.urlsafe_b64decode(seg + pad)
    except (binascii.Error, ValueError):
        return b""


def inspect_jwt(token: str) -> JWTInspection | None:
    """Decode a JWT WITHOUT verification — used only as a structured carrier of
    *claimed* principal identity. We never trust the JWT's authority assertion;
    we only use it to know which principal the request CLAIMS to be, and to flag
    obvious signature attacks (alg=none, empty sig) as a side-channel signal.

    Returns None if the token is not a parseable JWT shape.
    """
    if not isinstance(token, str):
        return None
    # strip optional "Bearer " prefix
    if token.lower().startswith("bearer "):
        token = token[7:]
    parts = token.split(".")
    if len(parts) not in (2, 3):
        return None
    header_bytes = _b64url_decode(parts[0])
    payload_bytes = _b64url_decode(parts[1])
    if not header_bytes or not payload_bytes:
        return None
    try:
        header = json.loads(header_bytes)
        claims = json.loads(payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(claims, dict) or not isinstance(header, dict):
        return None
    alg = header.get("alg")
    none_alg = isinstance(alg, str) and alg.lower() == "none"
    empty_sig = (len(parts) == 2) or (len(parts) == 3 and not parts[2].strip())

    ident = {k: v for k, v in claims.items()
             if k.lower() in JWT_IDENTITY_CLAIMS and v is not None}
    auth = {k: v for k, v in claims.items()
            if k.lower() in JWT_AUTHORITY_CLAIMS and v is not None}
    return JWTInspection(
        identity_claims=ident, authority_claims=auth,
        alg=alg if isinstance(alg, str) else None,
        none_alg=none_alg, empty_signature=empty_sig, raw_claims=claims,
    )


def extract_identity_headers(headers: dict[str, str]) -> list[tuple[str, str]]:
    """Return [(header_name, value)] for headers that carry principal identity.

    Strictly allow-listed: an explicit set + a narrow suffix pattern. Trace/
    correlation headers are explicitly excluded to keep noise out (rule of
    fail-safe extraction: when in doubt, omit)."""
    out: list[tuple[str, str]] = []
    if not headers:
        return out
    for raw_name, raw_value in headers.items():
        name = raw_name.lower().strip()
        if name in IDENTITY_HEADER_DENY:
            continue
        if name in IDENTITY_HEADER_EXACT or any(name.endswith(s) for s in IDENTITY_HEADER_SUFFIX):
            if raw_value is not None and str(raw_value).strip():
                out.append((raw_name, str(raw_value)))
    return out


def extract_query_ids(query: dict[str, Any]) -> list[tuple[str, Any]]:
    """Return [(param, value)] for query params whose name resembles an id field.
    Multi-valued params (HTTP parameter pollution, e.g. ?id=a&id=b captured as a
    list) yield one pair PER value, so a polluted victim id is never dropped.
    Re-uses the same classifier the body extractor uses, so the rules stay
    consistent across request surfaces."""
    if not query:
        return []
    out = []
    for k, v in query.items():
        if v is None:
            continue
        vc = classify_field(k, v if not isinstance(v, (list, tuple)) else "x")
        if vc in (ValueClass.ID, ValueClass.OWNER, ValueClass.TOKEN):
            if isinstance(v, (list, tuple)):
                for item in v:
                    if item is not None:
                        out.append((k, item))
            else:
                out.append((k, v))
    return out

