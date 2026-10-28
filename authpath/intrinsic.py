"""
SAIE / ISI — Intrinsic Structural Interrogation.

The structural-divergence engine (structural.py) is RELATIONAL: it proves a finding
by comparing an under-privileged response to a higher-privilege grammar, which costs a
reference principal + repeated observations. That discipline buys a 0-FP *finding* bar,
but it goes silent whenever a reference is missing — exactly the common case on a real
target with one account and single-shot endpoints.

This module is the orthogonal, INTRINSIC axis: it mines a SINGLE response, with NO
reference principal and NO repeat, for self-contained structural evidence that a
privileged code path executed. It does NOT emit findings (a single response cannot, by
itself, prove an authorization boundary was crossed — a present-but-null field may be a
benign optional). It emits ranked LEADS: high-value hypotheses that (a) tell the hunter
exactly where to look with zero extra traffic, and (b) feed the existing confirmer so a
cheap second signal can graduate a lead into a real finding.

The two signals here are chosen for maximum signal at minimum information:

  * SIBLING_ASYMMETRY — within one collection response, peer elements share a common
    base schema but a minority carry a sensitively-named privileged overlay the majority
    lack. The peers are each other's control, so this is a reference-FREE differential.
    This is the crown jewel: a built-in baseline inside one response.

  * GHOST_FIELD — a sensitively/privileged-named path that is PRESENT but NULL / EMPTY /
    MASKED. The key exists in the schema (the serialization branch executed) while the
    value is gone (output filtering). Stronger when MASKED (the server fetched the real
    value, then redacted it) than when merely null.

Boundary note (RL discipline): the value-blind core (structural.py) remains the only
path to a *finding*. This module is value-AWARE (it must read "***" to detect masking),
but its output is leads, never verdicts — so no value-derived signal ever enters the
finding decision. Leads are a separate, clearly-labelled channel.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .structural import (
    AbsenceState, StructuralFingerprint, fingerprint, shape_kind,
)


# --------------------------------------------------------------------------- #
# Confidence tiers (strictly BELOW a confirmed finding)                       #
# --------------------------------------------------------------------------- #

class Confidence:
    PROVISIONAL_LEAD = "PROVISIONAL_LEAD"  # relational hint from UNSTABLE (1-shot) grammars
    LEAD = "LEAD"                # a structural hypothesis worth a manual probe
    STRONG_LEAD = "STRONG_LEAD"  # reference-free differential or masking — near-finding


class LeadKind:
    SIBLING_ASYMMETRY = "SIBLING_ASYMMETRY"
    GHOST_FIELD = "GHOST_FIELD"
    AUTHZ_ORACLE = "AUTHZ_ORACLE"        # an error body that discloses the authz model
    TYPE_ASYMMETRY = "TYPE_ASYMMETRY"    # a shared field served richer (object) to some peers
    STRUCTURAL_PROVISIONAL = "STRUCTURAL_PROVISIONAL"  # relational breach on unproven grammars
    INTERMITTENT_PRESENCE = "INTERMITTENT_PRESENCE"    # sensitive field flickers under identical input
    ABSENCE_MAP = "ABSENCE_MAP"          # field-level authz differential across principals on ONE object
    GRAPHQL_FIELD_AUTHZ = "GRAPHQL_FIELD_AUTHZ"  # a requested field the server denied on authz grounds
    GRAPHQL_FIELD_BOLA = "GRAPHQL_FIELD_BOLA"    # same field+object: populated for one principal, denied for another
    CHAIN_PROVENANCE = "CHAIN_PROVENANCE"        # a distinctive value from one principal's response consumed in another's request
    TEMPORAL_STRUCTURAL_DRIFT = "TEMPORAL_STRUCTURAL_DRIFT"  # privileged branch retained structurally on a revoked credential


# --------------------------------------------------------------------------- #
# Sensitivity lexicon — a CLOSED vocabulary, never learned (RL1)              #
# Key-name fragments that mark a path as privileged / sensitive. Scored, so   #
# leads can be ranked by how alarming the leaked path name is.                #
# --------------------------------------------------------------------------- #

# strongest: server-internal / authorization machinery that should never reach a
# client at all.
_MARK_INTERNAL = {
    "internal", "audit", "debug", "trace", "_meta", "backend", "server_only",
    "margin", "cost_basis", "cost", "profit", "markup", "wholesale",
    "fraud", "risk_score", "risk", "flagged", "shadow",
}
# authorization / privilege fields.
_MARK_AUTHZ = {
    "role", "roles", "is_admin", "admin", "permission", "permissions", "scope",
    "scopes", "grant", "grants", "privilege", "acl", "capabilities", "can_",
    "is_staff", "is_superuser", "access_level", "tier",
}
# secrets / credentials.
_MARK_SECRET = {
    "password", "passwd", "secret", "token", "api_key", "apikey", "private_key",
    "session", "mfa", "otp", "seed", "salt", "hash", "signature", "client_secret",
}
# PII / financial.
_MARK_PII = {
    "ssn", "social_security", "national_id", "passport", "dob", "birth",
    "phone", "address", "iban", "bank", "card_number", "card_no", "cvv", "pan",
    "routing", "balance", "salary", "compensation", "tax_id", "geolocation",
    "email", "diagnosis", "medical",
}

_WEIGHTS = [(_MARK_SECRET, 10), (_MARK_INTERNAL, 8), (_MARK_AUTHZ, 7), (_MARK_PII, 5)]


def name_sensitivity(path: str) -> int:
    """Score a field path by the most alarming marker in any of its segments.
    Reference-free, deterministic, closed-vocabulary."""
    segs = re.split(r"[.\[\]]", path.lower())
    best = 0
    for seg in segs:
        if not seg:
            continue
        for vocab, w in _WEIGHTS:
            for frag in vocab:
                if frag in seg:
                    best = max(best, w)
    return best



# --------------------------------------------------------------------------- #
# DEFECT #5 FIX — language-NEUTRAL value salience (no English word list).       #
# Sensitivity is scored from the VALUE's SHAPE, so an abbreviated / non-English #
# / opaque field name no longer blinds the relational detectors. Combined with  #
# the cross-principal structural differential, three neutral weak signals beat  #
# one brittle dictionary.                                                       #
# --------------------------------------------------------------------------- #
import re as _re5

_IBAN_RE  = _re5.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$")
_CARD_RE  = _re5.compile(r"^(?:\d[ -]?){13,19}$")
_SSNISH   = _re5.compile(r"^\d{3}-?\d{2}-?\d{4}$")
_HEXTOK   = _re5.compile(r"^[A-Fa-f0-9]{24,}$")
_B64TOK   = _re5.compile(r"^[A-Za-z0-9_\-]{20,}={0,2}$")
_JWTISH   = _re5.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$")

def value_salience(value) -> int:
    """Score how secret/identifying/financial a VALUE looks, by shape only.
    Language-neutral and deterministic. Never reads the field name."""
    if isinstance(value, bool) or value is None:
        return 0
    # financial / large numeric magnitude (balances, salaries, totals)
    if isinstance(value, (int, float)):
        n = abs(float(value))
        if n >= 1000:                     # a non-trivial monetary/identifier magnitude
            return 6
        return 0
    if not isinstance(value, str):
        return 0
    v = value.strip()
    if not v or " " in v.strip() and len(v) > 40:  # free-text prose -> not a secret
        return 0
    if _JWTISH.match(v):  return 10
    if _IBAN_RE.match(v): return 7
    if _SSNISH.match(v):  return 7
    if _CARD_RE.match(v) and 13 <= sum(c.isdigit() for c in v) <= 19: return 7
    if _HEXTOK.match(v):  return 9       # api keys, session ids, hashes
    if _B64TOK.match(v) and any(c.isdigit() for c in v) and any(c.isalpha() for c in v):
        return 8
    # a long all-digit value (account/card/id number)
    if v.isdigit() and len(v) >= 7: return 5
    return 0


def field_salience(path: str, value=None) -> int:
    """The neutral replacement gate: the STRONGER of the (language-specific)
    name score and the (language-neutral) value-shape score. A field is salient
    if EITHER its name is known-sensitive OR its value looks sensitive."""
    s = name_sensitivity(path)
    if value is not None:
        s = max(s, value_salience(value))
    return s


_MASK_RE = re.compile(r"^(?:\*{2,}|x{3,}|\[?redacted\]?|<redacted>|tok_\*+|"
                      r"sk_\*+|\*+[-* ]*\d{2,4}|\d*\*{2,}\d*|\.{3,}|"
                      r"[*x•]{3,}[-•* ]?\d{0,4})$", re.IGNORECASE)


def is_masked(value: Any) -> bool:
    """Heuristic: a string value that is clearly a redaction/mask of a real value.
    Masking is STRONGER evidence than null — the server fetched the real value, then
    deliberately obscured it (so the privileged field provably exists)."""
    if not isinstance(value, str) or not value:
        return False
    v = value.strip()
    if _MASK_RE.match(v):
        return True
    # mostly-stars with a short visible tail: ****1234, ***-**-1111
    stars = sum(c in "*x•" for c in v)
    return stars >= 3 and stars >= len(v.replace("-", "").replace(" ", "")) * 0.4


# --------------------------------------------------------------------------- #
# Lead — a ranked, reference-free hypothesis (NOT a finding)                   #
# --------------------------------------------------------------------------- #

@dataclass
class Lead:
    kind: str
    family: str
    principal: str
    paths: list[str]
    rationale: str
    weight: int
    confidence: str = Confidence.LEAD
    confirmable: bool = False        # is there a cheap follow-up that could confirm?
    suggested_probe: str = ""        # the single operation that would confirm
    evidence: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# helpers — walk a single body's element collections                          #
# --------------------------------------------------------------------------- #

def _element_pathset(elem: Any) -> tuple[set[str], dict[str, str]]:
    """Value-blind path-set + per-path absence-state of ONE collection element,
    rooted at the element (so siblings are directly comparable)."""
    fp = fingerprint(elem)
    return ({p for p in fp.present_paths() if p != "$"}, dict(fp.absence_map))


def _iter_object_arrays(body: Any):
    """Yield (array_path, [elements]) for every array whose elements are objects.
    Single-level + one nested level is enough for real API list/detail shapes."""
    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                child = k if path == "$" else f"{path}.{k}"
                yield from walk(v, child)
        elif isinstance(node, list):
            objs = [e for e in node if isinstance(e, dict)]
            if len(objs) >= 2:
                yield (path, objs)
            for i, e in enumerate(node):
                yield from walk(e, f"{path}[{i}]")
    yield from walk(body, "$")


# --------------------------------------------------------------------------- #
# the interrogation                                                           #
# --------------------------------------------------------------------------- #


def _dig_leaf(elem, dotted):
    """Resolve a simple dotted path inside one collection element. (present, value)."""
    cur = elem
    for seg in dotted.split("."):
        m = re.match(r"^(.*?)\[(\d+)\]$", seg)
        key, idx = (m.group(1), int(m.group(2))) if m else (seg, None)
        if key:
            if not isinstance(cur, dict) or key not in cur:
                return (False, None)
            cur = cur[key]
        if idx is not None:
            if not isinstance(cur, list) or idx >= len(cur):
                return (False, None)
            cur = cur[idx]
    return (True, cur)


def interrogate(body: Any, family: str, principal: str) -> list[Lead]:
    """Mine ONE response for intrinsic structural leads. Pure, reference-free,
    single-operation. Returns ranked leads (highest weight first)."""
    leads: list[Lead] = []
    if not isinstance(body, (dict, list)):
        return leads

    leads.extend(_sibling_asymmetry(body, family, principal))
    leads.extend(_type_asymmetry(body, family, principal))
    leads.extend(_ghost_fields(body, family, principal))
    leads.extend(_authz_oracle(body, family, principal))

    leads.sort(key=lambda d: (-d.weight, d.kind, ",".join(d.paths)))
    return leads


def _sibling_asymmetry(body: Any, family: str, principal: str) -> list[Lead]:
    """Reference-free differential: peers in one collection share a base schema but
    a MINORITY carry a sensitively-named privileged overlay the MAJORITY lack."""
    out: list[Lead] = []
    for arr_path, objs in _iter_object_arrays(body):
        per = [_element_pathset(e) for e in objs]      # (pathset, absence_map) per element
        sets = [s for s, _a in per]
        base = set.intersection(*sets) if sets else set()
        if len(base) < 2:
            continue                       # not the same logical type -> skip (type-driven)
        union = set().union(*sets)
        overlay = union - base             # paths not present in every element
        # privileged/sensitive overlay paths. The minority-on-a-shared-base
        # constraint is itself highly specific, so PII-level (>=5) qualifies here
        # (unlike the noisier single-field ghost signal which requires >=7).
        # DEFECT #5 FIX: qualify an overlay path by the STRONGER of its name score
        # and the value-shape salience of the value the carriers actually hold —
        # language-neutral, so 'bal'/'solde'/'الرصيد' with a financial/token value
        # qualify even though the NAME is not in the English lexicon.
        def _overlay_salient(p):
            best = name_sensitivity(p)
            for e in objs:
                present, val = _dig_leaf(e, p)
                if present:
                    best = max(best, value_salience(val))
            return best
        priv_overlay = {p for p in overlay if _overlay_salient(p) >= 5}
        if not priv_overlay:
            continue
        for p in sorted(priv_overlay):
            carriers = [i for i, s in enumerate(sets) if p in s]
            absentees = [i for i, s in enumerate(sets) if p not in s]
            if not carriers or not absentees or len(carriers) >= len(sets):
                continue                   # genuine minority overlay only
            # carriers where the leaked field actually holds a VALUE (a real leak,
            # not just a present-null structural difference) + their element ids,
            # so the engine can confirm via a single detail read-back.
            populated_ids = []
            for i in carriers:
                _s, absence = per[i]
                if absence.get(p) == AbsenceState.PRESENT_POPULATED:
                    eid = _element_id(objs[i])
                    if eid is not None:
                        populated_ids.append(str(eid))
            w = name_sensitivity(p) + (3 if len(carriers) <= len(sets) // 2 else 1)
            out.append(Lead(
                kind=LeadKind.SIBLING_ASYMMETRY, family=family, principal=principal,
                paths=[f"{arr_path}[*].{p}"], weight=w,
                confidence=Confidence.STRONG_LEAD,
                confirmable=bool(populated_ids),
                rationale=(f"in a single {arr_path} collection, {len(carriers)}/{len(sets)} "
                           f"peer element(s) carry the privileged path '{p}' that the other "
                           f"{len(absentees)} lack — the peers are each other's control, so "
                           f"this is a reference-free authorization asymmetry"),
                suggested_probe=(f"read each {arr_path} element by id as '{principal}'; if the "
                                 f"carriers belong to other principals, '{p}' is a cross-tenant "
                                 f"field-projection leak (confirmable in one read-back)"),
                evidence={"array": arr_path, "field": p,
                          "carriers": carriers, "absentees": absentees,
                          "base_size": len(base), "populated_ids": populated_ids},
            ))
    return out


def _element_id(elem: Any) -> Any:
    """Best-effort identity of a collection element (for a detail read-back)."""
    if not isinstance(elem, dict):
        return None
    for k in ("id", "uuid", "guid", "_id", "key", "slug", "username"):
        if k in elem and isinstance(elem[k], (str, int)):
            return elem[k]
    return None


def _ghost_fields(body: Any, family: str, principal: str) -> list[Lead]:
    """A sensitively-named path that is PRESENT but NULL / EMPTY / MASKED: the
    serialization branch executed (key emitted) while the value was filtered out."""
    out: list[Lead] = []
    fp = fingerprint(body)
    # masked values need the raw body (value-aware, leads-only)
    masked = _collect_masked(body)
    for path, state in fp.absence_map.items():
        if path == "$":
            continue
        s = name_sensitivity(path)
        if path in masked and s >= 5:      # masking is strong at any sensitivity (incl PII)
            out.append(Lead(
                kind=LeadKind.GHOST_FIELD, family=family, principal=principal,
                paths=[path], weight=s + 4, confidence=Confidence.STRONG_LEAD,
                confirmable=True,
                rationale=(f"sensitive field '{path}' is present but MASKED — the server "
                           f"fetched the real value then redacted it, proving the field "
                           f"exists and a fuller view may be reachable"),
                suggested_probe=(f"re-request as a higher-context principal / with an "
                                 f"include or field-selection parameter; an unmasked '{path}' "
                                 f"confirms over-exposure"),
                evidence={"path": path, "filtering": "masked"}))
        elif s >= 7 and state in (AbsenceState.PRESENT_NULL, AbsenceState.PRESENT_EMPTY):
            out.append(Lead(
                kind=LeadKind.GHOST_FIELD, family=family, principal=principal,
                paths=[path], weight=s, confidence=Confidence.LEAD,
                confirmable=True,
                rationale=(f"privileged-named field '{path}' is PRESENT but "
                           f"{'NULL' if state == AbsenceState.PRESENT_NULL else 'EMPTY'} — the "
                           f"serialization branch executed; output filtering emptied the value"),
                suggested_probe=(f"re-request '{path}' as the owner or with elevated context; "
                                 f"a populated value confirms a filtered privileged field"),
                evidence={"path": path, "filtering": state}))
    return out


def _collect_masked(body: Any, path: str = "$") -> set[str]:
    found: set[str] = set()
    if isinstance(body, dict):
        for k, v in body.items():
            child = k if path == "$" else f"{path}.{k}"
            if is_masked(v):
                found.add(child)
            else:
                found |= _collect_masked(v, child)
    elif isinstance(body, list):
        for i, e in enumerate(body):
            found |= _collect_masked(e, f"{path}[{i}]")
    return found


# --------------------------------------------------------------------------- #
# AUTHZ_ORACLE — an error/denial body that discloses the authorization model  #
# --------------------------------------------------------------------------- #

# Closed vocabulary of keys whose mere PRESENCE leaks the gate guarding an
# endpoint (the server tells the attacker exactly which role/scope to obtain).
_AUTHZ_ORACLE_KEYS = {
    "required_role", "required_roles", "required_scope", "required_scopes",
    "required_permission", "required_permissions", "required_tier", "min_role",
    "missing_scope", "missing_scopes", "missing_permission", "missing_permissions",
    "missing_roles", "needs_role", "needs_permission", "needs_scope",
    "your_role", "current_role", "allowed_roles", "allowed_scopes",
    "insufficient_scope", "insufficient_role", "denied_reason", "permission_denied",
    "acl", "policy", "required_claims",
}
# the strongest (directly name the credential to obtain)
_AUTHZ_ORACLE_STRONG = {
    "required_role", "required_roles", "required_scope", "required_scopes",
    "missing_scopes", "missing_permissions", "needs_role", "allowed_roles",
    "required_permission", "required_permissions",
}


def _iter_objects(body: Any, path: str = "$"):
    """Yield (path, dict) for every object node in the body."""
    if isinstance(body, dict):
        yield (path, body)
        for k, v in body.items():
            child = k if path == "$" else f"{path}.{k}"
            yield from _iter_objects(v, child)
    elif isinstance(body, list):
        for i, e in enumerate(body):
            yield from _iter_objects(e, f"{path}[{i}]")


def _authz_oracle(body: Any, family: str, principal: str) -> list[Lead]:
    """A structured error/denial that discloses authorization machinery — a
    reference-free recon lead that hands the hunter the exact gate to attack."""
    out: list[Lead] = []
    seen: set[str] = set()
    for path, obj in _iter_objects(body):
        keys_lower = {str(k).lower() for k in obj}
        hits = keys_lower & _AUTHZ_ORACLE_KEYS
        if not hits or path in seen:
            continue
        seen.add(path)
        revealed = {k: obj[k] for k in obj if str(k).lower() in hits}
        strong = bool(hits & _AUTHZ_ORACLE_STRONG)
        out.append(Lead(
            kind=LeadKind.AUTHZ_ORACLE, family=family, principal=principal,
            paths=sorted(f"{path}.{k}" if path != "$" else k for k in revealed),
            weight=6 + len(hits) + (2 if strong else 0),
            confidence=Confidence.STRONG_LEAD if strong else Confidence.LEAD,
            confirmable=False,
            rationale=(f"the response discloses authorization machinery "
                       f"({sorted(hits)}) — it names the exact role/scope/policy that "
                       f"guards this endpoint, a precise map of the gate to attack"),
            suggested_probe=("re-issue as a principal holding the disclosed credential, or "
                             "probe the named role/scope boundary directly"),
            evidence={"path": path, "revealed": revealed}))
    return out


# --------------------------------------------------------------------------- #
# TYPE_ASYMMETRY — a shared field served with a RICHER type to a minority      #
# (an expanded projection / object where peers got a flattened scalar)        #
# --------------------------------------------------------------------------- #

def _type_asymmetry(body: Any, family: str, principal: str) -> list[Lead]:
    out: list[Lead] = []
    for arr_path, objs in _iter_object_arrays(body):
        fps = [fingerprint(e) for e in objs]
        sets = [{p for p in fp.present_paths() if p != "$"} for fp in fps]
        base = set.intersection(*sets) if sets else set()
        for p in sorted(base):
            if name_sensitivity(p) < 5:
                continue
            kinds: dict[str, list[int]] = {}
            for i, fp in enumerate(fps):
                t = fp.types.get(p)
                if t:
                    kinds.setdefault(shape_kind(t), []).append(i)
            if len(kinds) < 2:
                continue
            rich = [i for k, idxs in kinds.items() if k in ("object", "array") for i in idxs]
            flat = [i for k, idxs in kinds.items() if k == "leaf" for i in idxs]
            if not rich or not flat or len(rich) >= len(fps):
                continue                   # need a genuine minority richer projection
            out.append(Lead(
                kind=LeadKind.TYPE_ASYMMETRY, family=family, principal=principal,
                paths=[f"{arr_path}[*].{p}"], weight=name_sensitivity(p) + 2,
                confidence=Confidence.LEAD, confirmable=False,
                rationale=(f"in {arr_path}, the sensitive field '{p}' is served as an "
                           f"expanded object/array to {len(rich)}/{len(fps)} peer(s) but "
                           f"flattened to a scalar for the rest — the richer projection "
                           f"may expose a sub-structure that should have been collapsed"),
                suggested_probe=(f"compare '{p}' across the {arr_path} elements; the expanded "
                                 f"form likely leaks a nested object meant to be summarised"),
                evidence={"array": arr_path, "field": p,
                          "rich": rich, "flat": flat}))
    return out
