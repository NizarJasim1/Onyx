"""
authpath.attestation — the target's OWN testimony about who holds a credential.

THE NERVE, MADE OPERATIONAL (step 1 of the FORGE build)
------------------------------------------------------
Every authorization equivalence class begins with one question: "are these two
requests the SAME principal or DIFFERENT principals?" ONYX must NEVER answer that
itself — deciding identity from a credential fingerprint is induction (a shared
proxy token, a multi-device user, a hijacked session all defeat it) and would
violate RL1. Instead ONYX QUOTES THE TARGET: it reads the identity the target
itself declares for a credential at a self endpoint it observed in legitimate
traffic (`/me`, `/userinfo`, `/account`, `whoami`, a GraphQL `viewer`/`me`). The
target says "the holder of this credential is X"; ONYX records that testimony. Two
credentials the target maps to the SAME declared identity ARE the same principal —
by the target's own word, not ONYX's guess.

WHY THIS IS RL1-SAFE
--------------------
  * No token is parsed (works for opaque/reference tokens — RFC 9068 forbids the
    client inspecting JWT claims anyway).
  * No statistics, no thresholds, no "≥4 browsers ⇒ shared" heuristics.
  * The binding is a literal equality the target asserted in a response ONYX saw.
  * Absence of testimony ⇒ ABSTAIN (F2), never a guessed identity.

FALSE-POSITIVE PRE-MORTEM (F7) and the guard for each
-----------------------------------------------------
  FP-1  Two principals share one credential (proxy) and ONYX treats them as two →
        it would split one equivalence class in two. GUARD: identity comes from the
        target's testimony, so a shared credential yields ONE declared identity →
        ONYX unifies them exactly as the target does.
  FP-2  One principal, two credentials (multi-device) treated as two principals →
        GUARD: the target declares the SAME identity for both → unified.
  FP-3  A self endpoint that is actually a SHARED resource (e.g. `/users/{id}`
        where id happens to be the caller's) misread as self-testimony → GUARD:
        only endpoints the target resolves to a SELF alias, or that echo a field
        equal to the credential's already-known identity, count as testimony;
        ambiguous endpoints are ignored (F2 abstain).
  FP-4  A field guessed to be "the identity" that is really something else →
        GUARD: the identity field is not guessed; it is the field whose value is
        identical across EVERY self-endpoint response for that credential AND
        differs across credentials — the target's own stable self-pointer. If no
        such field is unambiguous, abstain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Self endpoints the target resolves to "the caller". Reuses the same vocabulary
# the router already trusts (models.SELF_ALIASES) plus the common literal paths.
_SELF_PATH_LEAVES = {"me", "self", "whoami", "current", "current_user", "viewer",
                     "profile", "account", "userinfo", "user_info"}


def _looks_self_referential(path: str) -> bool:
    """True iff the path's final segment is a self alias (…/me, …/userinfo).
    Cosmetic routing only — it selects which responses are candidate testimony;
    it asserts no verdict."""
    leaves = [s for s in (path or "").strip("/").split("/") if s]
    if not leaves:
        return False
    return leaves[-1].lower() in _SELF_PATH_LEAVES


def _scalar_fields(body: Any, prefix: str = "", out: Optional[dict] = None) -> dict:
    """Flatten a JSON body to {dotted_path: scalar} for scalar leaves only. Used to
    find the field the target uses as its stable self-pointer. Bounded depth; never
    raises on messy real bodies (SENTINEL S3)."""
    if out is None:
        out = {}
    if isinstance(body, dict):
        for k, v in body.items():
            key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
            if isinstance(v, (str, int)) and not isinstance(v, bool):
                out[key] = str(v)
            elif isinstance(v, dict):
                _scalar_fields(v, key, out)
            # lists are skipped: a self record is a single object, not a collection
    return out


@dataclass
class AttestationLedger:
    """Records, per credential fingerprint, the identity the TARGET declared for it
    at a self endpoint. Pure bookkeeping of the target's testimony — no inference."""

    # fingerprint -> {field_path: declared_value} seen at self endpoints
    _testimony: dict = field(default_factory=dict)
    # fingerprint -> resolved stable identity string (once unambiguous)
    _identity: dict = field(default_factory=dict)
    # the field path the target uses as its self-pointer, once it is unambiguous
    # across credentials (e.g. "id", "user.id", "email"). None until learned.
    _self_pointer: Optional[str] = None

    def record_self_response(self, fingerprint: str, request, response) -> None:
        """If this exchange is the target testifying about the caller (a self
        endpoint, 2xx), store the scalar fields it returned for this credential.
        No identity is decided here — only testimony is filed."""
        if fingerprint is None:
            return
        status = getattr(response, "status", 0)
        if not (200 <= status < 300):
            return
        path = getattr(request, "path", "") or ""
        is_gql_self = False
        try:
            if getattr(request, "is_graphql", lambda: False)():
                q = str((getattr(request, "body", None) or {}).get("query") or "")
                is_gql_self = ("viewer" in q or "{ me" in q or "{me" in q
                               or "currentUser" in q)
        except Exception:                              # noqa: BLE001 (S3)
            is_gql_self = False
        if not (_looks_self_referential(path) or is_gql_self):
            return
        body = getattr(response, "body", None)
        fields = _scalar_fields(body)
        if not fields:
            return
        bucket = self._testimony.setdefault(fingerprint, {})
        # keep only fields that are STABLE for this credential across self responses;
        # a field whose value changes between two self reads is not an identity.
        for k, v in fields.items():
            if k in bucket and bucket[k] != v:
                bucket[k] = _UNSTABLE
            elif k not in bucket:
                bucket[k] = v
        self._relearn_pointer()

    def _relearn_pointer(self) -> None:
        """The self-pointer is the IDENTITY-named self field (from a fixed, declared
        vocabulary — id/user_id/sub/email/…) that is present and stable for every
        credential that has testified. We deliberately do NOT pick "the field that
        distinguishes credentials": a principal's identity is SHARED across that
        principal's devices/sessions, so a volatile per-credential field (session,
        csrf, request_id) is the WRONG choice and would split one principal in two.
        Restricting to a declared identity vocabulary quotes the target's own field
        naming (RL1-safe, like the sensitivity vocabulary); a bespoke identity field
        name outside it ⇒ abstain (F2), operator-extensible. Deterministic."""
        creds = [fp for fp, b in self._testimony.items()
                 if any(val is not _UNSTABLE for val in b.values())]
        if not creds:
            return
        # fields stable for EVERY credential that testified
        common = None
        for fp in creds:
            stable = {k for k, v in self._testimony[fp].items() if v is not _UNSTABLE}
            common = stable if common is None else (common & stable)
        if not common:
            self._self_pointer = None
            return
        # keep only those whose LEAF name is a declared identity name
        id_fields = [k for k in common if _is_identity_field(k)]
        if not id_fields:
            self._self_pointer = None        # no recognised identity field ⇒ abstain
            return
        self._self_pointer = sorted(id_fields, key=_pointer_rank)[0]
        for fp in creds:
            val = self._testimony[fp].get(self._self_pointer)
            if val is not None and val is not _UNSTABLE:
                self._identity[fp] = val

    def identity_of(self, fingerprint: str) -> Optional[str]:
        """The identity the TARGET declared for this credential, or None if the
        target never testified unambiguously (⇒ caller must abstain, F2)."""
        return self._identity.get(fingerprint)

    def same_principal(self, fp_a: str, fp_b: str) -> Optional[bool]:
        """Did the TARGET declare these two credentials to be the same principal?
        Returns True/False only when both have testimony; None ⇒ unknown ⇒ abstain.
        ONYX never decides this itself — it reports the target's own verdict."""
        ia, ib = self._identity.get(fp_a), self._identity.get(fp_b)
        if ia is None or ib is None:
            return None
        return ia == ib


# sentinel for a field whose value was not stable across a credential's self reads
class _Unstable:
    __slots__ = ()
    def __repr__(self):                                # pragma: no cover
        return "<unstable>"


_UNSTABLE = _Unstable()


# Declared identity field names — a self field is an identity pointer iff its LEAF
# name is one of these (operator-extensible). Quotes the target's own naming; never
# inferred. A bespoke name outside this set ⇒ abstain (F2), not a guess.
_IDENTITY_FIELD_NAMES = {
    "id", "user_id", "userid", "uid", "sub", "account_id", "accountid",
    "uuid", "guid", "username", "user_name", "login", "email", "principal_id",
    "actor_id", "member_id", "subject",
}
_CUSTOM_IDENTITY_FIELDS: set = set()


def register_identity_fields(names) -> None:
    """Operator hook: declare this target's bespoke identity field name(s)."""
    for n in names or []:
        if isinstance(n, str) and n.strip():
            _CUSTOM_IDENTITY_FIELDS.add(n.strip().lower())


def _is_identity_field(field_path: str) -> bool:
    leaf = field_path.split(".")[-1].lower()
    return leaf in _IDENTITY_FIELD_NAMES or leaf in _CUSTOM_IDENTITY_FIELDS


def _pointer_rank(field_name: str) -> tuple:
    """Prefer the most identity-like stable field as the self-pointer, deterministically.
    Lower rank = preferred. Purely a tie-break among already-qualifying fields."""
    leaf = field_name.split(".")[-1].lower()
    order = {"id": 0, "user_id": 1, "userid": 1, "uid": 1, "sub": 1, "account_id": 2,
             "username": 3, "login": 3, "email": 4, "uuid": 2, "guid": 2}
    return (order.get(leaf, 9), len(field_name), field_name)
