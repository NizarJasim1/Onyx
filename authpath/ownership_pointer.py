"""
authpath.ownership_pointer — discover, per target, WHICH response field denotes
ownership, by correlating it with the identity the target attested for a credential.

THE NERVE, STEP 2 (FORGE build)
-------------------------------
Step 1 (attestation.py) gave us the identity the TARGET declares for each credential.
Step 2 asks the target's OWN data which field carries ownership: across a principal's
LEGITIMATE resources, the field whose value equals that principal's attested identity
IS this target's ownership pointer — learned from the target, not assumed. On target A
it may be `owner_id`, on B `user.email`, on C `createdBy`; ONYX reads it off the wire.

CRITICAL SAFETY CONTRACT (your instruction: never weaken the project, never add a
single false positive)
----------------------------------------------------------------------------------
  * This module EMITS CANDIDATES ONLY. It produces no finding, touches no verdict,
    no Δstate, no existing confirmer/owner logic. A wrong correlation can therefore
    NEVER raise a false positive — conviction stays exclusively with the existing
    Δstate confirmer (step 4). (Meta-guard / FP-d.)
  * Flag-gated and additive: with the flag off this module is never constructed and
    behaviour is byte-identical.

FALSE-POSITIVE PRE-MORTEM (F7) — five sources, five guards, all enforced here:
  FP-a  coincidental equality (a field equals my id by chance) → require the field to
        equal the identity across ≥2 DISTINCT resources before it is a pointer.
  FP-b  a field shared by ALL principals (tenant_id, region) that looks owner-like →
        require the pointer to take DIFFERENT values for DIFFERENT attested identities
        (it must distinguish owners), and an ownership-like leaf name.
  FP-c  a resource legitimately SHARED with me (owner≠me but an acl/shared_with grants
        me) → `grant_includes` reports the declared grant; the equivalence layer must
        treat such a resource as legitimately reachable, never a candidate.
  FP-d  policy grants me access via an unseen role/relation → correlation NEVER
        convicts; it only marks a candidate for Δstate to judge. Enforced by design.
  FP-e  the server reflects MY OWN input back (echoes the id I sent) → exclude any
        response value that also appears in the request (path/query/body).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .attestation import _is_identity_field, _scalar_fields

# ownership-pointer leaf names we will accept (quotes the target's naming; a bespoke
# name ⇒ abstain, operator-extensible via register_ownership_fields).
_OWNERSHIP_FIELD_NAMES = {
    "owner", "owner_id", "ownerid", "user_id", "userid", "uid", "user",
    "account_id", "accountid", "created_by", "createdby", "author", "author_id",
    "customer_id", "customerid", "member", "member_id", "principal", "principal_id",
    "tenant_owner", "belongs_to", "assigned_to", "patient", "patient_id",
    "provider", "provider_id", "subject_id",
}
_CUSTOM_OWNERSHIP_FIELDS: set = set()

# declared grant fields — a resource that names me here is legitimately shared (FP-c).
_GRANT_FIELDS = {"shared_with", "sharedwith", "acl", "collaborators", "members",
                 "viewers", "editors", "shared_to", "grantees", "allowed_users",
                 "participants", "assignees", "guests"}


def register_ownership_fields(names) -> None:
    for n in names or []:
        if isinstance(n, str) and n.strip():
            _CUSTOM_OWNERSHIP_FIELDS.add(n.strip().lower())


def _is_ownership_field(field_path: str) -> bool:
    leaf = field_path.split(".")[-1].lower()
    return (leaf in _OWNERSHIP_FIELD_NAMES or leaf in _CUSTOM_OWNERSHIP_FIELDS
            or _is_identity_field(field_path))


def _request_values(request) -> set:
    """Every scalar the CLIENT supplied (path segments, query values, body scalars).
    Used to exclude reflected input (FP-e): a 'pointer' that merely echoes what I
    sent is not the server declaring ownership."""
    vals: set = set()
    try:
        for seg in (getattr(request, "path", "") or "").strip("/").split("/"):
            if seg:
                vals.add(seg.lower())
        for v in (getattr(request, "query", {}) or {}).values():
            vals.add(str(v).lower())
        body = getattr(request, "body", None)
        if isinstance(body, dict):
            for v in _scalar_fields(body).values():
                vals.add(str(v).lower())
    except Exception:                                  # noqa: BLE001 (S3 robustness)
        pass
    return vals


@dataclass
class OwnershipPointerLedger:
    """Learns the target's ownership-pointer field by identity-correlation and exposes
    pure, non-convicting queries for the equivalence layer."""

    # field_path -> {attested_identity -> set(resource_keys where field==identity)}
    _hits: dict = field(default_factory=dict)
    # field_path -> set(distinct attested identities that ever owned via this field)
    _owners_seen: dict = field(default_factory=dict)
    _pointer: Optional[str] = None

    def observe_owned(self, request, response, attested_identity: str,
                      resource_key: str) -> None:
        """Record a LEGITIMATE access: the principal whose attested identity is given
        accessed `resource_key` and got `response`. For every response field whose
        value equals the attested identity (and was NOT reflected from the request),
        bank a correlation hit. Pure bookkeeping — no verdict."""
        if attested_identity is None:
            return
        if not (200 <= getattr(response, "status", 0) < 300):
            return
        body = getattr(response, "body", None)
        fields = _scalar_fields(body)
        if not fields:
            return
        reflected = _request_values(request)
        ident_l = str(attested_identity).lower()
        for fpath, val in fields.items():
            if str(val).lower() != ident_l:
                continue
            if str(val).lower() in reflected:          # FP-e: reflected input, not ownership
                continue
            if not _is_ownership_field(fpath):         # FP-b (partial): must look owner-like
                continue
            self._hits.setdefault(fpath, {}).setdefault(attested_identity, set()).add(resource_key)
            self._owners_seen.setdefault(fpath, set()).add(attested_identity)
        self._relearn_pointer()

    def _relearn_pointer(self) -> None:
        """Promote a field to THE ownership pointer only when it satisfies every guard:
          FP-a: it equalled an identity across ≥2 DISTINCT resources (not a one-off);
          FP-b: it has distinguished ≥2 DIFFERENT owners OR (with one owner so far)
                covers ≥2 resources — and its leaf name is ownership-like.
        Deterministic; ties broken by ownership-name rank then path length."""
        qualified = []
        for fpath, per_id in self._hits.items():
            distinct_resources = set()
            for rkeys in per_id.values():
                distinct_resources |= rkeys
            if len(distinct_resources) < 2:            # FP-a: need corroboration
                continue
            owners = self._owners_seen.get(fpath, set())
            # FP-b: if every owner-value is identical the field doesn't distinguish
            # owners; require either >1 owner seen, or defer (still a candidate, but
            # not promoted to canonical pointer until a 2nd owner corroborates).
            qualified.append((fpath, len(owners), len(distinct_resources)))
        if not qualified:
            self._pointer = None
            return
        # prefer fields that have distinguished MORE owners, then ownership-name rank
        qualified.sort(key=lambda t: (-t[1], _own_rank(t[0]), len(t[0])))
        self._pointer = qualified[0][0]

    # -------- pure, non-convicting queries for the equivalence layer ---------- #
    def pointer(self) -> Optional[str]:
        return self._pointer

    def declared_owner(self, response) -> Optional[str]:
        """The owner the target DECLARED for this response (value at the learned
        pointer), or None if unknown ⇒ caller abstains (F2). Never a verdict."""
        if self._pointer is None:
            return None
        fields = _scalar_fields(getattr(response, "body", None))
        return fields.get(self._pointer)

    def grant_includes(self, response, attested_identity: str) -> bool:
        """FP-c: did the target DECLARE this resource shared with me (acl/shared_with/…)?
        If so the access is legitimate and must never become a candidate. Reads the
        target's own grant declaration; never inferred."""
        if attested_identity is None:
            return False
        body = getattr(response, "body", None)
        ident_l = str(attested_identity).lower()
        return _grant_mentions(body, ident_l)


def _grant_mentions(body: Any, ident_l: str, depth: int = 0) -> bool:
    if depth > 6 or not isinstance(body, (dict, list)):
        return False
    if isinstance(body, dict):
        for k, v in body.items():
            if k.lower() in _GRANT_FIELDS:
                if _value_contains(v, ident_l):
                    return True
            if isinstance(v, (dict, list)) and _grant_mentions(v, ident_l, depth + 1):
                return True
    else:
        for it in body:
            if _grant_mentions(it, ident_l, depth + 1):
                return True
    return False


def _value_contains(v: Any, ident_l: str) -> bool:
    if isinstance(v, (str, int)) and not isinstance(v, bool):
        return str(v).lower() == ident_l
    if isinstance(v, list):
        return any(_value_contains(x, ident_l) for x in v)
    if isinstance(v, dict):
        return any(_value_contains(x, ident_l) for x in v.values())
    return False


def _own_rank(field_name: str) -> int:
    leaf = field_name.split(".")[-1].lower()
    order = {"owner_id": 0, "owner": 0, "user_id": 1, "created_by": 1, "account_id": 2,
             "author_id": 2, "customer_id": 2}
    return order.get(leaf, 5)
