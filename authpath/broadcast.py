"""
authpath.broadcast — the target's DECLARED authorization decision, read off the wire.

THE BROADCAST-vs-ACT NERVE (FORGE build, step 1)
------------------------------------------------
Every target broadcasts its authorization decision twice: as a DECLARATION (what it
shows vs. hides) and as an ACT (what it executes). This module reads the DECLARATION
channel — the broadcast — so a later step can confront it with the act and catch a
contradiction (Δstate-confirmed). Forms of broadcast this reads:

  * field presence/absence across principals — A is shown `salary`, B is not; the
    target declared, per principal, who may see the field;
  * `_links` / HATEOAS action sets — a present link declares "you may"; its absence
    declares "you may not" (per the hypermedia contract);
  * explicit 403 reasons — the target naming the permission it withheld.

CRITICAL FP PRE-MORTEM (F7) — the one trap that can kill this nerve
------------------------------------------------------------------
A difference in broadcast between two principals may be LEGITIMATE, not an authorization
decision: a feature flag, an A/B test, a plan tier, or a field that is simply null
because there is no value (not because it is forbidden). Treating every difference as an
authorization claim would manufacture false positives — fatal.

THE GUARD (built in here, before any detection): a broadcast difference is only ever a
CANDIDATE authorization claim when it correlates with a declared identity / role /
ownership signal the target itself emitted (the principals differ in attested identity
or declared role/tier, and the hidden item is owner/role-scoped). Absent that link →
ABSTAIN (RL5). And this module EMITS CANDIDATES ONLY — it never convicts; Δstate (a
later step) is the sole judge, so even a misclassified legitimate difference costs a
wasted probe, never a false positive.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .attestation import _scalar_fields

# field names that declare WHO OWNS a resource — used to recognize a private resource
# (e.g. the AUTHN-gap path: anon receiving a body that declares an owner = private data).
_OWNER_FIELDS = {"owner_id", "owner", "user_id", "userid", "account_id", "created_by",
                 "author_id", "author", "uid", "customer_id", "belongs_to"}

# link containers that carry a HATEOAS/action broadcast
_LINK_KEYS = {"_links", "links", "_actions", "actions", "@controls", "operations"}
# field-name leaves that are structural/public, not an authorization-scoped broadcast
_PUBLIC_LEAVES = {"id", "type", "kind", "object", "status", "created_at", "updated_at",
                  "url", "href", "self", "_links", "links", "version", "schema",
                  "page", "limit", "total", "count", "next", "prev"}


def _present_fields(body: Any) -> set:
    """The set of scalar field paths the target chose to SHOW in this response — the
    field-presence broadcast. Structural/public leaves are excluded; they carry no
    authorization signal."""
    out = set()
    for k in _scalar_fields(body).keys():
        if k.split(".")[-1].lower() not in _PUBLIC_LEAVES:
            out.add(k)
    return out


def _declared_actions(body: Any, depth: int = 0) -> set:
    """The set of action/link relations the target declared available (HATEOAS). A
    present relation broadcasts 'you may'; its absence broadcasts 'you may not'."""
    rels = set()
    if depth > 6 or not isinstance(body, (dict, list)):
        return rels
    if isinstance(body, dict):
        for k, v in body.items():
            if k.lower() in _LINK_KEYS and isinstance(v, dict):
                rels |= {str(r).lower() for r in v.keys()}
            elif isinstance(v, (dict, list)):
                rels |= _declared_actions(v, depth + 1)
    else:
        for it in body:
            rels |= _declared_actions(it, depth + 1)
    return rels


def _withheld_permission(response) -> Optional[str]:
    """If the target returned 401/403 and NAMED the permission/scope it withheld, that
    string is an explicit broadcast of its decision. Returns the named token or None.
    Skips bare keywords ('permission', 'scope', 'role') and prefers a real identifier —
    a scope-like token (containing : . _ - ) or the noun after the last keyword."""
    if getattr(response, "status", 0) not in (401, 403):
        return None
    import re
    text = ""
    body = getattr(response, "body", None)
    if isinstance(body, dict):
        for key in ("error", "message", "detail", "reason", "error_description"):
            if isinstance(body.get(key), str):
                text += " " + body[key]
    elif isinstance(body, str):
        text = body
    hdr = (getattr(response, "headers", {}) or {}).get("WWW-Authenticate", "")
    text += " " + str(hdr)
    _KW = {"permission", "permissions", "scope", "scopes", "role", "roles",
           "require", "requires", "required", "access", "the", "a", "an", "to", "this",
           "denied", "forbidden", "unauthorized", "error", "failed", "invalid",
           "missing", "insufficient", "not", "allowed", "you", "need", "needs",
           "must", "have", "has", "your", "user", "is", "are", "of", "for"}
    # 1) prefer an explicit scope-like identifier anywhere (orders:write, docs.admin)
    scoped = re.findall(r"[A-Za-z][\w.\-]*[:.][\w.\-]{2,40}", text)
    scoped = [s for s in scoped if s.split(":")[0].lower() not in _KW or ":" in s]
    if scoped:
        return scoped[0]
    # 2) else walk tokens; after any permission keyword, return the first token that
    #    is itself not a keyword (handles 'requires role admin' → admin)
    toks = re.findall(r"[A-Za-z][\w:.\-]{1,40}", text)
    seen_kw = False
    for t in toks:
        low = t.lower()
        is_kw = low in _KW
        if seen_kw and not is_kw:
            return t
        seen_kw = seen_kw or is_kw
    return None


@dataclass
class PrincipalBroadcast:
    """What the target broadcast to ONE principal for ONE resource."""
    accessor: str                      # attested identity (or pid) of the viewer
    resource: str                      # ResourceIdentity string
    present_fields: set = field(default_factory=set)
    declared_actions: set = field(default_factory=set)
    withheld: Optional[str] = None
    accessible: bool = True
    is_owner: bool = False             # a body value equals THIS accessor's identity
    is_anonymous: bool = False         # the accessor had no credential (no token)
    owner_ref: Optional[str] = None    # the ownership field value declared in the body


@dataclass
class BroadcastLedger:
    """Records each principal's broadcast per resource and exposes DIFFERENCES that are
    candidate authorization claims — only when tied to a declared identity/role signal
    (the FP guard). Candidates only; never a verdict."""

    # (resource) -> {accessor -> PrincipalBroadcast}
    _by_resource: dict = field(default_factory=dict)
    # accessor -> declared role/tier the target emitted for it (None if unknown)
    _declared_role: dict = field(default_factory=dict)

    def record(self, accessor: str, resource: str, response, is_anonymous: bool = False) -> None:
        if accessor is None or resource is None:
            return
        status = getattr(response, "status", 0)
        body = getattr(response, "body", None)
        fields = _scalar_fields(body)
        # is_owner: a body value equals THIS accessor's identity — the ownership signal
        # (the same correlation nerve 1 uses, computed locally). Lets the action channel
        # surface owner-vs-non-owner action differences even at the same role.
        is_owner = any(str(v) == str(accessor) for v in fields.values())
        # owner_ref: the value of an ownership-named field, if the body declares one. Used
        # by the AUTHN-gap path: an anonymous principal receiving a body that declares an
        # owner is receiving private data.
        owner_ref = None
        for k, v in fields.items():
            if k.split(".")[-1].lower() in _OWNER_FIELDS and v not in (None, ""):
                owner_ref = str(v)
                break
        pb = PrincipalBroadcast(
            accessor=accessor, resource=resource,
            present_fields=_present_fields(body),
            declared_actions=_declared_actions(body),
            withheld=_withheld_permission(response),
            accessible=200 <= status < 300,
            is_owner=is_owner, is_anonymous=is_anonymous, owner_ref=owner_ref)
        self._by_resource.setdefault(resource, {})[accessor] = pb

    def note_declared_role(self, accessor: str, role: Optional[str]) -> None:
        """Record a role/tier the TARGET declared for this principal (e.g. from /me).
        Used by the FP guard: a broadcast difference only counts when principals differ
        on a declared signal, not on a hidden feature flag."""
        if accessor is not None and role:
            self._declared_role[accessor] = str(role)

    def broadcast_difference_candidates(self) -> list:
        """Pairs of principals the target broadcast DIFFERENTLY for the SAME resource,
        where the difference is tied to a declared identity/role signal (FP guard).
        CANDIDATES for the act-channel to confront — never verdicts.

        Guard logic (the legitimate-conditional trap):
          * the two principals must be DISTINCT identities, and
          * either the target declared DIFFERENT roles/tiers for them (so the broadcast
            difference plausibly tracks authorization, not a flag), OR the difference is
            an explicit withheld-permission broadcast (401/403 naming a permission).
          Otherwise → not emitted (abstain)."""
        out = []
        for resource, per_acc in self._by_resource.items():
            accs = list(per_acc.keys())
            for i in range(len(accs)):
                for j in range(i + 1, len(accs)):
                    a, b = per_acc[accs[i]], per_acc[accs[j]]
                    if a.accessor == b.accessor:
                        continue
                    field_delta = a.present_fields ^ b.present_fields
                    action_delta = a.declared_actions ^ b.declared_actions
                    explicit = bool(a.withheld or b.withheld)
                    if not (field_delta or action_delta or explicit):
                        continue
                    roles_differ = (self._declared_role.get(a.accessor)
                                    != self._declared_role.get(b.accessor))
                    # FIELD/role-tied path (unchanged): a candidate when tied to a declared
                    # role/permission signal — keeps field differences strictly guarded
                    # against feature-flag false positives.
                    role_qualified = explicit or roles_differ
                    # ACTION/ownership-tied path (BFLA): an action difference between the
                    # declared OWNER and a NON-owner is a candidate even at the same role —
                    # the owner legitimately has actions the non-owner is declared to lack,
                    # and the act channel + Δstate decide if the non-owner can do them
                    # anyway. Scoped to ACTIONS only; fields are NOT surfaced via this path
                    # (so the field FP guard is untouched).
                    ownership_tied = bool(action_delta) and (a.is_owner != b.is_owner)
                    if not (role_qualified or ownership_tied):
                        continue
                    # if the candidate qualifies ONLY by ownership (not role/explicit),
                    # surface the ACTION delta only — never the field delta.
                    emit_fields = role_qualified
                    out.append({
                        "resource": resource,
                        "accessor_a": a.accessor, "accessor_b": b.accessor,
                        "fields_only_a": sorted(a.present_fields - b.present_fields) if emit_fields else [],
                        "fields_only_b": sorted(b.present_fields - a.present_fields) if emit_fields else [],
                        "actions_only_a": sorted(a.declared_actions - b.declared_actions),
                        "actions_only_b": sorted(b.declared_actions - a.declared_actions),
                        "withheld_a": a.withheld, "withheld_b": b.withheld,
                        "why": (f"target broadcast {resource} differently to "
                                f"{a.accessor} vs {b.accessor} "
                                f"({'role/permission' if role_qualified else 'owner-vs-nonowner action'} "
                                f"signal) — confront with the act"),
                    })
        return out
