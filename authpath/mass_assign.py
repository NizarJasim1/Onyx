"""
Mass-assignment (write-side BOPLA) — candidate selection.

A privilege-bound field is one whose value is declared role-tied: in observed self-bodies it
carries a privileged value ONLY for a privileged role and a different/absent value for
members. That role↔value correlation is the TARGET'S OWN declaration that the field is
privilege-bound — non-inductive. The verdict itself is never taken here; it is a write-then-
read-back Δstate confirmation (act_bridge.confirm_mass_assignment), scope-gated.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

# roles that denote elevated privilege when they appear as a principal's declared role.
_PRIVILEGED_ROLES = {"admin", "administrator", "superadmin", "super_admin", "root",
                     "staff", "owner", "superuser"}

# field NAMES that hint a privilege flag — used only to SELECT candidates to confront,
# never to convict (the Δstate read-back is the verdict).
_PRIVILEGE_FIELDS_HINT = {"is_admin", "isadmin", "is_staff", "is_superuser", "admin",
                          "role", "roles", "tier", "plan", "is_verified", "verified",
                          "is_active", "permissions", "scopes", "can_admin", "level",
                          "access_level", "grade", "membership"}

# identity / cosmetic fields that legitimately differ per user — never privilege signals.
_IDENTITY_FIELDS = {"id", "email", "user_id", "uid", "username", "name", "display_name",
                    "displayname", "first_name", "last_name", "full_name", "avatar",
                    "bio", "nickname", "handle", "created_at", "updated_at"}


def _truthy_priv(value: Any) -> bool:
    """A clearly-privileged value: boolean True, or a privileged-role token."""
    if value is True:
        return True
    s = str(value).strip().lower()
    return s in ("true", "1") or s in _PRIVILEGED_ROLES


def role_tied_privileged_fields(self_bodies):
    """self_bodies: list of (declared_role, body_dict).
    Return [(field, privileged_value)] — fields whose privileged value is held by a
    privileged role and by NO member-role principal. Identity/cosmetic fields excluded.
    A candidate must (a) be role-tied AND (b) either have a privilege-hinting name or a
    clearly-privileged value — so a per-user display name (even 'Admin') is NOT selected."""
    by_field = defaultdict(lambda: defaultdict(list))   # field -> role -> [values]
    roles = set()
    for role, body in self_bodies:
        if not isinstance(body, dict):
            continue
        roles.add(role)
        for k, v in body.items():
            if isinstance(v, (dict, list)):
                continue
            by_field[k][role].append(v)

    priv_roles = {r for r in roles if r and str(r).lower() in _PRIVILEGED_ROLES}
    member_roles = {r for r in roles if r not in priv_roles}
    if not priv_roles or not member_roles:
        return []

    out = []
    for field, by_role in by_field.items():
        if field.lower() in _IDENTITY_FIELDS:
            continue
        priv_vals = [v for r in priv_roles for v in by_role.get(r, [])]
        mem_vals = {str(v).strip().lower() for r in member_roles for v in by_role.get(r, [])}
        if not priv_vals:
            continue
        for pv in priv_vals:
            if str(pv).strip().lower() in mem_vals:
                continue                                # a member already has it ⇒ not privileged
            name_hint = field.lower() in _PRIVILEGE_FIELDS_HINT
            if name_hint or _truthy_priv(pv):
                out.append((field, pv))
                break
    return out
