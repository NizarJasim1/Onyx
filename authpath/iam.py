"""
authpath.iam — the AUTHORITY-GRAPH model (RL13 support).

ONYX modelled authority as a fixed ENVELOPE the actor operates within. IAM
escalation is different in kind: it is a WRITE to the authority graph — granting a
role/permission to a member on a resource. To judge such a write we need a model
of authority RANK, and a way to read role bindings out of the common cloud shapes.

RL1 (no induction): role rank is a DECLARED, reviewed partial order — never
learned. Sensible built-in defaults for the major clouds are provided and the
operator can override/extend per deployment via the contract. The ranks are a
coarse ladder (higher number ⇒ more authority); only the ORDER matters, and only
for the comparison "is the granted role above what the actor holds?".
"""
from __future__ import annotations

from typing import Optional

# Declared rank ladder. Coarse on purpose — we only ever compare ranks, never
# treat the numbers as quantities. Matching is by normalised substring so
# "roles/owner", "Owner", "ORGANIZATION_OWNER" all map to the owner tier.
_DEFAULT_RANKS = (
    # (substring, rank) — first match wins, checked high→low specificity
    ("owner", 100), ("superadmin", 100), ("super_admin", 100), ("root", 100),
    ("admin", 90), ("administrator", 90),
    ("editor", 70), ("write", 60), ("writer", 60), ("contributor", 60),
    ("maintainer", 65), ("developer", 55), ("operator", 55),
    ("billing", 75),                       # billing admin is high-value
    ("iam", 95),                           # any IAM-management role is near-owner
    ("viewer", 30), ("reader", 30), ("read", 30), ("read_only", 30),
    ("guest", 10), ("none", 0),
)


class RoleModel:
    """Declared role→rank oracle. Built-in defaults + optional contract overrides."""

    def __init__(self, overrides: Optional[dict] = None):
        # overrides: {role_substring_or_exact: rank}
        self.overrides = {str(k).lower(): int(v) for k, v in (overrides or {}).items()}

    def rank(self, role: str) -> int:
        """Rank of a role string. Unknown roles get a conservative MID rank so an
        unknown grant is neither dismissed nor over-flagged; the Δstate confirmer
        still decides. Deterministic; no learning."""
        if not role:
            return 0
        r = str(role).lower()
        # exact override first, then substring override, then defaults
        if r in self.overrides:
            return self.overrides[r]
        for key, rank in self.overrides.items():
            if key in r:
                return rank
        for sub, rank in _DEFAULT_RANKS:
            if sub in r:
                return rank
        return 50      # unknown custom role → mid rank (conservative)


# --------------------------------------------------------------------------- #
# binding extraction from common IAM request/response shapes                  #
# --------------------------------------------------------------------------- #

# request paths/operations that EDIT the authority graph
_GRANT_MARKERS = (
    "setiampolicy", "addbinding", "createrole", "grantrole", "addmember",
    "putrolepolicy", "attachuserpolicy", "attachrolepolicy", "roleassignments",
    "addrole", "updateacl", "setacl", "add-iam-policy-binding",
)


def is_authority_grant(method: str, path: str, body) -> bool:
    """Does this request EDIT the authority graph? Detected by the conventional
    operation markers (GCP setIamPolicy, AWS Attach*Policy, Azure roleAssignments,
    generic ACL writes) or a body that carries role bindings on a mutating verb."""
    p = (path or "").lower()
    if any(m in p for m in _GRANT_MARKERS):
        return True
    if method.upper() in ("POST", "PUT", "PATCH") and _extract_bindings(body):
        # a mutating call whose body literally carries {role, members} bindings
        return True
    return False


def _extract_bindings(body) -> list:
    """Pull (role, [members]) pairs out of a body, tolerant of the common shapes:
      GCP:   {"policy": {"bindings": [{"role": "...", "members": [...]}]}}
      flat:  {"bindings": [{"role": "...", "members": [...]}]}
      AWS:   {"PolicyArn": "...", "RoleName"/"UserName": "..."} (role as the policy)
      Azure: {"roleDefinitionId": "...", "principalId": "..."}
    Returns a list of {"role": str, "members": [str]} dicts."""
    out: list = []
    if not isinstance(body, dict):
        return out
    # GCP / flat bindings
    policy = body.get("policy") if isinstance(body.get("policy"), dict) else body
    bindings = policy.get("bindings") if isinstance(policy, dict) else None
    if isinstance(bindings, list):
        for b in bindings:
            if isinstance(b, dict) and b.get("role"):
                members = b.get("members") or b.get("member") or []
                if isinstance(members, str):
                    members = [members]
                out.append({"role": str(b["role"]),
                            "members": [str(m) for m in members]})
    # AWS attach-policy shape: the policy arn IS the role
    if not out and (body.get("PolicyArn") or body.get("policyArn")):
        arn = str(body.get("PolicyArn") or body.get("policyArn"))
        member = (body.get("RoleName") or body.get("UserName")
                  or body.get("roleName") or body.get("userName") or "")
        out.append({"role": arn, "members": [str(member)] if member else []})
    # Azure role assignment
    if not out and body.get("roleDefinitionId"):
        member = body.get("principalId") or body.get("principal") or ""
        out.append({"role": str(body["roleDefinitionId"]),
                    "members": [str(member)] if member else []})
    return out


def extract_bindings(body) -> list:
    return _extract_bindings(body)


def member_matches_principal(member: str, principal_id: str) -> bool:
    """Is this binding member the acting principal (a self-grant)? Tolerant of the
    'user:alice@x', 'serviceAccount:…', 'principalId' encodings."""
    if not member or not principal_id:
        return False
    m = member.lower()
    p = principal_id.lower()
    tail = m.split(":")[-1]
    return p == m or p == tail or p in tail or tail in p
