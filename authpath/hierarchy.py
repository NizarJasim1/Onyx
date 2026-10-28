"""
authpath.hierarchy — RESOURCE-HIERARCHY AUTHORITY (RL14).

ONYX modelled authority FLAT: a principal either holds an object or it does not.
Real cloud authority is HIERARCHICAL — a resource sits in an ancestry chain
(organization ⊐ folder ⊐ project ⊐ resource) and a role bound at any ANCESTOR
inherits down to every descendant. Without this model ONYX both risks FALSE
POSITIVES (reporting legitimate inherited access as IDOR) and MISSES SCOPE (a grant
at an organization escalates authority over everything beneath it, not one object).

This module derives the ancestry DETERMINISTICALLY from the resource name (RL1: a
structural parse, never induced) and resolves a principal's EFFECTIVE rank at a node
as the maximum rank it holds at that node OR any ancestor.

It changes no verdict on its own; it feeds the RL13 AuthorityGrantLaw so that:
  * an admin holding authority at an ancestor granting at a descendant is RECOGNISED
    as legitimate (false-positive suppression), and
  * an actor granting at a node ABOVE where it holds authority is recognised as an
    escalation over the whole subtree (scope).
"""
from __future__ import annotations

import re
from typing import Optional

# GCP-style hierarchy collectors, ordered high → low authority scope. The pattern
# `collection/{id}` repeats; ancestry is every prefix down to the full name.
_LEVEL_ORDER = ("organizations", "folders", "projects")


def parse_resource_name(path_or_name: str) -> str:
    """Extract the canonical resource name from a request path. Strips a leading
    version prefix and any GCP method suffix (':setIamPolicy', ':getIamPolicy').
      '/v1/projects/P1/datasets/D1:setIamPolicy' -> 'projects/P1/datasets/D1'
      '//cloudresourcemanager.googleapis.com/organizations/123' -> 'organizations/123'
    """
    if not path_or_name:
        return ""
    s = str(path_or_name)
    s = s.split("://", 1)[-1]               # drop scheme if any
    s = re.sub(r":[a-zA-Z][a-zA-Z0-9]*$", "", s)   # drop ':setIamPolicy' style verb
    # drop a leading host (contains a dot before the first path segment)
    s = re.sub(r"^[^/]*\.[^/]*/", "", s)
    s = s.strip("/")
    # drop a leading version segment like v1 / v1beta1
    parts = s.split("/")
    if parts and re.fullmatch(r"v\d[\w]*", parts[0]):
        parts = parts[1:]
    # keep from the first recognised collection onward (so 'api/projects/..' works)
    for i, seg in enumerate(parts):
        if seg in _LEVEL_ORDER or (i + 1 < len(parts) and seg in _LEVEL_ORDER):
            parts = parts[i:]
            break
    return "/".join(parts)


def ancestry(resource_name: str, parent_map: Optional[dict] = None) -> list:
    """Ordered ancestry of a resource, FROM the resource UP to the root. Combines
    two sources, both declarative/structural (RL1, never induced):
      * NAME-ENCODED nesting — 'projects/P1/datasets/D1' ⊐ 'projects/P1' ⊐ 'projects';
      * DECLARED parent links — `parent_map` maps a resource to its parent where the
        link is NOT in the name (e.g. {'projects/P1': 'organizations/123'}), as the
        org→folder→project hierarchy is not encoded in a project's own name.
    """
    name = parse_resource_name(resource_name)
    if not name:
        return []
    parts = name.split("/")
    out = [name]
    # name-encoded prefixes (collection/{id} boundaries and bare collections)
    for cut in range(len(parts) - 1, 0, -1):
        prefix = "/".join(parts[:cut])
        if prefix and prefix not in out:
            out.append(prefix)
    # follow declared parent links upward from every node discovered so far
    pm = {parse_resource_name(k): parse_resource_name(v)
          for k, v in (parent_map or {}).items()}
    i = 0
    while i < len(out):
        parent = pm.get(out[i])
        if parent and parent not in out:
            out.append(parent)
            # also add the parent's own name-encoded prefixes
            pp = parent.split("/")
            for cut in range(len(pp) - 1, 0, -1):
                pre = "/".join(pp[:cut])
                if pre and pre not in out:
                    out.append(pre)
        i += 1
    return out


def is_ancestor(maybe_ancestor: str, resource_name: str, parent_map: Optional[dict] = None) -> bool:
    """Is `maybe_ancestor` the resource itself or an ancestor of it?"""
    a = parse_resource_name(maybe_ancestor)
    if not a:
        return False
    return a in ancestry(resource_name, parent_map)


def normalize_bindings(actor_binding) -> dict:
    """Normalise the declared actor binding form into {resource_name: [roles]}.
    Accepts:
      * a list of role strings  -> treated as GLOBAL (applies at every node) under
        the sentinel key '' (back-compat with the flat RL13 declaration);
      * a dict {resource: [roles]} -> scoped bindings (RL14).
    """
    if actor_binding is None:
        return {}
    if isinstance(actor_binding, list):
        return {"": [str(r) for r in actor_binding]}
    if isinstance(actor_binding, dict):
        out = {}
        for res, roles in actor_binding.items():
            if isinstance(roles, str):
                roles = [roles]
            out[parse_resource_name(res) if res else ""] = [str(r) for r in (roles or [])]
        return out
    return {}


def effective_rank_at(actor_binding, grant_resource: str, role_model,
                      parent_map: Optional[dict] = None) -> Optional[int]:
    """The actor's EFFECTIVE rank at `grant_resource`: the max rank over roles it
    holds at that resource OR any ancestor of it (inheritance, including declared
    parent links), plus any GLOBAL binding. None when nothing applies (unknown)."""
    scoped = normalize_bindings(actor_binding)
    if not scoped:
        return None
    chain = set(ancestry(grant_resource, parent_map))
    ranks = []
    for res, roles in scoped.items():
        applies = (res == "") or (res in chain)   # global, exact, or ancestor
        if applies:
            ranks.extend(role_model.rank(r) for r in roles)
    return max(ranks) if ranks else None


def subtree_scope(grant_resource: str) -> str:
    """Human label for the breadth a grant at this node confers, for evidence.
    A grant at an organization/folder inherits to all descendants."""
    name = parse_resource_name(grant_resource)
    head = name.split("/")[0] if name else ""
    return {
        "organizations": "the ENTIRE organization and every folder/project/resource beneath it",
        "folders": "the folder and every project/resource beneath it",
        "projects": "the project and every resource beneath it",
    }.get(head, "the target resource")
