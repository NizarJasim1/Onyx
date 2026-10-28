"""
RL14 regression suite — HIERARCHICAL AUTHORITY (resource ancestry).

ONYX's authority model was FLAT. Real cloud authority inherits down a resource
hierarchy (organization ⊐ folder ⊐ project ⊐ resource). RL14 derives the ancestry
structurally from the resource name and resolves a principal's effective rank as
the max over the node and its ancestors — which both SUPPRESSES false positives
(inherited admin access is legitimate) and SCOPES escalation (a grant at an
ancestor confers power over the whole subtree).

Properties under guard:
  1. PARSE      — resource name extracted from a path (version + verb stripped).
  2. ANCESTRY   — ordered ancestry chain; is_ancestor relation.
  3. RANK       — effective rank inherits from an ancestor binding; global back-compat.
  4. FP-SUPPRESS— an ancestor-admin granting at a descendant is CLEAN.
  5. SCOPE-ESC  — a low-rank actor granting at an ANCESTOR is a finding.
  6. BACK-COMPAT— the flat RL13 declaration form ({pid:[roles]}) still works.
"""
from authpath.models import Principal, HTTPRequest, HTTPResponse
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.economy import BudgetLedger
from authpath.transport import make_exchange
from authpath.iam import RoleModel
from authpath.hierarchy import (parse_resource_name, ancestry, is_ancestor,
                                effective_rank_at, subtree_scope)

A = Principal("A", "Alice")
O = Principal("owner", "Owner")
_RM = RoleModel()


# --- (1) PARSE -------------------------------------------------------------- #
def test_parse_resource_name():
    assert parse_resource_name("/v1/projects/P1/datasets/D1:setIamPolicy") == "projects/P1/datasets/D1"
    assert parse_resource_name("/v1/organizations/123:getIamPolicy") == "organizations/123"


# --- (2) ANCESTRY ----------------------------------------------------------- #
def test_ancestry_chain():
    chain = ancestry("projects/P1/datasets/D1")
    assert chain[0] == "projects/P1/datasets/D1"
    assert "projects/P1" in chain
    assert "projects" in chain


def test_is_ancestor():
    assert is_ancestor("projects/P1", "projects/P1/datasets/D1")
    assert is_ancestor("projects/P1/datasets/D1", "projects/P1/datasets/D1")   # self
    assert not is_ancestor("projects/P2", "projects/P1/datasets/D1")


# --- (3) EFFECTIVE RANK ----------------------------------------------------- #
def test_effective_rank_inherits_from_ancestor():
    # name-encoded inheritance: binding at projects/P1 covers a sub-resource
    binding = {"projects/P1": ["roles/owner"]}
    r = effective_rank_at(binding, "projects/P1/datasets/D1", _RM)
    assert r == _RM.rank("roles/owner")


def test_effective_rank_inherits_via_declared_parent():
    # org→project link is NOT name-encoded; declared parent_map supplies it
    binding = {"organizations/123": ["roles/owner"]}
    pm = {"projects/P1": "organizations/123"}
    r = effective_rank_at(binding, "projects/P1", _RM, pm)
    assert r == _RM.rank("roles/owner")


def test_effective_rank_not_from_descendant():
    # viewer at a project gives NOTHING at the org (an ancestor)
    binding = {"projects/P1": ["roles/viewer"]}
    assert effective_rank_at(binding, "organizations/123", _RM) is None


def test_effective_rank_global_back_compat():
    # the flat RL13 list form applies everywhere
    assert effective_rank_at(["roles/owner"], "projects/P1", _RM) == _RM.rank("roles/owner")


def test_subtree_scope_labels():
    assert "organization" in subtree_scope("organizations/123").lower()
    assert "project" in subtree_scope("projects/P1").lower()


# --- engine helpers --------------------------------------------------------- #
def _app(after_role, member):
    class App:
        def __init__(self):
            self.g = False
        def send(self, req, p):
            if "setIamPolicy" in req.path:
                self.g = True
                return HTTPResponse(200, {"bindings": [{"role": after_role, "members": [member]}]})
            if "getIamPolicy" in req.path:
                b = ([{"role": after_role, "members": [member]}] if self.g
                     else [{"role": "roles/viewer", "members": [member]}])
                return HTTPResponse(200, {"bindings": b})
            return HTTPResponse(404, {})
    return App()


def _run(actor_roles, path, role, member, parents=None):
    t = _app(role, member)
    contract = {"actor_roles": {"A": actor_roles}}
    if parents:
        contract["resource_parents"] = parents
    eng = AuthPathEngine(t, {"A": A, "owner": O},
                         ScopeConfig(allowed_hosts=["h"], dry_run=False),
                         contract=contract, ledger=BudgetLedger.unbounded())
    ex = make_exchange(t, HTTPRequest("POST", path,
                       body={"policy": {"bindings": [{"role": role, "members": [member]}]}},
                       host="h"), A)
    return eng.analyze(ex).outcome


# --- (4) FALSE-POSITIVE SUPPRESSION ---------------------------------------- #
def test_ancestor_admin_granting_at_descendant_is_clean():
    # name-encoded: owner at projects/P1 grants editor at a sub-resource → clean
    out = _run({"projects/P1": ["roles/owner"]},
               "/v1/projects/P1/datasets/D1:setIamPolicy", "roles/editor", "user:victim")
    assert out != "finding"


def test_org_owner_self_grant_at_child_is_clean():
    # the dangerous FP: org-owner SELF-granting owner at a child project is
    # legitimate (inherited) and must NOT be flagged — needs declared parent link.
    out = _run({"organizations/123": ["roles/owner"]},
               "/v1/projects/P1:setIamPolicy", "roles/owner", "user:A",
               parents={"projects/P1": "organizations/123"})
    assert out != "finding"


# --- (5) SCOPE ESCALATION --------------------------------------------------- #
def test_low_rank_actor_granting_at_ancestor_is_finding():
    out = _run({"projects/P1": ["roles/viewer"]},
               "/v1/organizations/123:setIamPolicy", "roles/owner", "user:A")
    assert out == "finding"          # escalation over the whole org


def test_scoped_self_escalation_is_finding():
    out = _run({"projects/P1": ["roles/viewer"]},
               "/v1/projects/P1:setIamPolicy", "roles/owner", "user:A")
    assert out == "finding"


# --- (6) BACK-COMPAT with the flat RL13 form -------------------------------- #
def test_flat_declaration_still_works():
    # owner declared globally (RL13 list form) → granting editor anywhere is clean
    out = _run(["roles/owner"], "/v1/projects/P1:setIamPolicy", "roles/editor", "user:victim")
    assert out != "finding"
