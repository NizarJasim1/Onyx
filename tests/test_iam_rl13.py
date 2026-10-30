"""
RL13 regression suite — AUTHORITY-GRANT CONSERVATION (IAM privilege escalation).

ONYX modelled authority as a fixed envelope the actor operates WITHIN. IAM
escalation is a WRITE to the authority graph (grant a role to a member). RL13 adds
the AUTHORITY_GRANT effect-class, a DECLARED role-rank model (RL1 — no induction),
a conservation law, and a Δstate confirmer that proves the binding PERSISTED.

Properties under guard:
  1. ROLE MODEL — declared rank ladder + overrides; unknown role → conservative mid.
  2. BINDINGS   — extracted across GCP / flat / AWS / Azure shapes.
  3. DETECTION  — setIamPolicy / role-binding bodies classify as AUTHORITY_GRANT.
  4. SELF-ESC   — actor grants ITSELF a privileged role → confirmed by Δstate.
  5. LATERAL    — actor grants a role ABOVE its declared rank to another member.
  6. NO-FP      — self-grant of a non-privileged role within rank → clean.
  7. NO-PERSIST — a grant that does NOT show up in the read-back → abstain.
  8. BYTE-IDENT — no IAM traffic ⇒ AUTHORITY_GRANT never fires (suite stays green).
"""
from authpath.models import Principal, HTTPRequest, HTTPResponse
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.economy import BudgetLedger
from authpath.transport import make_exchange
from authpath.iam import (RoleModel, is_authority_grant, extract_bindings,
                          member_matches_principal)

A = Principal("A", "Alice")
O = Principal("owner", "Owner")


# --- (1) ROLE MODEL --------------------------------------------------------- #
def test_role_rank_ladder():
    rm = RoleModel()
    assert rm.rank("roles/owner") > rm.rank("roles/editor") > rm.rank("roles/viewer")
    assert rm.rank("roles/owner") == 100 and rm.rank("roles/viewer") == 30


def test_role_rank_override_and_unknown():
    rm = RoleModel({"custom/superpower": 99})
    assert rm.rank("custom/superpower") == 99
    assert rm.rank("totally-unknown-role") == 50      # conservative mid


# --- (2) BINDING EXTRACTION ------------------------------------------------- #
def test_extract_bindings_gcp_and_flat():
    gcp = {"policy": {"bindings": [{"role": "roles/owner", "members": ["user:a"]}]}}
    flat = {"bindings": [{"role": "roles/editor", "members": ["user:b"]}]}
    assert extract_bindings(gcp)[0]["role"] == "roles/owner"
    assert extract_bindings(flat)[0]["members"] == ["user:b"]


def test_extract_bindings_aws_azure():
    aws = {"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "RoleName": "r1"}
    azure = {"roleDefinitionId": "/.../Owner", "principalId": "p1"}
    assert extract_bindings(aws)[0]["members"] == ["r1"]
    assert extract_bindings(azure)[0]["role"].endswith("Owner")


def test_member_matches_principal():
    assert member_matches_principal("user:A", "A")
    assert member_matches_principal("serviceAccount:svc@x", "svc@x")
    assert not member_matches_principal("user:bob", "A")


# --- (3) DETECTION ---------------------------------------------------------- #
def test_is_authority_grant_detection():
    assert is_authority_grant("POST", "/v1/projects/p:setIamPolicy", {})
    assert is_authority_grant("POST", "/x", {"bindings": [{"role": "r", "members": ["m"]}]})
    assert not is_authority_grant("GET", "/v1/projects/p", {})


# --- helpers ---------------------------------------------------------------- #
class _IAMApp:
    """Serves setIamPolicy (records the grant) and a getIamPolicy read-back that
    reflects whether the grant persisted."""
    def __init__(self, before_role, after_role, member="user:A"):
        self.before, self.after, self.member, self.granted = before_role, after_role, member, False
    def send(self, req, p):
        if "setIamPolicy" in req.path:
            self.granted = True
            return HTTPResponse(200, {"bindings": [{"role": self.after, "members": [self.member]}]})
        if "getIamPolicy" in req.path:
            role = self.after if self.granted else self.before
            return HTTPResponse(200, {"bindings": [{"role": role, "members": [self.member]}]})
        return HTTPResponse(404, {})


def _grant(eng, t, role, member="user:A", path="/v1/projects/p1:setIamPolicy"):
    ex = make_exchange(t, HTTPRequest("POST", path,
                       body={"policy": {"bindings": [{"role": role, "members": [member]}]}},
                       host="h"), A)
    return eng.analyze(ex)


def _engine(t, contract=None):
    return AuthPathEngine(t, {"A": A, "owner": O},
                          ScopeConfig(allowed_hosts=["h"], dry_run=False),
                          contract=contract or {}, ledger=BudgetLedger.unbounded())


# --- (4) SELF-ESCALATION confirmed by Δstate -------------------------------- #
def test_self_escalation_to_owner_confirmed():
    t = _IAMApp("roles/viewer", "roles/owner")
    eng = _engine(t)
    tr = _grant(eng, t, "roles/owner")
    assert tr.outcome == "finding"
    assert eng.findings[0].impact.value.startswith("Privilege Escalation / Authority-Graph")


# --- (5) LATERAL escalation (declared actor rank) --------------------------- #
def test_lateral_grant_above_held_rank():
    t = _IAMApp("roles/viewer", "roles/editor", member="user:victim")
    eng = _engine(t, contract={"actor_roles": {"A": ["roles/viewer"]}})
    tr = _grant(eng, t, "roles/editor", member="user:victim")
    assert tr.outcome == "finding"


# --- (6) NO FALSE POSITIVE -------------------------------------------------- #
def test_self_grant_nonprivileged_is_clean():
    t = _IAMApp("roles/viewer", "roles/viewer")
    eng = _engine(t)
    tr = _grant(eng, t, "roles/viewer")
    assert tr.outcome != "finding"


def test_grant_within_held_rank_is_clean():
    # actor declared as owner granting editor (below its own rank) — legitimate admin
    t = _IAMApp("roles/viewer", "roles/editor", member="user:victim")
    eng = _engine(t, contract={"actor_roles": {"A": ["roles/owner"]}})
    tr = _grant(eng, t, "roles/editor", member="user:victim")
    assert tr.outcome != "finding"


# --- (7) GRANT THAT DOES NOT PERSIST → abstain ------------------------------ #
def test_grant_not_persisted_abstains():
    class NoPersist:
        def send(self, req, p):
            if "setIamPolicy" in req.path:
                return HTTPResponse(200, {"ok": True})          # 200 but...
            if "getIamPolicy" in req.path:
                return HTTPResponse(200, {"bindings": [{"role": "roles/viewer",
                                                        "members": ["user:A"]}]})  # never owner
            return HTTPResponse(404, {})
    t = NoPersist()
    eng = _engine(t)
    tr = _grant(eng, t, "roles/owner")
    assert tr.outcome != "finding"      # status 200 alone is not proof (RL3)


# --- (8) BYTE-IDENTICAL guard ----------------------------------------------- #
def test_non_iam_traffic_never_triggers_grant_law():
    class Plain:
        def send(self, req, p):
            return HTTPResponse(200, {"id": "1", "name": "x"})
    t = Plain()
    eng = _engine(t)
    ex = make_exchange(t, HTTPRequest("POST", "/api/items", body={"name": "x"}, host="h"), A)
    eng.analyze(ex)
    # whatever the outcome, it is NOT an IAM-escalation finding
    assert not any(getattr(f, "impact", None) and "IAM" in f.impact.value for f in eng.findings)
