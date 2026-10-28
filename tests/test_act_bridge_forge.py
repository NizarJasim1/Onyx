"""
FORGE — Δstate act-bridge regression (Broadcast-vs-Act nerve, step 3).

Locks the only place this nerve touches conviction: a confrontation becomes a finding
ONLY when two live reads prove the act contradicts the broadcast (the principal the field
was hidden from actually receives the owner's real value). Every B-guard abstains.
End-to-end through the REAL Confirmer (audited _read).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.act_bridge import ActBridge
from authpath.act_confront import Confrontation
from authpath.confirmer import Confirmer
from authpath.scope_guard import ScopeConfig, ScopeGuard
from authpath.models import HTTPRequest, HTTPResponse, Principal


def _H(m, p):
    return HTTPRequest(m, p, host="t.local")


class _Target:
    """doc:1 belongs to owner; `salary` is owner-private. Knobs model each guard case."""
    host = "t.local"

    def __init__(self, member_salary="leak", owner_salary=99000):
        self.member_salary = member_salary      # "leak" | None | <other value> | "none"
        self.owner_salary = owner_salary

    def send(self, req, principal):
        if req.path != "/doc/1":
            return HTTPResponse(404, {})
        base = {"id": "1", "title": "Q4"}
        if principal.pid == "owner":
            if self.owner_salary is not None:
                base["salary"] = self.owner_salary
        elif principal.pid == "member":
            if self.member_salary == "leak":
                base["salary"] = self.owner_salary
            elif self.member_salary == "none":
                base["salary"] = None
            elif self.member_salary is not None:
                base["salary"] = self.member_salary
        return HTTPResponse(200, base)


def _bridge(target, provision_owner=True):
    owner = Principal("owner", "Adm", {"Authorization": "Bearer o"})
    member = Principal("member", "Mem", {"Authorization": "Bearer m"})
    sg = ScopeGuard(ScopeConfig(allowed_hosts=["t.local"], dry_run=True,
                                automation_permitted=True))
    conf = Confirmer(target, {"owner": owner, "member": member}, sg)
    bi = {"u-member": member}
    if provision_owner:
        bi["u-owner"] = owner
    return ActBridge(conf, bi)


_CONF = Confrontation(kind="hidden_field", accessor="u-member", resource="doc:1",
                      verb="GET", declared="salary", owner_hint="u-owner")


def test_core_field_leak_confirmed():
    br = _bridge(_Target(member_salary="leak"))
    f = br.confirm_field_leak(_CONF, "u-owner", _H("GET", "/doc/1"))
    assert f is not None and f.field == "salary" and f.accessor == "u-member"


def test_correct_no_leak_abstains():
    br = _bridge(_Target(member_salary=None))
    assert br.confirm_field_leak(_CONF, "u-owner", _H("GET", "/doc/1")) is None


def test_b1_null_field_abstains():
    br = _bridge(_Target(member_salary="none"))
    assert br.confirm_field_leak(_CONF, "u-owner", _H("GET", "/doc/1")) is None
    assert any("not actually exposed" in w for _, w in br.abstained)


def test_b2_owner_not_provisioned_abstains():
    br = _bridge(_Target(member_salary="leak"), provision_owner=False)
    assert br.confirm_field_leak(_CONF, "u-owner", _H("GET", "/doc/1")) is None
    assert any("owner not provisioned" in w for _, w in br.abstained)


def test_b3_value_mismatch_abstains():
    """Member gets a salary value, but it differs from the owner's → not the owner's
    private datum (maybe the member's own) → abstain."""
    br = _bridge(_Target(member_salary=12345, owner_salary=99000))
    assert br.confirm_field_leak(_CONF, "u-owner", _H("GET", "/doc/1")) is None
    assert any("!= owner value" in w for _, w in br.abstained)


def test_separate_channel_no_findings_attr():
    br = _bridge(_Target())
    assert not hasattr(br, "findings")          # never writes the engine findings channel
