"""
Mass-assignment (write-side BOPLA) regression — CRUCIBLE problem #10 (first write capability).

A privilege-bound field (role-tied in observed self-bodies) that a member can WRITE and have
STICK on read-back is an escalation. A member-settable cosmetic field (display_name) and a
write that does not stick (server ignored) must abstain; the write is scope-gated so dry_run
abstains (zero-harm).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.mass_assign import role_tied_privileged_fields
from authpath.act_bridge import ActBridge
from authpath.scope_guard import ScopeGuard, ScopeConfig
from authpath.models import HTTPResponse, Principal


# ---- candidate selection -----------------------------------------------------------
def test_role_tied_selects_privilege_field_not_cosmetic():
    bodies = [
        ("admin",  {"id": "u-admin", "role": "admin",  "is_admin": True,  "display_name": "Admin"}),
        ("member", {"id": "u-alice", "role": "member", "is_admin": False, "display_name": "Alice"}),
        ("member", {"id": "u-bob",   "role": "member", "is_admin": False, "display_name": "Bob"}),
    ]
    fields = dict(role_tied_privileged_fields(bodies))
    assert fields.get("is_admin") is True          # privilege flag selected
    assert "display_name" not in fields            # cosmetic per-user field NOT selected
    assert "id" not in fields and "email" not in fields


def test_no_candidates_without_a_privileged_role():
    bodies = [("member", {"id": "a", "role": "member", "is_admin": False}),
              ("member", {"id": "b", "role": "member", "is_admin": False})]
    assert role_tied_privileged_fields(bodies) == []


# ---- write-then-read-back confirmation ----------------------------------------------
class _WriteTarget:
    """Models the server's profile state; a PATCH binds is_admin (the bug) but the read-back
    reflects `sticks` so we can test both the sticking and non-sticking cases."""
    host = "t.local"

    def __init__(self, sticks):
        self.sticks = sticks
        self.state = {"id": "u-alice", "role": "member", "is_admin": False}

    def send(self, req, principal):
        if req.method == "PATCH":
            if self.sticks and isinstance(req.body, dict):
                self.state.update({k: v for k, v in req.body.items()})
            return HTTPResponse(200, dict(self.state))
        return HTTPResponse(200, dict(self.state))


def _bridge(target):
    cfg = ScopeConfig(allowed_hosts=["t.local"], dry_run=False,
                      allow_destructive=True, automation_permitted=True)
    from authpath.confirmer import Confirmer
    conf = Confirmer.__new__(Confirmer)
    conf.scope = ScopeGuard(cfg)
    conf.target = target

    class _L:
        def acquire(self, host): return True
        def record(self, host, struck=False): pass
    conf.ledger = _L()
    return ActBridge(conf, {"u-alice": Principal("u-alice", "Alice",
                                                 {"Authorization": "Bearer a"})})


def test_mass_assignment_caught_when_value_sticks():
    br = _bridge(_WriteTarget(sticks=True))
    f = br.confirm_mass_assignment("u-alice", "/api/me", "is_admin", True, host="t.local")
    assert f is not None and f.kind == "mass_assignment" and f.field == "is_admin"


def test_abstain_when_write_does_not_stick():
    br = _bridge(_WriteTarget(sticks=False))
    assert br.confirm_mass_assignment("u-alice", "/api/me", "is_admin", True,
                                      host="t.local") is None


def test_abstain_under_dry_run():
    cfg = ScopeConfig(allowed_hosts=["t.local"], dry_run=True, automation_permitted=True)
    from authpath.confirmer import Confirmer
    conf = Confirmer.__new__(Confirmer)
    conf.scope = ScopeGuard(cfg)
    conf.target = _WriteTarget(sticks=True)

    class _L:
        def acquire(self, host): return True
        def record(self, host, struck=False): pass
    conf.ledger = _L()
    br = ActBridge(conf, {"u-alice": Principal("u-alice", "Alice", {"Authorization": "Bearer a"})})
    assert br.confirm_mass_assignment("u-alice", "/api/me", "is_admin", True,
                                      host="t.local") is None       # zero-harm: no write
    assert any("gated by scope" in why for _, why in br.abstained)
