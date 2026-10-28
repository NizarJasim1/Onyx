"""
BFLA (function-escalation) detection regression — CRUCIBLE problem #3.

Pins three guarantees:
  1. the broadcast guard surfaces an OWNERSHIP-tied ACTION difference as a candidate even
     at the same role, WITHOUT surfacing any field difference (field FP guard untouched);
  2. confirm_action confirms a BFLA only when the mutation actually executes (2xx) AND the
     scope is armed for destructive testing;
  3. under dry_run / unarmed scope the mutation is GATED → abstain (the zero-harm red line).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.broadcast import BroadcastLedger
from authpath.act_bridge import ActBridge
from authpath.act_confront import Confrontation
from authpath.scope_guard import ScopeGuard, ScopeConfig
from authpath.models import HTTPRequest, HTTPResponse, Principal


# ---- guard: ownership-tied action candidate, no field leakage --------------------
def test_broadcast_guard_surfaces_ownership_tied_action_only():
    L = BroadcastLedger()
    L.note_declared_role("owner", "member")
    L.note_declared_role("other", "member")          # SAME role
    L.record("owner", "doc:4", HTTPResponse(200, {
        "id": "4", "owner_id": "owner", "secret": "x",
        "_links": {"self": {}, "delete": {}, "edit": {}}}))
    L.record("other", "doc:4", HTTPResponse(200, {
        "id": "4", "owner_id": "owner",
        "_links": {"self": {}}}))
    cands = L.broadcast_difference_candidates()
    assert len(cands) == 1
    c = cands[0]
    assert set(c["actions_only_a"]) >= {"delete", "edit"}    # action delta surfaced
    assert c["fields_only_a"] == [] and c["fields_only_b"] == []   # NO field leak


def test_broadcast_guard_still_blocks_same_role_field_diff():
    """The field FP guard must be untouched: same-role field difference → no candidate."""
    L = BroadcastLedger()
    L.note_declared_role("a", "member")
    L.note_declared_role("b", "member")
    L.record("a", "doc:1", HTTPResponse(200, {"id": "1", "owner_id": "x", "beta": "on"}))
    L.record("b", "doc:1", HTTPResponse(200, {"id": "1", "owner_id": "x"}))
    assert L.broadcast_difference_candidates() == []


# ---- confirm_action: armed catches, dry_run abstains -----------------------------
class _Target:
    """Records nothing destructive for real — returns a 2xx for the non-owner DELETE,
    simulating a server that wrongly executes the function (BFLA)."""
    host = "t.local"

    def send(self, req, principal):
        if req.method == "DELETE":
            return HTTPResponse(200, {"deleted": req.path})
        return HTTPResponse(200, {})


def _bridge(dry_run):
    cfg = ScopeConfig(allowed_hosts=["t.local"], dry_run=dry_run,
                      allow_destructive=not dry_run, automation_permitted=True)
    from authpath.confirmer import Confirmer
    # minimal confirmer: only _read (scope + ledger + target.send) is used by confirm_action
    conf = Confirmer.__new__(Confirmer)
    conf.scope = ScopeGuard(cfg)
    conf.target = _Target()

    class _L:                                  # always-grant budget ledger
        def acquire(self, host): return True
        def record(self, host, struck=False): pass
    conf.ledger = _L()
    br = ActBridge(conf, {"u-alice": Principal("u-alice", "Alice",
                                               {"Authorization": "Bearer a"})})
    return br


def _conf():
    return Confrontation(kind="hidden_action", accessor="u-alice", resource="doc:4",
                         verb="DELETE", declared="delete", owner_hint="u-bob")


def test_confirm_action_catches_bfla_when_armed():
    br = _bridge(dry_run=False)
    mut = HTTPRequest("DELETE", "/api/docs/4", host="t.local")
    f = br.confirm_action(_conf(), mut)
    assert f is not None and f.kind == "function_escalation" and f.resource == "doc:4"


def test_confirm_action_abstains_under_dry_run():
    br = _bridge(dry_run=True)
    mut = HTTPRequest("DELETE", "/api/docs/4", host="t.local")
    assert br.confirm_action(_conf(), mut) is None          # zero-harm: gated, no mutation
    assert any("gated by scope" in why for _, why in br.abstained)


# ---- verb-tunneling generalization (CRUCIBLE problem #7) --------------------------
class _GateTarget:
    """Plain DELETE is gated (403 to the non-owner); a verb-tunnel (POST + override)
    bypasses the gate (200) — the verb-tunneling BFLA."""
    host = "t.local"

    def send(self, req, principal):
        if req.method == "DELETE":
            return HTTPResponse(403, {"error": "requires role owner"})
        if req.method == "POST" and any(
                h.lower() in ("x-http-method-override", "x-http-method", "x-method-override")
                for h in getattr(req, "headers", {})):
            return HTTPResponse(200, {"deleted": req.path, "via": "override"})
        return HTTPResponse(404, {})


class _SafeGateTarget:
    """Both plain DELETE and the tunnel are gated (403) — no BFLA, must abstain."""
    host = "t.local"

    def send(self, req, principal):
        return HTTPResponse(403, {"error": "requires role owner"})


def _bridge_for(target_cls, dry_run):
    cfg = ScopeConfig(allowed_hosts=["t.local"], dry_run=dry_run,
                      allow_destructive=not dry_run, automation_permitted=True)
    from authpath.confirmer import Confirmer
    conf = Confirmer.__new__(Confirmer)
    conf.scope = ScopeGuard(cfg)
    conf.target = target_cls()

    class _L:
        def acquire(self, host): return True
        def record(self, host, struck=False): pass
    conf.ledger = _L()
    return ActBridge(conf, {"u-alice": Principal("u-alice", "Alice",
                                                 {"Authorization": "Bearer a"})})


def test_verb_tunnel_bfla_caught_when_plain_is_gated():
    br = _bridge_for(_GateTarget, dry_run=False)
    mut = HTTPRequest("DELETE", "/api/docs/3", host="t.local")
    f = br.confirm_action(_conf(), mut)
    assert f is not None and f.kind == "function_escalation"
    assert "verb-tunnel" in f.why


def test_no_bfla_when_both_plain_and_tunnel_gated():
    br = _bridge_for(_SafeGateTarget, dry_run=False)
    mut = HTTPRequest("DELETE", "/api/docs/3", host="t.local")
    assert br.confirm_action(_conf(), mut) is None          # gate honored on every vector


def test_verb_tunnel_abstains_under_dry_run():
    br = _bridge_for(_GateTarget, dry_run=True)
    mut = HTTPRequest("DELETE", "/api/docs/3", host="t.local")
    assert br.confirm_action(_conf(), mut) is None          # zero-harm: no mutation tried
