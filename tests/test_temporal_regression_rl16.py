"""
RL16 — TEMPORAL AUTHORIZATION-SHAPE REGRESSION regression suite.

Each test locks one guarantee CRUCIBLE forced before this touched the codebase.
The invariant: a sensitive field that was structurally WITHHELD from a principal at
T1 but is POPULATED at T2 — with NO declared role change in between — is a
Δstate-confirmed authorization regression, and nothing else is. Specifically:

  * positive            — ssn null@T1 → populated@T2 (no role change) → finding
  * role-epoch guard    — a legitimate promotion widening the view → silent (the
                          single worst false positive, defused)
  * sensitive-only      — a non-sensitive field going null→populated → silent
  * live-confirmation   — a one-off blip that does not reproduce on read-back → silent
  * first-blind-window  — the very first observation has no prior → silent (fail-safe)
  * additive isolation  — flag OFF ⇒ byte-identical (no finding at all)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.transport import make_exchange
from authpath.models import HTTPRequest, HTTPResponse, Principal
from authpath.temporal_shape import AuthShapeLedger
from authpath.structural import AbsenceState

B = Principal("B", "Bob")


def _engine(target, temporal=True, contract=None):
    scope = ScopeConfig(allowed_hosts=["demo.local"], dry_run=True,
                        automation_permitted=True)
    eng = AuthPathEngine(target, {"B": B}, scope, contract=contract or {})
    eng.temporal_shape = temporal
    return eng


class _DriftTarget:
    """A profile whose `ssn` filter regresses on the Nth read (deploy drift).
    `mode` selects what changes: 'sensitive' (ssn), 'nonsensitive' (nickname),
    or 'blip' (populated once at T2 but withheld again on the confirm read-back)."""
    host = "demo.local"

    def __init__(self, mode="sensitive"):
        self.mode = mode
        self._reads = 0

    def send(self, req, principal):
        m, p = req.method.upper(), req.path
        if m == "GET" and p == "/api/profile2/900":
            self._reads += 1
            if self.mode == "sensitive":
                leaked = self._reads >= 2
                return HTTPResponse(200, {"id": "900", "holder": "self",
                                          "ssn": ("123-45-6789" if leaked else None)})
            if self.mode == "nonsensitive":
                leaked = self._reads >= 2
                return HTTPResponse(200, {"id": "900", "holder": "self",
                                          "nickname": ("bobby" if leaked else None)})
            if self.mode == "blip":
                # populated only on the 2nd read (T2); withheld again on the 3rd
                # (the confirmer's read-back) → must abstain (not live).
                leaked = (self._reads == 2)
                return HTTPResponse(200, {"id": "900", "holder": "self",
                                          "ssn": ("123-45-6789" if leaked else None)})
        return HTTPResponse(404, {"error": "no route"})


def _t1_t2(target):
    eng = _engine(target)
    eng.observe(make_exchange(target, HTTPRequest("GET", "/api/profile2/900"), B))  # T1
    tr = eng.analyze(make_exchange(target, HTTPRequest("GET", "/api/profile2/900"), B))  # T2
    return eng, tr


# ----------------------------- the guarantees ------------------------------ #

def test_sensitive_regression_confirms():
    eng, tr = _t1_t2(_DriftTarget("sensitive"))
    assert tr.outcome == "finding", f"expected finding, got {tr.outcome}"
    f = eng.findings[-1]
    assert f.effect.value == "AUTH_REGRESSION"
    assert "ssn" in (f.state_proof.after or "")


def test_nonsensitive_regression_is_silent():
    eng, tr = _t1_t2(_DriftTarget("nonsensitive"))
    assert tr.outcome != "finding", "a non-sensitive field widening must NOT fire"


def test_transient_blip_not_confirmed():
    eng, tr = _t1_t2(_DriftTarget("blip"))
    assert tr.outcome != "finding", "a field that does not reproduce on read-back must abstain"


def test_first_observation_is_blind_silent():
    """The very first read has no prior snapshot → must abstain (fail-safe)."""
    t = _DriftTarget("sensitive")
    eng = _engine(t)
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/profile2/900"), B))  # T1 only
    assert tr.outcome != "finding"


def test_flag_off_is_byte_identical_silent():
    t = _DriftTarget("sensitive")
    eng = _engine(t, temporal=False)
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/profile2/900"), B))
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/profile2/900"), B))
    assert tr.outcome != "finding"
    assert not any(f.effect.value == "AUTH_REGRESSION" for f in eng.findings)


# ----------------- the role-epoch guard (worst false positive) ------------- #

class _PromoteTarget:
    """clearance.secret is withheld until a promotion, then populated."""
    host = "demo.local"

    def __init__(self):
        self._promoted = {}

    def send(self, req, principal):
        m, p = req.method.upper(), req.path
        if m == "POST" and p == "/api/promote":
            self._promoted[principal.pid] = True
            return HTTPResponse(200, {"promoted": principal.pid})
        if m == "GET" and p == "/api/clearance/300":
            pop = self._promoted.get(principal.pid, False)
            return HTTPResponse(200, {"id": "300", "level": "L2",
                                      "secret": ("topsecret" if pop else None)})
        return HTTPResponse(404, {"error": "no route"})


def test_legitimate_promotion_is_not_a_regression():
    contract = {"POST /api/promote": {"effect": "NONE"},
                "GET /api/clearance/{id}": {"effect": "OBJECT_ACCESS"},
                "role_change_events": [
                    {"endpoint": "POST /api/promote",
                     "affects_principals": ["B"], "kind": "role_promote"}]}
    t = _PromoteTarget()
    eng = _engine(t, contract=contract)
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/clearance/300"), B))      # T1 (epoch 0)
    eng.analyze(make_exchange(t, HTTPRequest("POST", "/api/promote"), B))           # epoch → 1
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/clearance/300"), B)) # T2 (epoch 1)
    assert tr.outcome != "finding", "a promotion across the snapshots must suppress the comparison"


# --------------------------- ledger unit guarantees ------------------------ #

def test_ledger_detects_withheld_to_populated_only():
    led = AuthShapeLedger()
    req = HTTPRequest("GET", "/api/profile2/900")
    led.record(req, HTTPResponse(200, {"id": "900", "ssn": None}), "B", role_epoch=0)
    regs = led.regressions(req, HTTPResponse(200, {"id": "900", "ssn": "X"}), "B", role_epoch=0)
    assert [r.path.split(".")[-1] for r in regs] == ["ssn"]


def test_ledger_same_populated_value_no_regression():
    led = AuthShapeLedger()
    req = HTTPRequest("GET", "/api/profile2/900")
    led.record(req, HTTPResponse(200, {"id": "900", "ssn": "A"}), "B", role_epoch=0)
    regs = led.regressions(req, HTTPResponse(200, {"id": "900", "ssn": "B"}), "B", role_epoch=0)
    assert regs == []          # value changed but it was always exposed — not a regression


def test_ledger_role_epoch_change_suppresses():
    led = AuthShapeLedger()
    req = HTTPRequest("GET", "/api/clearance/300")
    led.record(req, HTTPResponse(200, {"id": "300", "secret": None}), "B", role_epoch=0)
    regs = led.regressions(req, HTTPResponse(200, {"id": "300", "secret": "X"}), "B", role_epoch=1)
    assert regs == []
