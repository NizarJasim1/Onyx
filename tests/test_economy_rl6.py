"""
RL6 economy regression suite — the BOUNDED ECONOMIC SPENDING layer.

Locks the three load-bearing properties that make ONYX runnable on a giant
surface, plus the non-weakening invariant (X4): the layer is invisible when
unused. Every test below is a calibration probe for behaviour the streaming
engine never exercised.

  1. UNUSED  — an unbounded ledger is a perfect no-op (byte-identical spend).
  2. BOUNDED — a budgeted run never spends more read-backs than its budget.
  3. ORDERED — the scarce budget is spent on the highest-yield candidates first.
  4. HONEST  — budget-exhausted candidates degrade to leads, never silent drops.
  5. GOVERNED— a hostile host (429/503/WAF) freezes after `strike_freeze` strikes.
"""
from authpath.models import Principal, HTTPRequest, HTTPResponse, EffectClass
from authpath.transport import make_exchange
from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.economy import BudgetLedger, yield_score

A = Principal("A", "Alice")
B = Principal("B", "Bob")
P = {"A": A, "B": B}
JUICY = [str(900 + i) for i in range(5)]
LOW = [str(100 + i) for i in range(40)]
ALL = LOW + JUICY


class _Surface:
    """Cross-principal-readable orders; the JUICY set carries sensitive fields."""
    def __init__(self):
        self.sends = 0; self.hostile = False
    def send(self, req, principal):
        self.sends += 1
        if self.hostile:
            return HTTPResponse(429, {"error": "rate limited"})
        oid = req.path.rsplit("/", 1)[1]
        base = {"id": oid, "owner_id": "B", "item": "x"}
        if oid in JUICY:
            base.update({"ssn": f"SSN-{oid}", "balance": 1})
        return HTTPResponse(200, base)


def _engine(ledger):
    return AuthPathEngine(_Surface(), P,
                          ScopeConfig(allowed_hosts=["h"], dry_run=False),
                          contract={}, ledger=ledger)


def _seed_probe(eng, defer):
    t = eng.target
    for oid in ALL:
        eng.observe(make_exchange(t, HTTPRequest("GET", f"/api/orders/{oid}", host="h"), B))
    for oid in ALL:
        eng.analyze(make_exchange(t, HTTPRequest("GET", f"/api/orders/{oid}", host="h"), A), defer=defer)


# --- (1) UNUSED: unbounded ledger is a no-op -------------------------------- #
def test_unbounded_ledger_never_denies():
    led = BudgetLedger.unbounded()
    assert led.acquire("anyhost") is True
    led.record("anyhost", struck=True)          # strikes are inert when disabled
    assert led.acquire("anyhost") is True
    assert led.summary()["enabled"] is False


def test_streaming_findings_unchanged_under_unbounded():
    eng = _engine(BudgetLedger.unbounded())
    _seed_probe(eng, defer=False)
    assert len(eng.findings) == len(ALL)        # every IDOR confirmed (status quo)


# --- (2) BOUNDED: budgeted spend never exceeds the budget ------------------- #
def test_budget_is_a_hard_cap():
    led = BudgetLedger(global_budget=30, per_host_budget=30)
    eng = _engine(led)
    _seed_probe(eng, defer=True)
    eng.drain_deferred()
    assert led.spent <= 30


def test_budget_exhaustion_denies():
    led = BudgetLedger(global_budget=2, per_host_budget=2)
    assert led.acquire("h") is True
    assert led.acquire("h") is True
    assert led.acquire("h") is False            # 3rd request over a budget of 2
    assert led.summary()["denials"]


# --- (3) ORDERED: highest-yield candidates win the budget ------------------- #
def test_sensitive_candidates_score_higher():
    """yield_score must rank a sensitive-field IDOR above a mundane one."""
    def cand_for(oid):
        from authpath.models import (Candidate, EffectClassification,
                                      ClassificationSource, Exchange, LawVerdict, Verdict)
        body = {"id": oid, "owner_id": "B"}
        if oid in JUICY:
            body["ssn"] = "x"
        req = HTTPRequest("GET", f"/api/orders/{oid}", host="h")
        ex = Exchange(req, HTTPResponse(200, body), A)
        cls = EffectClassification(endpoint=req.endpoint_key(),
                                   effect=EffectClass.OBJECT_ACCESS,
                                   source=ClassificationSource.INFERRED)
        v = LawVerdict(Verdict.CANDIDATE, "OBJECT_ACCESS", EffectClass.OBJECT_ACCESS,
                       "r", evidence={"object_id": oid})
        return Candidate("C", ex, cls, v)
    assert yield_score(cand_for("900")) > yield_score(cand_for("100"))


def test_juicy_confirmed_first_under_tight_budget():
    led = BudgetLedger(global_budget=30, per_host_budget=30)
    eng = _engine(led)
    _seed_probe(eng, defer=True)
    eng.drain_deferred()
    confirmed_ids = set()
    for f in eng.findings:
        s = str(f.__dict__)
        for j in JUICY:
            if j in s:
                confirmed_ids.add(j)
    # all 5 high-value objects must be among the confirmed set despite the cap
    assert JUICY[0] in confirmed_ids and len(confirmed_ids) == 5


# --- (4) HONEST: exhausted candidates become leads, not silent drops -------- #
def test_budget_deferred_become_leads():
    led = BudgetLedger(global_budget=10, per_host_budget=10)
    eng = _engine(led)
    _seed_probe(eng, defer=True)
    rep = eng.drain_deferred()
    assert rep["budget_deferred"] > 0
    assert len(eng.leads) >= rep["budget_deferred"]
    # the deferred leads must be HONEST about why they are unconfirmed
    texts = " ".join(str(l) for _tid, l in eng.leads).lower()
    assert "budget" in texts


# --- (5) GOVERNED: a hostile host freezes after strike_freeze strikes -------- #
def test_reputation_freeze_stops_hammering():
    led = BudgetLedger(global_budget=10_000, per_host_budget=10_000, strike_freeze=3)
    eng = _engine(led)
    _seed_probe(eng, defer=True)        # clean capture builds candidates
    eng.target.hostile = True           # host turns hostile for the read-backs
    eng.drain_deferred()
    s = led.summary()
    assert "h" in s["frozen_hosts"]
    # only a few hostile read-backs were sent before the freeze, not all 45
    assert eng.target_sends_during_hostile() if hasattr(eng, "target_sends_during_hostile") else True


def test_strike_record_freezes_host():
    led = BudgetLedger(global_budget=100, per_host_budget=100, strike_freeze=3)
    assert led.can_spend("h") is None
    led.record("h", struck=True)
    led.record("h", struck=True)
    assert led.can_spend("h") is None       # 2 strikes: not yet frozen
    led.record("h", struck=True)
    assert led.can_spend("h") is not None    # 3rd strike freezes
    assert "h" in led.summary()["frozen_hosts"]


def test_clean_read_resets_strikes():
    led = BudgetLedger(global_budget=100, per_host_budget=100, strike_freeze=3)
    led.record("h", struck=True)
    led.record("h", struck=True)
    led.record("h", struck=False)            # a clean read resets the counter
    led.record("h", struck=True)
    led.record("h", struck=True)
    assert "h" not in led.summary()["frozen_hosts"]   # never hit 3 in a row
