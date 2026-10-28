"""
RL10 regression suite — READ CONSISTENCY (distributed-target robustness).

The confirmer treated a single read-back as instantaneous ground truth. After
AHP-3 added refutation, a STALE replica read could REFUTE a real leak — a
self-inflicted false negative on eventually-consistent backends. The confirmer now
re-reads within a bounded window and acts only on the CONVERGED verdict.

Properties under guard:
  1. DEFAULT  — consistency_reads=1 is single-shot (byte-identical; verified by the
                whole suite staying green + demo unchanged).
  2. STALE-FN — a real leak behind a stale-first replica that converges is CONFIRMED
                (the AHP-3 regression is fixed).
  3. NO-FP    — a transient leak that converges to fixed is NOT confirmed.
  4. UNSTABLE — a flapping backend neither confirms nor clears; it abstains and
                surfaces a CONSISTENCY_UNSTABLE lead (RL5 honesty).
  5. STABLE   — a genuinely stable leak still confirms under a multi-read window.
"""
from authpath.models import (
    Candidate, EffectClass, EffectClassification, ClassificationSource,
    Exchange, HTTPRequest, HTTPResponse, LawVerdict, Principal, Verdict,
)
from authpath.confirmer import Confirmer
from authpath.scope_guard import ScopeGuard, ScopeConfig
from authpath.engine import AuthPathEngine
from authpath.economy import BudgetLedger
from authpath.transport import make_exchange

A = Principal("A", "Alice")
B = Principal("B", "Bob")
_SG = ScopeGuard(ScopeConfig(allowed_hosts=["demo.local", "h"], dry_run=True))


class _Seq:
    """Returns the i-th body in `seq`, holding the last once exhausted."""
    def __init__(self, seq):
        self.seq = seq
        self.i = 0
    def send(self, req, principal):
        b = self.seq[min(self.i, len(self.seq) - 1)]
        self.i += 1
        return HTTPResponse(200, dict(b))


def _pay_cand():
    req = HTTPRequest("POST", "/api/checkout",
                      body={"order_id": "303", "amount_paid": 1}, host="demo.local")
    ex = Exchange(req, HTTPResponse(200, {"order_id": "303", "amount_due": 90,
                                          "amount_paid": 1, "status": "paid"}), B)
    cls = EffectClassification(endpoint="x", effect=EffectClass.PAYMENT,
                               source=ClassificationSource.INFERRED)
    v = LawVerdict(Verdict.CANDIDATE, "PAY", EffectClass.PAYMENT, "r",
                   evidence={"amount_paid": 1, "amount_due": 90, "shortfall": 89})
    return Candidate("C", ex, cls, v)


def _confirm(seq, reads):
    c = Confirmer(_Seq(seq), {"B": B}, _SG)
    c.consistency_reads = reads
    proof = c.confirm(_pay_cand())
    return ("CONFIRM" if (proof and proof.confirmed) else "abstain"), c._unstable


_UNDERPAID = {"id": "303", "status": "paid", "amount_paid": 1, "amount_due": 90}
_FIXED = {"id": "303", "status": "paid", "amount_paid": 90, "amount_due": 90}


# --- (1) DEFAULT single-shot ----------------------------------------------- #
def test_default_is_single_shot():
    c = Confirmer(_Seq([_UNDERPAID]), {"B": B}, _SG)
    assert c.consistency_reads == 1
    proof = c.confirm(_pay_cand())
    assert proof and proof.confirmed              # one read, real leak, confirmed


# --- (2) STALE-replica FN fixed -------------------------------------------- #
def test_stale_first_then_converges_confirms():
    verdict, _ = _confirm([_FIXED, _UNDERPAID, _UNDERPAID], reads=4)
    assert verdict == "CONFIRM"                   # AHP-3 regression fixed


# --- (3) NO false positive on a transient leak ----------------------------- #
def test_transient_leak_then_fixed_abstains():
    verdict, _ = _confirm([_UNDERPAID, _FIXED, _FIXED], reads=4)
    assert verdict == "abstain"


# --- (4) UNSTABLE flapping -> abstain + instability ------------------------ #
def test_flapping_abstains_and_logs_instability():
    verdict, unstable = _confirm([_UNDERPAID, _FIXED, _UNDERPAID, _FIXED], reads=4)
    assert verdict == "abstain"
    assert unstable                               # instability recorded


# --- (5) STABLE leak still confirms under a window ------------------------- #
def test_stable_leak_confirms_under_window():
    verdict, _ = _confirm([_UNDERPAID, _UNDERPAID, _UNDERPAID], reads=4)
    assert verdict == "CONFIRM"


# --- end-to-end through the engine ----------------------------------------- #
class _FlapOwner:
    """A's capture is a stable leak; the owner (B) read-back flaps -> unstable."""
    def __init__(self):
        self.b = 0
    def send(self, req, p):
        if p.pid == "A":
            return HTTPResponse(200, {"id": "900", "owner_id": "B", "ssn": "SSN-B"})
        self.b += 1
        return (HTTPResponse(200, {"id": "900", "owner_id": "B", "ssn": "SSN-B"})
                if self.b % 2 else HTTPResponse(404, {"error": "x"}))


def test_engine_surfaces_instability_lead():
    t = _FlapOwner()
    eng = AuthPathEngine(t, {"A": A, "B": B},
                         ScopeConfig(allowed_hosts=["h"], dry_run=False),
                         contract={}, ledger=BudgetLedger.unbounded(), consistency_reads=4)
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/orders/900", host="h"), B))
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/orders/900", host="h"), A))
    assert tr.outcome == "candidate-unconfirmed"
    assert len(eng.findings) == 0
    assert any(getattr(l, "kind", "") == "CONSISTENCY_UNSTABLE" for _t, l in eng.leads)


class _StableLeak:
    def send(self, req, p):
        return HTTPResponse(200, {"id": "900", "owner_id": "B", "ssn": "SSN-B"})


def test_engine_stable_leak_confirms_under_window():
    t = _StableLeak()
    eng = AuthPathEngine(t, {"A": A, "B": B},
                         ScopeConfig(allowed_hosts=["h"], dry_run=False),
                         contract={}, ledger=BudgetLedger.unbounded(), consistency_reads=4)
    eng.observe(make_exchange(t, HTTPRequest("GET", "/api/orders/900", host="h"), B))
    tr = eng.analyze(make_exchange(t, HTTPRequest("GET", "/api/orders/900", host="h"), A))
    assert tr.outcome == "finding"
