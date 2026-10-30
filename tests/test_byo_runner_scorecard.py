"""
Deficiency #10 (independent T1 number) — solved-criterion for what code CAN do.

A genuine T1 number needs a live, independently-authored, authorized target — impossible in
a no-egress sandbox, and claiming one would be a lie. What is proven here: the turnkey
harness runs ONYX end-to-end and emits a SEALED, TIER-HONEST scorecard. Tier honesty is
enforced by construction — an in-process replica is T2 and cannot be stamped T1.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "external_targets"))
from authpath.models import HTTPRequest, HTTPResponse, Principal
from byo_runner import TargetConfig, run_target, TIER_T1, TIER_T2


class _Replica:
    """A tiny in-process target with a real cross-principal leak (a stand-in for the VAmPI
    faithful replica). In-process => must be scored T2, never T1."""
    host = "replica.test"
    def send(self, req, principal):
        rid = req.path.rstrip("/").split("/")[-1]
        if rid == "9":
            return HTTPResponse(200, {"id": "9", "owner_email": "victim@corp.test",
                                      "secret": "bravo-secret"})
        return HTTPResponse(404, {})


def _cfg(**kw):
    P = {p: Principal(p, p, auth={"Authorization": f"Bearer {p}"}) for p in "AB"}
    return TargetConfig(name="vampi-faithful-replica", client=_Replica(), principals=P, **kw)


def _plans():
    obs = [("B", HTTPRequest("GET", "/api/v1/orders/9", host="replica.test"))]   # B owns 9
    atk = [("A", HTTPRequest("GET", "/api/v1/orders/9", host="replica.test"))]   # A reads B's 9
    return obs, atk


def test_harness_runs_and_finds_the_seeded_leak():
    obs, atk = _plans()
    s = run_target(_cfg(), obs, atk)
    assert s["n_findings"] >= 1, "the turnkey harness must confirm the seeded cross-principal leak"


def test_scorecard_is_tamper_evident():
    obs, atk = _plans()
    s = run_target(_cfg(), obs, atk)
    card = s["_card"]
    assert card.verify() is True and s["tamper_evident"] is True
    card.audit._chain[0]["note"] = "forged"                 # tamper
    assert card.verify() is False                           # chain breaks


def test_tier_honesty_replica_is_T2_and_cannot_be_T1():
    obs, atk = _plans()
    # even if a caller lies about ONE axis, BOTH are required for T1
    s_inproc = run_target(_cfg(independently_authored=True, live_networked=False), obs, atk)
    assert s_inproc["tier"] == TIER_T2                      # in-process => T2 regardless
    s_default = run_target(_cfg(), obs, atk)
    assert s_default["tier"] == TIER_T2


def test_tier_T1_requires_both_operator_assertions():
    obs, atk = _plans()
    # ONLY when the operator asserts BOTH independent authorship AND live network is it T1.
    # (Here we assert them to prove the label path; the RUN is still the in-box replica, so
    # this is a label-path unit check, not a real T1 claim.)
    s = run_target(_cfg(independently_authored=True, live_networked=True), obs, atk)
    assert s["tier"] == TIER_T1


def test_recall_vs_declared_ground_truth_is_reported():
    obs, atk = _plans()
    s = run_target(_cfg(ground_truth={"9"}), obs, atk)
    assert s.get("recall_vs_declared_gt") == 1.0


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
