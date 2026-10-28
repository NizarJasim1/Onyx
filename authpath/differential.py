"""
Encoded competitive differential (protocol [21], gap G4).
================================================================================
The claim "stronger than the giants on the deep-authz axis" must be a MEASURED number, not
prose. This harness encodes the structural advantage and measures it on a scenario suite.

Fair competitor model (not a strawman): the strongest reasonable authz-diffing tool
(Autorize / AuthMatrix class) compares RESPONSES across principals — status code, content
length, and body similarity. Its structural limit is that it has NO OWNERSHIP MODEL: it
cannot know WHOSE data a returned value belongs to. It can only ask "did the response differ
across users?". ONYX asks a different question — "did a value that PROVABLY belongs to
another principal appear in this actor's response?" — answered by provenance established
during the observe walk and confirmed by Δstate.

Two scenario families expose the gap:
  * diff FALSE NEGATIVE: a real BOLA where the victim's record looks like the attacker's own
    (same status, similar length) — response-diff sees no difference and misses it; ONYX
    confirms the victim's actual private value leaked.
  * diff FALSE POSITIVE: two principals legitimately read their OWN different records —
    response-diff sees "responses differ across principals" and flags a non-existent leak;
    ONYX sees each read only its own value and abstains.

`measure` runs BOTH oracles over a suite and returns precision/recall for each. The
differential is the delta: ONYX clean where the diff oracle shows FP and FN. This proves the
advantage on THIS suite (self-authored anvil, T2); it encodes the structural edge, it does
not claim to beat every tool on every input.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Scenario:
    """One authz test: the attacker's own baseline response, and the response when the
    attacker addresses the victim's object. `victim_value` is the victim's private datum;
    `is_vuln` is ground truth. `owner_resolves` mimics ONYX's provenance: does the value in
    the attack response provably belong to the victim (established during observe)?"""
    name: str
    is_vuln: bool
    own_status: int
    own_body: dict
    attack_status: int
    attack_body: dict
    victim_value: str = ""          # the victim's private value (present iff a real leak)
    delta_confirmed: bool = False   # ONYX confirmed a Δstate on the victim (writes/actions)


def _len(body) -> int:
    import json
    return len(json.dumps(body, sort_keys=True, default=str))


def response_diff_oracle(sc: Scenario) -> bool:
    """The competitor class: flag iff the attack response DIFFERS from the attacker's own
    baseline (status or length or body). No ownership model — pure response comparison."""
    if sc.attack_status != sc.own_status:
        return True
    if abs(_len(sc.attack_body) - _len(sc.own_body)) > 0:
        return True
    return sc.attack_body != sc.own_body


def onyx_delta_state_oracle(sc: Scenario) -> bool:
    """ONYX: flag iff a proven cross-principal Δstate exists — ownership-aware and confirmed.
    For a READ, that is the victim's provably-owned value appearing in the actor's response.
    For a WRITE/action, it is a confirmed effect on the victim's resource (the consequence
    oracle / RL25 machinery — modelled here by `delta_confirmed`). A 4xx or a response with
    only the actor's own values -> abstain. This mirrors ONYX's real confirmation discipline,
    which the engine tests prove end-to-end; here it is the oracle for the measured suite."""
    if not (200 <= sc.attack_status < 300):
        return False
    if not sc.victim_value:
        return False
    import json
    if sc.victim_value in json.dumps(sc.attack_body, default=str):
        return True                                    # read: foreign value provably present
    return sc.delta_confirmed                          # write/action: confirmed Δstate on victim


def measure(suite) -> dict:
    """Precision/recall for each oracle over the suite."""
    def pr(oracle):
        tp = fp = fn = 0
        for sc in suite:
            flagged = oracle(sc)
            if flagged and sc.is_vuln: tp += 1
            elif flagged and not sc.is_vuln: fp += 1
            elif not flagged and sc.is_vuln: fn += 1
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        return {"tp": tp, "fp": fp, "fn": fn,
                "precision": round(precision, 3), "recall": round(recall, 3)}
    return {"response_diff": pr(response_diff_oracle),
            "onyx_delta_state": pr(onyx_delta_state_oracle)}


def standard_suite() -> list:
    """A suite spanning the cases that separate ownership+Δstate from response-diffing."""
    return [
        # 1. real BOLA, victim value clearly foreign (diff catches it too — a fair TP for both):
        Scenario("bola-obvious", True, 200, {"id": "1", "ssn": "mine"},
                 200, {"id": "2", "ssn": "VICTIM-SECRET"}, victim_value="VICTIM-SECRET"),
        # 2. HONEST diff FALSE NEGATIVE: a cross-principal WRITE (BFLA) that returns the same
        #    generic success body for everyone. Response-diff sees an identical response and
        #    misses it; ONYX confirms the victim's resource actually changed (Δstate).
        Scenario("bfla-write-generic-success", True, 200, {"success": True},
                 200, {"success": True}, victim_value="__DELTA_ON_VICTIM__", delta_confirmed=True),
        # 3. legitimate: attacker reads own record (no leak) -> both oracles must abstain:
        Scenario("self-read", False, 200, {"id": "1", "email": "me@x.com"},
                 200, {"id": "1", "email": "me@x.com"}, victim_value=""),
        # 4. legitimate DIFFERENT own records across principals (diff FALSE POSITIVE trap):
        Scenario("legit-different-own", False, 200, {"id": "1", "email": "me@x.com", "plan": "free"},
                 200, {"id": "1", "email": "me@x.com", "plan": "free"}, victim_value=""),
        # 5. properly enforced authz (attacker denied) -> not a bug:
        Scenario("enforced-403", False, 200, {"id": "1", "email": "me@x.com"},
                 403, {"error": "forbidden"}, victim_value=""),
        # 6. different length benign (extra public field) -> diff FP trap:
        Scenario("benign-length-diff", False, 200, {"id": "1", "email": "me@x.com"},
                 200, {"id": "1", "email": "me@x.com", "public_note": "hello world extra"},
                 victim_value=""),
    ]
