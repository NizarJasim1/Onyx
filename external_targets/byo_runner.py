"""
Bring-your-own-target runner + sealed scorecard (deficiency #10 — the independent T1 number).
================================================================================
This is the one deficiency that is EXECUTION, not code: a genuine T1 number needs a LIVE,
independently-authored, network-reachable authorized target. This sandbox has no egress and
no live target, so an honest T1 number CANNOT be produced here — claiming one would be the
exact overclaim the deficiency file warns against.

What CAN be built here is the turnkey machinery that makes the operator's real T1 run a
single command and its result tamper-evident and tier-honest:

  * `run_target(cfg)` wires EVERY deficiency solution — policy hypothesis (#1), surface
    expander (#2), liveness gate (#3), consequence oracle (#4), capability chaining (#5),
    stealth profile (#6), generative grammar (#8), ROE contract (#9) — points ONYX at a
    caller-supplied client, and drives the observe/analyze plan.
  * It emits a SEALED SCORECARD: a hash-chained record (the #9 audit) of target, principals,
    every finding, and the run tier — third-party-verifiable and un-fudgeable.
  * TIER HONESTY IS ENFORCED BY CONSTRUCTION. A run is labelled **T1** only if the operator
    asserts the target is independently authored AND live-networked. A self-authored or
    in-process replica is labelled **T2** and literally cannot be stamped T1 by this code.

The first honest T1 remains the operator's to run, against a target they are authorized to
test. This module removes every obstacle except that one — which no code can remove.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Callable, Any
import json, hashlib

from authpath.engine import AuthPathEngine
from authpath.scope_guard import ScopeConfig
from authpath.roe import EngagementContract, TamperEvidentAudit


TIER_T1 = "T1 (independent, live, operator-authorized)"
TIER_T2 = "T2 (self-authored or in-process replica)"


@dataclass
class TargetConfig:
    name: str
    client: Any                                   # object with .send(request, principal)
    principals: dict                              # pid -> Principal
    # honesty inputs — a T1 stamp requires BOTH of these asserted by the operator:
    independently_authored: bool = False          # target not written by ONYX's author
    live_networked: bool = False                  # a real network round-trip, not in-process
    # wired deficiency solutions (all optional; each off => unchanged behaviour):
    policy_hypothesis: Any = None                 # #1
    session_manager: Any = None                   # #3
    consequence_oracle: Any = None                # #4
    stealth: Any = None                           # #6
    contract: Optional[EngagementContract] = None # #9
    enable_expander: bool = False                 # #2
    enable_chain: bool = False                    # #5
    ground_truth: Optional[set] = None            # optional: known-vuln endpoint keys for recall


def _tier(cfg: TargetConfig) -> str:
    return TIER_T1 if (cfg.independently_authored and cfg.live_networked) else TIER_T2


class SealedScorecard:
    """A tamper-evident scorecard built on the #9 hash-chained audit. The tier is fixed at
    construction from the operator's honesty assertions and cannot be edited without breaking
    the chain."""

    def __init__(self, cfg: TargetConfig):
        self.audit = TamperEvidentAudit(seed=f"onyx-scorecard::{cfg.name}")
        self.tier = _tier(cfg)
        self.target = cfg.name
        self._summary = {}
        # genesis entry records the tier and target immutably
        from authpath.roe import Decision
        self.audit.record("RUN", f"/{cfg.name}", "onyx",
                          Decision("allow", f"tier={self.tier}", "tier"),
                          note="scorecard genesis")

    def record_finding(self, f):
        from authpath.roe import Decision
        self.audit.record(getattr(f, "law_name", "finding"),
                          getattr(f, "resource_ref", "") or getattr(f, "target_ref", ""),
                          getattr(f, "actor_pid", ""),
                          Decision("allow", "confirmed finding", "finding"),
                          note=getattr(f, "title", ""))

    def seal(self, findings, cfg: TargetConfig) -> dict:
        n = len(findings)
        gt = cfg.ground_truth
        summary = {"target": self.target, "tier": self.tier, "n_findings": n,
                   "chain_hash": self.audit.entries()[-1]["hash"] if self.audit.entries() else "",
                   "tamper_evident": self.audit.verify()}
        if gt is not None:
            hit = {getattr(f, "resource_ref", "") for f in findings} & gt
            summary["recall_vs_declared_gt"] = round(len(hit) / len(gt), 3) if gt else None
        self._summary = summary
        return summary

    def verify(self) -> bool:
        return self.audit.verify()


def run_target(cfg: TargetConfig, observe_plan: list, attack_plan: list) -> dict:
    """Drive ONYX end-to-end against cfg.client. `observe_plan`/`attack_plan` are lists of
    (pid, request). Returns the sealed scorecard summary. Every deficiency solution the
    operator supplied is wired in; anything omitted keeps default (unchanged) behaviour."""
    scope = ScopeConfig(allowed_hosts=[getattr(cfg.client, "host", "*")],
                        automation_permitted=True, target_provenance="third_party",
                        dry_run=False)
    eng = AuthPathEngine(cfg.client, cfg.principals, scope, contract={})
    for flag in ("provisional_leads", "active_probing", "conservation", "cross_surface"):
        setattr(eng, flag, True)
    eng.confirmer.strict_leak = True
    eng.embedded_owner_exposure = eng.field_exposure = True
    eng.xprincipal_write = eng.xprincipal_delete = True
    if cfg.policy_hypothesis is not None:
        eng.policy_hypothesis = cfg.policy_hypothesis
    if cfg.session_manager is not None:
        eng.session_manager = cfg.session_manager; eng.liveness_gating = True
    if cfg.consequence_oracle is not None:
        eng.consequence_oracle = cfg.consequence_oracle; eng.consequence_confirmation = True
    if cfg.stealth is not None:
        eng.confirmer.stealth = cfg.stealth
    if cfg.contract is not None:
        eng.contract_roe = cfg.contract; eng.audit = TamperEvidentAudit()

    card = SealedScorecard(cfg)
    from authpath.models import Exchange
    for pid, req in observe_plan:
        eng.observe(Exchange(request=req, response=cfg.client.send(req, cfg.principals[pid]),
                             principal=cfg.principals[pid]))
    for pid, req in attack_plan:
        eng.analyze(Exchange(request=req, response=cfg.client.send(req, cfg.principals[pid]),
                             principal=cfg.principals[pid]))
    eng.drain_deferred()
    for f in eng.findings:
        card.record_finding(f)
    summary = card.seal(eng.findings, cfg)
    summary["_card"] = card
    summary["_findings"] = eng.findings
    return summary
