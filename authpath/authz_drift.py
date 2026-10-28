"""
Object-Binding Authorization Drift — a pioneered class (protocol [22]).
================================================================================
HONEST FRAMING (protocol [16].1): ONYX already has a TEMPORAL axis — `temporal.py` detects
CREDENTIAL-lifecycle drift (a stale credential still working after a revocation event). This
module does NOT re-claim that axis. Its contribution is a distinct class on the interaction
of  temporal × object-reference-resolution  that neither the credential-lifecycle detector
nor any point-in-time law covers:

    THE OBJECT BOUND TO AN AUTHORIZATION DRIFTS BETWEEN THE CHECK AND THE COMMIT.

An authorization is granted against a reference REF while REF resolves to the actor's own
object O1 (authorized). REF is then re-pointed to a victim's object O2 (a mutation the actor
is individually allowed to make on REF). The privileged operation COMMITS against REF, now
resolving to O2 — so the effect lands on the victim's object carrying an authorization that
only ever saw the actor's own. A TOCTOU-of-authorization by object re-binding.

Real mechanism (not fiction): sagas, eventual consistency, CQRS, async commit, and any
"validate then commit" flow where the validated reference can change before the commit —
e.g. a draft/order/document whose target or owner field is mutated between an authz check
and the finalizing step.

Why the competitor class is STRUCTURALLY blind (measured in the differential harness):
  * response-diff: each individual step (check, mutate, commit) is legitimately authorized
    on its own -> no cross-user diff signal.
  * single-exchange scanners: the bug spans >=2 ordered exchanges with a mutation between.
  * fuzzers: it needs the exact ordered interleave check -> mutate -> use, not payloads.
ONYX sees it via cross-step value provenance + Δstate: the committed effect provably used
the post-mutation object against the pre-mutation check.

Zero-FP by construction: confirmed ONLY when (a) a CHECK resolved REF to an actor-owned
object and was authorized for the actor, (b) an observed MUTATE changed REF's resolution,
and (c) the committed USE landed on an object owned by a DIFFERENT principal. An atomic /
re-checked target (authorization re-evaluated at commit) yields no drift -> nothing.
Deterministic, no ML. Every finding carries a reproducible step sequence.

Wall (declared, = #4): ONYX must OBSERVE the ordered steps; a mutation that is entirely
server-internal and never surfaces is out of scope (invisible Δstate).
"""
from __future__ import annotations
from dataclasses import dataclass

# the sub-axis this class exercises (temporal × object-resolution); the temporal axis itself
# already exists in temporal.py — this is the object-binding interaction, declared honestly.
BINDING_STATE = ("stable_binding", "rebound_between_check_and_use")

CHECK, MUTATE, USE = "check", "mutate", "use"


@dataclass
class Step:
    kind: str                       # CHECK | MUTATE | USE
    ref: str                        # the reference/scope being operated on
    resolved_object: str            # what REF resolves to at this step
    owner: str                      # the principal owning resolved_object
    authorized_for: str = ""        # CHECK: the principal the authz was granted to
    committed: bool = False         # USE: did the privileged effect actually land?


@dataclass
class DriftFinding:
    actor: str
    ref: str
    checked_object: str
    used_object: str
    victim: str
    class_name: str = "OBJECT_BINDING_AUTHORIZATION_DRIFT"
    binding_state: str = "rebound_between_check_and_use"
    tag: str = "PIONEERED-CLASS / UNREVIEWED"
    def poc(self) -> list:
        return [f"CHECK {self.ref} -> {self.checked_object} (authorized for {self.actor})",
                f"MUTATE {self.ref} -> re-point to {self.used_object}",
                f"USE   {self.ref} -> commit on {self.used_object} (owned by {self.victim})"]


class ObjectBindingDriftDetector:
    """Consumes an ordered step sequence and confirms an object-binding authorization drift
    by Δstate. Used explicitly (opt-in); it never changes point-in-time behaviour."""

    def __init__(self):
        self._by_ref: dict = {}

    def record(self, step: Step):
        self._by_ref.setdefault(step.ref, []).append(step)

    def confirm(self, actor: str) -> list:
        out = []
        for ref, steps in self._by_ref.items():
            check = mutate = None
            for s in steps:
                if s.kind == CHECK and s.owner == actor and s.authorized_for == actor:
                    check, mutate = s, None                # fresh authorization epoch
                elif s.kind == MUTATE and check is not None and s.resolved_object != check.resolved_object:
                    mutate = s
                elif s.kind == USE and check is not None and mutate is not None:
                    if s.committed and s.owner != actor and s.resolved_object == mutate.resolved_object:
                        out.append(DriftFinding(actor=actor, ref=ref,
                                                checked_object=check.resolved_object,
                                                used_object=s.resolved_object, victim=s.owner))
                        check = mutate = None              # consume the epoch
        return out
