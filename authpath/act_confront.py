"""
authpath.act_confront — confront the target's BROADCAST with its ACT.

THE BROADCAST-vs-ACT NERVE (FORGE build, step 2)
------------------------------------------------
Step 1 (broadcast.py) read the target's DECLARED decision: which fields/actions it
showed principal A but hid from B, or the permission it named when it withheld. Step 2
asks the other channel: when B does the thing the target declared B may not — does the
target EXECUTE it anyway? A contradiction (declared forbidden, actually done) is the
nerve's signal.

This step only PROPOSES the confrontation and packages the proof requirement; the
existing Δstate confirmer remains the sole judge.

SAFETY CONTRACT (never weaken the project, never add a false positive)
---------------------------------------------------------------------
  * CANDIDATES ONLY. Produces contradiction candidates for the existing confirmer;
    no finding, no verdict, no Δstate of its own.
  * Reuses the audited destructive-action gates: every mutating confrontation is
    checked against scope.may_mutate; irreversible verbs (DELETE) are NEVER probed
    unless the operator armed allow_destructive — identical discipline to action_matrix.
  * Flag-gated / isolated: imported by nothing in the live pipeline ⇒ byte-identical.

F7 PRE-MORTEM — four FP sources, four guards:
  A-1 a link is merely ABSENT (incomplete broadcast) but the action is in fact allowed →
      absence alone never convicts; the confrontation is only a candidate, and the
      conviction requires Δstate proof that B changed/obtained an object that is NOT B's.
  A-2 a field is hidden because it is null/empty, not forbidden → the field-exposure
      confrontation requires the owner's view to actually CONTAIN the field with a real
      value (read as the declared owner); a merely-absent field is abstained.
  A-3 a destructive confrontation could harm the target → scope.may_mutate gate; DELETE
      and other irreversible verbs are excluded unless explicitly armed.
  A-4 "forbidden" vs "not found" confusion → 404 is treated as non-existence (no claim),
      403 as a declared denial, 2xx as executed; never conflated.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

_MUTATING = ("POST", "PUT", "PATCH", "DELETE")
_IRREVERSIBLE = ("DELETE",)
# map a declared action/link relation to the HTTP verb it implies (conservative)
_REL_VERB = {
    "edit": "PATCH", "update": "PATCH", "modify": "PATCH", "patch": "PATCH",
    "delete": "DELETE", "remove": "DELETE", "destroy": "DELETE",
    "create": "POST", "add": "POST", "publish": "POST", "approve": "POST",
    "cancel": "POST", "archive": "POST", "transfer": "POST",
    "view": "GET", "read": "GET", "get": "GET", "self": "GET", "download": "GET",
}


@dataclass
class Confrontation:
    """One proposed broadcast-vs-act test: principal B does what the target declared B
    may not, and we check whether the act contradicts the broadcast — Δstate to judge."""
    kind: str                          # "hidden_action" | "hidden_field"
    accessor: str                      # the principal the target broadcast "forbidden" to
    resource: str
    verb: str                          # the HTTP verb to attempt (GET for field exposure)
    declared: str                      # the action/field the broadcast withheld
    owner_hint: Optional[str] = None   # declared owner of the resource, if known
    reversible: bool = True
    request_path: Optional[str] = None


def _verb_for_action(rel: str) -> str:
    return _REL_VERB.get(rel.split(".")[-1].lower(), "POST")  # unknown action ⇒ assume mutating (safer gate)


def confrontations_from_candidate(cand: dict, *, owner_of=None) -> list:
    """Turn ONE broadcast-difference candidate into safe confrontations.

    For each item the target broadcast to A but hid from B, propose that B attempts it:
      * a hidden ACTION (link/rel) → B attempts the implied verb on the resource;
      * a hidden FIELD → B attempts to read the resource and we check the field appears.
    A-4: only acts on a declared denial (the item is present for A, absent for B), not
    on non-existence. owner_of(resource) (optional) supplies the declared owner hint."""
    out = []
    resource = cand["resource"]
    owner = owner_of(resource) if callable(owner_of) else None

    # hidden actions: broadcast to A, withheld from B
    for rel in cand.get("actions_only_a", []):
        verb = _verb_for_action(rel)
        out.append(Confrontation(
            kind="hidden_action", accessor=cand["accessor_b"], resource=resource,
            verb=verb, declared=rel, owner_hint=owner,
            reversible=verb not in _IRREVERSIBLE))
    for rel in cand.get("actions_only_b", []):
        verb = _verb_for_action(rel)
        out.append(Confrontation(
            kind="hidden_action", accessor=cand["accessor_a"], resource=resource,
            verb=verb, declared=rel, owner_hint=owner,
            reversible=verb not in _IRREVERSIBLE))
    # hidden fields: broadcast to A, hidden from B → B reads, we check field appears
    for fld in cand.get("fields_only_a", []):
        out.append(Confrontation(
            kind="hidden_field", accessor=cand["accessor_b"], resource=resource,
            verb="GET", declared=fld, owner_hint=owner, reversible=True))
    for fld in cand.get("fields_only_b", []):
        out.append(Confrontation(
            kind="hidden_field", accessor=cand["accessor_a"], resource=resource,
            verb="GET", declared=fld, owner_hint=owner, reversible=True))
    return out


def safe_confrontations(confrontations, scope, *, host=None) -> tuple:
    """Split confrontations into (runnable, blocked) using the AUDITED scope gate. A
    mutating verb is runnable only if scope.may_mutate allows it; irreversible verbs are
    blocked unless the operator armed allow_destructive. Read-only confrontations
    (hidden_field, GET actions) are always runnable. Never weakens the gate — it calls
    the same scope.may_mutate the rest of the engine uses. `host` is the target host the
    real request will carry (a hostless request is refused by scope before the mutation
    check, so it must be supplied for the gate to be exercised)."""
    from .models import HTTPRequest
    from .scope_guard import ScopeVerdict
    runnable, blocked = [], []
    for c in confrontations:
        if c.verb in _MUTATING:
            req = HTTPRequest(c.verb, c.request_path or f"/{c.resource.replace(':', '/')}",
                              host=host or "")
            decision = scope.may_mutate(req)
            if decision.verdict is ScopeVerdict.ALLOW:
                runnable.append(c)
            else:
                blocked.append((c, decision.reason))
        else:
            runnable.append(c)                          # read-only is always safe
    return runnable, blocked
