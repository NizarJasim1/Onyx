"""
GAP 3 — action-level BOLA matrix (the largest field family, 41.7%).

The read matrix (problem 2) is GET-only by design. The largest confirmed BOLA family
in the field taxonomy is ACTION-level: a principal performs a state-changing action
(POST/PUT/PATCH/DELETE) on ANOTHER principal's object. ONYX could run a hand-written
chain for this, but had no SYSTEMATIC generator.

This module generates action-level cross-principal probes from observed action
endpoints, each carrying a declarative OWNER-READBACK invariant: a finding is raised
ONLY if, after the attacker's action, the legitimate owner's read shows the object's
state genuinely changed (Δstate). "B's POST returned 200" is never, by itself, a
finding — the server may have ignored it.

SAFETY (supreme here, because actions are destructive):
  * every action probe is gated by scope.may_mutate (dry_run blocks; allow_destructive
    required) — exactly like any mutation in ONYX;
  * default is PLANNED-only (probes are emitted, not sent) until the operator arms
    action testing explicitly;
  * irreversible actions (DELETE) are flagged and require explicit arming;
  * reversible/idempotent actions are preferred for confirmation.
It reuses the engine's Δstate confirmation — no parallel judge — and is flag-gated,
so with action testing off the engine behaves identically.
"""
from __future__ import annotations

from dataclasses import dataclass

_MUTATING = ("POST", "PUT", "PATCH", "DELETE")
_IRREVERSIBLE = ("DELETE",)


@dataclass
class ActionProbe:
    attacker_pid: str
    method: str
    path: str
    object_id: str
    endpoint_key: str
    owner_pid: str
    irreversible: bool
    readback_path: str                # owner-side GET to confirm the state change
    rank: int = 0

    @property
    def dedup_key(self):
        return (self.attacker_pid, self.method.upper(), self.path)


def _tier_of(principal) -> int:
    from .matrix import _tier_of as t
    return t(principal)


def build_action_matrix(observed_actions, observed_reads, principals: dict, *,
                        max_pairs: int = 300, allow_irreversible: bool = False) -> list:
    """Generate action-level cross-principal probes.

    observed_actions: legitimate state-changing accesses seen in the capture:
        {"owner_pid","method","endpoint","path","object_id","readback_path"}
      readback_path = an owner-side GET that reflects the object's state (e.g. the
      object resource itself). If absent, derived from the object path.
    observed_reads: GET accesses (used only to derive a readback path if needed).
    """
    read_for_object = {}
    for r in observed_reads or []:
        if r.get("method", "GET").upper() == "GET":
            read_for_object[str(r.get("object_id", ""))] = r.get("path", "")

    pairs = []
    for a in observed_actions or []:
        method = a.get("method", "").upper()
        if method not in _MUTATING:
            continue
        oid = str(a.get("object_id", ""))
        if not oid:
            continue
        owner = a.get("owner_pid")
        irreversible = method in _IRREVERSIBLE
        readback = a.get("readback_path") or read_for_object.get(oid) or _strip_action(a.get("path", ""))
        owner_tier = _tier_of(principals[owner]) if owner in principals else 1
        for pid, principal in principals.items():
            if pid == owner:
                continue                          # never test the legitimate owner
            atk_tier = _tier_of(principal)
            if atk_tier > owner_tier:
                continue                          # higher-priv acting down is expected
            kind_rank = 10 + (5 if atk_tier < owner_tier else 0)
            if getattr(principal, "is_anonymous", False):
                kind_rank += 5
            if irreversible:
                kind_rank -= 3                    # rank destructive lower (handle last)
            pairs.append(ActionProbe(
                attacker_pid=pid, method=method, path=a.get("path", ""),
                object_id=oid, endpoint_key=a.get("endpoint", ""),
                owner_pid=owner, irreversible=irreversible,
                readback_path=readback, rank=kind_rank))

    # filter irreversible unless explicitly allowed
    if not allow_irreversible:
        pairs = [p for p in pairs if not p.irreversible]

    seen, uniq = set(), []
    for p in sorted(pairs, key=lambda x: (-x.rank, x.attacker_pid, x.path)):
        if p.dedup_key in seen:
            continue
        seen.add(p.dedup_key); uniq.append(p)
        if len(uniq) >= max_pairs:
            break
    return uniq


def _strip_action(path: str) -> str:
    """Derive the object resource path from an action path:
    /api/orders/42/cancel -> /api/orders/42 (best-effort owner read-back target)."""
    parts = path.rstrip("/").split("/")
    if len(parts) >= 2 and not parts[-1].isdigit() and not _looks_id(parts[-1]):
        return "/".join(parts[:-1])
    return path


def _looks_id(seg: str) -> bool:
    return seg.isdigit() or len(seg) >= 12


def to_chain_specs(pairs: list) -> list:
    """Render each action probe as a declarative one-step chain with an owner-readback
    invariant, so the EXISTING ChainRunner executes + confirms it (no new judge).
    The chain mutates as the attacker, then asserts via the owner's read-back."""
    specs = []
    for p in pairs:
        specs.append({
            "name": f"action-bola:{p.method}:{p.object_id}:{p.attacker_pid}",
            "actor": p.attacker_pid,
            "steps": [{"as": p.attacker_pid, "method": p.method, "path": p.path, "body": {}}],
            "assert": {
                "read": {"as": p.owner_pid, "method": "GET", "path": p.readback_path},
                # the invariant is target-specific; the operator refines `violated_if`.
                # default: any owner-visible change marker the user declares.
                "violated_if": {"field": "_changed", "equals": True},
            },
            "_meta": {"irreversible": p.irreversible, "endpoint": p.endpoint_key,
                      "kind": "action-level-bola"},
        })
    return specs


def summarize(pairs: list) -> dict:
    return {
        "total": len(pairs),
        "irreversible": sum(1 for p in pairs if p.irreversible),
        "by_method": {m: sum(1 for p in pairs if p.method == m) for m in _MUTATING},
        "attackers": sorted({p.attacker_pid for p in pairs}),
    }
