"""
PROBLEM 2 — the N-principal probe matrix.

Single-session tools miss horizontal IDOR because they test one identity. ONYX's
Δstate confirmation is sound per (principal, object) pair, but nothing in the engine
systematically MULTIPLIES one observed object across ALL known identities. This
module is that generator — pure COVERAGE expansion, zero new judgment:

  * HORIZONTAL: every same-tier principal who did NOT legitimately access object O is
    probed against O (same-privilege data theft — the most common IDOR).
  * VERTICAL: lower-privilege principals (and anon) are probed against higher-tier
    objects (privilege-escalation reads).

It NEVER probes a principal against an object it legitimately owns/accessed (no
wasted/false pair), emits GET-only candidates (never multiplies a mutation across
identities), is bounded + ranked + deterministic, and leaves every verdict to the
existing Δstate confirmer. It is structurally incapable of adding a false positive:
on a secure target every generated pair is denied and confirmed as no-leak.
"""
from __future__ import annotations

from dataclasses import dataclass

# privilege tiers (higher number = more privilege). Unknown roles -> SAME tier.
_TIER = {
    "anonymous": 0, "anon": 0, "guest": 0,
    "user": 1, "member": 1, "customer": 1, "basic": 1,
    "staff": 2, "manager": 2, "moderator": 2,
    "admin": 3, "administrator": 3, "owner": 3, "superuser": 3, "root": 3,
}


def _tier_of(principal) -> int:
    role = (getattr(principal, "role", "") or "").lower()
    label = (getattr(principal, "label", "") or "").lower()
    for key, t in _TIER.items():
        if key in role or key in label:
            return t
    if getattr(principal, "is_anonymous", False):
        return 0
    return 1                                  # default: ordinary authenticated user


@dataclass
class ProbePair:
    attacker_pid: str
    method: str
    path: str                                 # concrete (object id filled in)
    object_id: str
    endpoint_key: str
    kind: str                                 # "horizontal" | "vertical"
    rank: int = 0

    @property
    def dedup_key(self):
        return (self.attacker_pid, self.method.upper(), self.path)


def build_matrix(observed, principals: dict, *, max_pairs: int = 500,
                 expand_id_formats: bool = False, id_max_neighbours: int = 6) -> list:
    """Build the cross-principal probe matrix.

    `observed` is a list of dicts describing legitimate accesses seen in the capture:
        {"owner_pid": "A", "method": "GET", "endpoint": "GET /api/orders/{id}",
         "path": "/api/orders/42", "object_id": "42"}
    Only GET object reads are turned into cross-principal probes.

    GAP 1: when expand_id_formats is True, each observed id is expanded with
    structure-preserving NEIGHBOUR ids (decode->increment->re-encode) so encoded /
    GraphQL-global / prefixed id-spaces are enumerated too. Default False =>
    byte-identical to the prior behaviour. Every probe is still Δstate-gated.
    """
    from . import idformat
    # map object_id -> set of principals who legitimately accessed it (owners)
    owners = {}
    objects = {}
    for o in observed or []:
        if (o.get("method", "GET").upper() != "GET"):
            continue                          # GET object reads only (safety)
        oid = str(o.get("object_id", ""))
        if not oid:
            continue
        owners.setdefault(oid, set()).add(o.get("owner_pid"))
        objects[oid] = o                      # representative access for this object

    pairs = []
    for oid, rep in objects.items():
        owner_set = owners.get(oid, set())
        owner_tiers = {_tier_of(principals[p]) for p in owner_set if p in principals}
        max_owner_tier = max(owner_tiers) if owner_tiers else 1
        # GAP 1: candidate ids to probe for this endpoint (observed + neighbours).
        candidate_ids = idformat.expand_ids(oid, enabled=expand_id_formats,
                                            max_neighbours=id_max_neighbours)
        for pid, principal in principals.items():
            if pid in owner_set:
                continue                      # never probe a legitimate owner (RISK 3)
            atk_tier = _tier_of(principal)
            # classify the pair
            if atk_tier <= max_owner_tier:
                kind = "horizontal" if atk_tier == max_owner_tier else "vertical"
            else:
                continue
            for cand in candidate_ids:
                cand_path = (rep.get("path", "") if cand == oid
                             else _swap_id(rep.get("path", ""), oid, cand))
                if cand_path is None:
                    continue
                rank = 10
                if kind == "vertical":
                    rank += 5
                if getattr(principal, "is_anonymous", False):
                    rank += 5
                if cand != oid:
                    rank -= 1                 # observed id ranks above neighbours
                pairs.append(ProbePair(
                    attacker_pid=pid, method="GET", path=cand_path,
                    object_id=cand, endpoint_key=rep.get("endpoint", ""),
                    kind=kind, rank=rank))

    # dedupe + deterministic ranking
    seen, uniq = set(), []
    for p in sorted(pairs, key=lambda x: (-x.rank, x.attacker_pid, x.path)):
        if p.dedup_key in seen:
            continue
        seen.add(p.dedup_key); uniq.append(p)
        if len(uniq) >= max_pairs:
            break
    return uniq


def _swap_id(path: str, old_id: str, new_id: str):
    """Replace the observed id in a concrete path with a candidate id (exact, last
    occurrence to avoid clobbering an earlier path segment). Returns None if absent."""
    if old_id not in path:
        return None
    idx = path.rfind(old_id)
    return path[:idx] + new_id + path[idx + len(old_id):]


def to_probe_items(pairs: list) -> list:
    """Render matrix pairs as engine-consumable probe items (GET-only)."""
    return [{"principal": p.attacker_pid, "method": "GET", "path": p.path,
             "_matrix_kind": p.kind, "_object_id": p.object_id,
             "_from_endpoint": p.endpoint_key} for p in pairs]


def summarize(pairs: list) -> dict:
    h = sum(1 for p in pairs if p.kind == "horizontal")
    v = sum(1 for p in pairs if p.kind == "vertical")
    return {"total_pairs": len(pairs), "horizontal": h, "vertical": v,
            "objects_covered": len({p.object_id for p in pairs}),
            "attackers": sorted({p.attacker_pid for p in pairs})}
