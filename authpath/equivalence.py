"""
authpath.equivalence — the equivalence substrate of the nerve (FORGE build, step 3).

Steps 1-2 gave us, from the TARGET's own words: who a credential belongs to
(attested identity) and which response field denotes ownership (the ownership
pointer). Step 3 reconciles them into the nerve's core signal:

    THE TARGET SERVED PRINCIPAL Y AN OBJECT ITS OWN DATA DECLARES BELONGS TO X,
    AND DECLARED NO GRANT OF IT TO Y.

That is a self-contradiction by the target: by its ownership declaration the object
is X's; by its decision it handed it to Y. It is the deterministic, general BOLA
signal — read entirely off the wire, no policy reconstruction, no induction.

SAFETY CONTRACT (your standing instruction: never weaken the project, never add a
single false positive)
------------------------------------------------------------------------------
  * CANDIDATES ONLY. This module produces no finding, touches no verdict, no Δstate,
    no existing engine. Conviction stays exclusively with the existing Δstate
    confirmer (step 4). A wrong reconciliation can therefore never be a false
    positive — only, at worst, a candidate the confirmer then drops. (FP-6 / meta.)
  * Flag-gated and additive: imported by nothing in the live pipeline yet ⇒
    byte-identical.

F7 PRE-MORTEM — six FP sources, six guards, all enforced here:
  FP-1 different declared authority compared as equal → the reconciliation is keyed
       on a SINGLE accessor's attested identity vs the object's declared owner; it
       never compares two principals, so mismatched authority cannot arise here.
  FP-2 wrong identity unification of the OBJECT → the resource key comes from the
       audited surface_map.identify, never a new guess.
  FP-3 wrong permission → recorded per (resource, permission-class); read and write
       are never conflated.
  FP-4 a hidden context legitimises the access → never convicts; only a candidate,
       and only when the owner is UNAMBIGUOUSLY declared and no grant is declared.
  FP-5 an accessor with no attested identity → excluded (abstain, F2).
  FP-6 the layer itself convicting → it cannot; no verdict path exists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .surface_map import identify
from .ownership_pointer import OwnershipPointerLedger


def _permission_class(method: str) -> str:
    """read vs write — never conflated (FP-3). HEAD/GET/OPTIONS are reads."""
    return "read" if (method or "").upper() in ("GET", "HEAD", "OPTIONS") else "write"


@dataclass
class AccessRecord:
    accessor: str                      # the accessor's TARGET-ATTESTED identity
    resource: str                      # ResourceIdentity string (audited), e.g. "order:42"
    permission: str                    # "read" | "write"
    accessible: bool                   # the target's DECISION (2xx) vs forbidden
    declared_owner: Optional[str]      # owner the target declared in the body (or None)
    granted_to_accessor: bool          # target declared the resource shared with accessor
    request: Any = None
    response: Any = None


@dataclass
class EquivalenceLedger:
    """Indexes accesses by the target's own declarations and emits ownership-
    reconciliation CANDIDATES. No verdicts. The Δstate confirmer judges."""

    ownership: OwnershipPointerLedger = field(default_factory=OwnershipPointerLedger)
    _records: list = field(default_factory=list)

    def record_access(self, request, response, accessor_identity: Optional[str]) -> None:
        """File one observed access under the target's declarations. `accessor_identity`
        is the TARGET-ATTESTED identity of the caller (from attestation.py) — None if
        the target never testified, in which case the access is filed but can never be
        an accessor in a candidate (FP-5)."""
        ri = identify(request)
        if ri is None:
            return                                     # unaddressable ⇒ not an object access
        status = getattr(response, "status", 0)
        accessible = 200 <= status < 300
        owner = self.ownership.declared_owner(response) if accessible else None
        granted = (self.ownership.grant_includes(response, accessor_identity)
                   if accessible and accessor_identity else False)
        self._records.append(AccessRecord(
            accessor=accessor_identity, resource=str(ri),
            permission=_permission_class(getattr(request, "method", "GET")),
            accessible=accessible, declared_owner=owner,
            granted_to_accessor=granted, request=request, response=response))

    def ownership_mismatch_candidates(self) -> list:
        """The nerve's core candidates: an accessible object whose target-DECLARED
        owner is unambiguously someone OTHER than the accessor, with NO declared grant
        to the accessor. Each is a CANDIDATE for Δstate — never a finding.

        Every guard is a hard precondition; any unmet one ⇒ the access is skipped
        (RL5 abstain), so the set is a conservative under-approximation, never an
        over-claim."""
        if self.ownership.pointer() is None:
            return []                                  # no ownership vocabulary learned ⇒ abstain
        out = []
        for r in self._records:
            if not r.accessible:                       # only granted accesses can be a leak
                continue
            if r.accessor is None:                     # FP-5: no attested accessor identity
                continue
            # LAZY OWNERSHIP: declared_owner is filed at record time, but the ownership
            # pointer is learned INCREMENTALLY — an access filed before the pointer
            # stabilised would carry declared_owner=None forever (order-dependent blind
            # spot). Recompute here, where the pointer is final, applying the SAME learned
            # pointer to every record consistently. No new signal ⇒ no new FP, only recall.
            declared_owner = r.declared_owner
            if declared_owner is None:
                declared_owner = self.ownership.declared_owner(r.response)
            if declared_owner is None:                 # owner not declared ⇒ cannot reconcile
                continue
            if str(declared_owner).lower() == str(r.accessor).lower():
                continue                               # self-owned: correct, not a leak
            if r.granted_to_accessor:                  # FP-c: legitimately shared with me
                continue
            out.append({
                "resource": r.resource,
                "accessor": r.accessor,
                "declared_owner": declared_owner,
                "permission": r.permission,
                "request": r.request,
                "response": r.response,
                "why": (f"target served {r.accessor} the {r.permission} of {r.resource}, "
                        f"which its own data declares belongs to {declared_owner}, "
                        f"with no declared grant to {r.accessor}"),
            })
        return out

    def decision_conflict_pairs(self) -> list:
        """Secondary candidates: the SAME (accessor, resource, permission) for which
        the target both GRANTED and FORBADE across different observations — a decision
        the target contradicted itself on (generalises the cross-door / temporal
        inconsistency). Candidates only; Δstate judges. Context guard: only accesses
        with no observed distinguishing attribute are paired (FP-4 handled by the
        caller supplying already-context-matched records; here we pair on the exact
        same key, the most conservative possible)."""
        by_key: dict = {}
        for r in self._records:
            if r.accessor is None:
                continue
            by_key.setdefault((r.accessor, r.resource, r.permission), set()).add(r.accessible)
        pairs = []
        for (acc, res, perm), decisions in by_key.items():
            if True in decisions and False in decisions:
                pairs.append({"accessor": acc, "resource": res, "permission": perm,
                              "why": (f"target both granted and forbade {acc} the {perm} "
                                      f"of {res} — a self-contradicted decision")})
        return pairs
