"""
authpath.nerve_bridge — connect the nerve's candidates to live Δstate confirmation
(FORGE build, step 4: the FIRST and ONLY place the nerve touches a conviction path).

Steps 1-3 read, from the target's own words, who a credential belongs to, which field
is ownership, and which accesses contradict that ownership. Step 4 CONFIRMS a
candidate the only RL1-safe way: by re-reading the contested object AS THE DECLARED
OWNER (resolved from the target's own attestation) and proving, by live Δstate, that
the non-owner accessor really obtained the owner's private object.

SAFETY CONTRACT (your standing instruction — never weaken the project, never add a
false positive)
------------------------------------------------------------------------------
  * This bridge is NOT imported by the engine/confirmer/any live path → byte-identical.
  * It introduces NO new "looks-like-a-bug" heuristic. A candidate becomes a finding
    ONLY when two LIVE reads prove cross-principal access:
        - the declared owner can read the object (it is real and theirs), AND
        - the non-owner accessor's observed response reproduced the owner's
          SUBSTANTIVE private fields (not just public/echoed scalars).
    Any failure, any ambiguity, any missing owner credential ⇒ ABSTAIN (RL5).
  * It reuses the audited `_read` primitive (scope-halt, budget, WAF-block and
    auth-expiry guards all apply), so it cannot probe out of scope or treat a WAF
    interstitial as data.

F7 PRE-MORTEM for the confirmation itself:
  X-1 declared owner is not a principal we hold creds for → cannot read as owner →
      ABSTAIN (never guess the owner's view).
  X-2 the object is actually PUBLIC (anyone reads it) → if an anonymous principal is
      available and also reads it, the access is not a leak → ABSTAIN.
  X-3 the accessor only got public/echoed fields, none of the owner's private data →
      no substantive leak → ABSTAIN.
  X-4 read-back fails / is blocked / creds expired → `_read` returns None → ABSTAIN.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .attestation import AttestationLedger, _scalar_fields
from .ownership_pointer import OwnershipPointerLedger

# role/tier fields a target may declare for a principal at its self endpoint. Used by the
# PEER-ROLE GUARD: a BOLA mismatch is only confirmed peer-to-peer (same declared role);
# a role DIFFERENCE is a plausible role-based grant ⇒ abstain (RL5). Reading the role is
# the same principle as the rest of the nerve: quote the target's own declaration.
_ROLE_FIELDS = ("role", "roles", "tier", "plan", "account_type", "user_type",
                "type", "membership", "level", "group")


def _declared_role(response):
    """Extract the role/tier the target declared at a self endpoint, or None."""
    from .attestation import _scalar_fields
    for k, v in _scalar_fields(getattr(response, "body", None)).items():
        if k.split(".")[-1].lower() in _ROLE_FIELDS and v:
            return str(v)
    return None
from .equivalence import EquivalenceLedger

# fields that are public/structural, not private owner data — never count as a leak
_NON_SUBSTANTIVE = {"id", "type", "kind", "object", "status", "public", "created_at",
                    "updated_at", "url", "href", "self", "_links", "version", "schema"}


@dataclass
class NerveFinding:
    resource: str
    accessor: str
    declared_owner: str
    leaked_fields: tuple
    why: str


class NerveBridge:
    """Orchestrates attestation → ownership-pointer → equivalence → live confirmation.
    Produces NerveFindings only when live Δstate proves the leak; abstains otherwise."""

    def __init__(self, confirmer, principals_by_identity: dict, anon_principal=None):
        # confirmer: the EXISTING confirmer instance (we use its audited `_read` and target)
        self.confirmer = confirmer
        self.by_identity = principals_by_identity      # attested identity -> Principal
        self.anon = anon_principal
        self.attest = AttestationLedger()
        self.ownership = OwnershipPointerLedger()
        self.equiv = EquivalenceLedger(ownership=self.ownership)
        self.abstained: list = []
        self.declared_role: dict = {}      # attested identity -> declared role/tier

    # -- feeding (mirrors what a driver observes; no engine hot-path touched) -- #
    def feed_self(self, fingerprint, request, response, principal=None):
        self.attest.record_self_response(fingerprint, request, response)
        # once the target has attested an identity for this credential, register the
        # principal under that identity so a later read-back as the owner is possible.
        ident = self.attest.identity_of(fingerprint)
        if ident is not None:
            if principal is not None:
                self.by_identity.setdefault(ident, principal)
            # PEER-ROLE GUARD input: record the role the target declared for this identity.
            role = _declared_role(response)
            if role:
                self.declared_role[ident] = role

    def feed_owned(self, request, response, fingerprint):
        ident = self.attest.identity_of(fingerprint)
        if ident is not None:
            self.ownership.observe_owned(request, response, ident, _rkey(request))

    def feed_access(self, request, response, fingerprint):
        self.equiv.record_access(request, response, self.attest.identity_of(fingerprint))

    # ---------------------------- confirmation ------------------------------- #
    def confirmed_findings(self) -> list:
        out = []
        seen = set()
        for cand in self.equiv.ownership_mismatch_candidates():
            key = (cand["resource"], cand["accessor"])
            if key in seen:
                continue
            f = self._confirm(cand)
            if f is not None:
                out.append(f)
                seen.add(key)
        return out

    def _confirm(self, cand) -> Optional[NerveFinding]:
        owner_id = str(cand["declared_owner"])
        owner = self.by_identity.get(owner_id)
        if owner is None:                              # X-1: cannot read as owner ⇒ abstain
            self.abstained.append((cand["resource"], "declared owner not provisioned"))
            return None
        # PEER-ROLE GUARD (F7): a BOLA mismatch is a confirmed violation only between
        # PEERS (same declared role). If the accessor's declared role DIFFERS from the
        # owner's, the target declared a role distinction that plausibly GRANTS the access
        # (e.g. an admin reading members' objects) — not provably a violation ⇒ abstain
        # (RL5). Guard rails so it never over-corrects:
        #   * only abstains when BOTH roles are KNOWN and DIFFERENT;
        #   * UNKNOWN role (no /me, no role field) ≠ elevated ⇒ proceed as before;
        #   * SAME role ⇒ proceed (real peer-to-peer BOLA is still caught).
        acc_role = self.declared_role.get(str(cand["accessor"]))
        own_role = self.declared_role.get(owner_id)
        if acc_role is not None and own_role is not None and acc_role != own_role:
            self.abstained.append((cand["resource"],
                                   f"role-difference ({acc_role} vs {own_role}): "
                                   f"plausible role-based grant"))
            return None
        req = cand["request"]
        owner_resp = self.confirmer._read(req, owner)  # audited Δstate read
        if owner_resp is None or not (200 <= getattr(owner_resp, "status", 0) < 300):
            self.abstained.append((cand["resource"], "owner read-back failed/blocked"))
            return None                                # X-4
        # X-2: rule out a public object — if anon can also read it, not a leak
        if self.anon is not None:
            anon_resp = self.confirmer._read(req, self.anon)
            if anon_resp is not None and 200 <= getattr(anon_resp, "status", 0) < 300:
                self.abstained.append((cand["resource"], "object is public (anon reads it)"))
                return None
        # X-3: the accessor must have reproduced the owner's SUBSTANTIVE private fields.
        # The ownership-pointer field (e.g. owner_id) is excluded: it is reproduced in
        # EVERY ownership mismatch by construction, so it is not independent evidence of
        # a private-data leak. A confirmed leak requires a private field BEYOND the
        # ownership metadata (stronger; reduces recall before it would ever raise an FP).
        pointer = self.ownership.pointer()
        owner_fields = _scalar_fields(getattr(owner_resp, "body", None))
        acc_fields = _scalar_fields(getattr(cand["response"], "body", None))
        leaked = tuple(sorted(
            k for k, v in owner_fields.items()
            if k.split(".")[-1].lower() not in _NON_SUBSTANTIVE
            and k != pointer
            and k in acc_fields and acc_fields[k] == v))
        if not leaked:
            self.abstained.append((cand["resource"], "no substantive owner field reproduced"))
            return None
        return NerveFinding(
            resource=cand["resource"], accessor=cand["accessor"],
            declared_owner=owner_id, leaked_fields=leaked,
            why=(f"{cand['accessor']} read {cand['resource']} (declared owner "
                 f"{owner_id}); live read-back as the owner proves the accessor "
                 f"reproduced the owner's private fields {list(leaked)} — confirmed "
                 f"cross-principal leak (Δstate)."))


    def diagnostics(self) -> dict:
        """A real-target self-diagnosis: not just what was found, but WHERE the nerve
        was blind and WHY candidates did not confirm — the data that tells you what to
        improve. Safe to call after a scan; it runs confirmation, then tallies.

        Reading the output:
          * coverage.* near zero ⇒ the nerve could not even attempt detection here
            (no self endpoint attested identity / no ownership field learned / the
            target rarely declares an owner in bodies). That is a REACH gap, not a bug.
          * funnel.abstained_by_reason ⇒ why confirmed candidates were dropped:
              X1_owner_not_provisioned → provision the declared owner's credential
              X2_object_public          → object is genuinely public (correct drop)
              X3_no_substantive_leak    → non-owner view was redacted (correct drop)
              X4_readback_failed        → owner read-back errored/blocked (transient)
        """
        findings = self.confirmed_findings()           # also fills self.abstained
        records = self.equiv._records
        accesses = len(records)
        with_owner = sum(1 for r in records if r.declared_owner is not None)
        candidates = self.equiv.ownership_mismatch_candidates()
        reason_map = {
            "not provisioned": "X1_owner_not_provisioned",
            "public": "X2_object_public",
            "no substantive": "X3_no_substantive_leak",
            "read-back failed": "X4_readback_failed",
        }
        by_reason: dict = {}
        for _res, why in self.abstained:
            tag = next((v for k, v in reason_map.items() if k in why), "other")
            by_reason[tag] = by_reason.get(tag, 0) + 1
        return {
            "coverage": {
                "identities_attested": len(self.attest._identity),
                "ownership_pointer_learned": self.ownership.pointer() is not None,
                "ownership_pointer_field": self.ownership.pointer(),
                "accesses_recorded": accesses,
                "accesses_with_declared_owner": with_owner,
                # the CEILING of what the nerve can attempt on this target:
                "owner_declared_ratio_pct": (round(100 * with_owner / accesses, 1)
                                             if accesses else 0.0),
                "owners_provisioned_for_readback": len(self.by_identity),
            },
            "funnel": {
                "candidates_raised": len(candidates),
                "confirmed_findings": len(findings),
                "abstained_total": len(self.abstained),
                "abstained_by_reason": by_reason,
            },
            "findings": [
                {"resource": f.resource, "accessor": f.accessor,
                 "declared_owner": f.declared_owner, "leaked_fields": list(f.leaked_fields)}
                for f in findings
            ],
            "reach_note": _reach_note(self),
        }


def _reach_note(br) -> str:
    """One honest line on the nerve's reach against THIS target."""
    if len(br.attest._identity) == 0:
        return ("no self endpoint attested any identity — the nerve is blind here; "
                "supply/learn a /me-style endpoint or extend the identity vocabulary")
    if br.ownership.pointer() is None:
        return ("identity known but no ownership field was learnable (need >=2 of a "
                "principal's own resources declaring it) — reach is zero until then")
    records = br.equiv._records
    with_owner = sum(1 for r in records if r.declared_owner is not None)
    if records and with_owner == 0:
        return ("ownership field learned but no probed object declared an owner — this "
                "target hides ownership in bodies; the owner-field signal has no reach here")
    return "nerve had reach on this target (identity + ownership + declared owners present)"


def _rkey(request) -> str:
    from .surface_map import identify
    ri = identify(request)
    return str(ri) if ri is not None else (getattr(request, "path", "") or "?")
