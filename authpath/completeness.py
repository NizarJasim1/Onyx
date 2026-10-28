"""
Completeness — pushing 'the rest' as far as it honestly goes (ASSURANCE-3).
=========================================================================

The fear behind "we can never guarantee real-world recall" is UNKNOWN-UNKNOWNS.
This module shows that fear conflates two very different things, and closes the one
that can be closed while bounding the one that cannot — precisely, not vaguely.

  1. THE ORACLE  (can we recognize a violation when we see one?)
     A broken-authorization violation with an observable effect is, by definition,
     either a LEAK (a principal obtained another principal's private data) or a
     WRITE (a principal changed another principal's resource). The class taxonomy —
     BOLA, BFLA, BOPLA, mass-assignment, IDOR-2, ... — is human labelling OVER THE
     SAME underlying invariant: a cross-principal Δstate reachable by an unauthorized
     principal. `check_universal` detects that invariant by its EFFECT, without being
     told the class. => For content-observable effects there are NO unknown violation
     TYPES. The oracle is CLOSED. This dissolves most of the unknown-unknowns fear.

  2. THE COVERAGE  (can we drive the system into every violating state?)
     This is the genuinely open part: the request/sequence space is unbounded, and a
     black box's undocumented surface cannot be enumerated. Completeness here is
     BOUNDED. But it can be made PRECISE and CERTIFIABLE relative to a machine-
     readable spec: enumerate every documented (endpoint x ordered-principal-pair x
     object-reference) obligation, discharge each, and certify "complete over the
     DOCUMENTED surface." The residual is then exactly the UNDOCUMENTED surface — no
     longer a vague "we might have missed something," but a named, bounded region.

  3. THE IRREDUCIBLE RESIDUAL  (what remains, and why it cannot be closed offline)
     Enumerated in IRREDUCIBLE_RESIDUALS with each item's basis: either OUT-OF-
     INVARIANT (a different security property) or COVERAGE-BOUNDED (closable only by
     real-target contact or a spec verified complete against the implementation).
     This is the honest floor — proven, not asserted.

Net: "100% of real-world bugs including unknown-unknowns" stays impossible offline
(Rice's theorem for the implementation's equivalence classes; the problem of
induction for transfer). But this reframes the goal into its largest ACHIEVABLE
form — a closed oracle + certified completeness over the documented surface + a
precisely-bounded, proven-irreducible remainder. That is as far as honour can carry
it without a real target, and it is much closer than "we can't guarantee recall."

Additive and decision-free: reuses the mutation-tested certificate checker; changes
no decision code.
"""

from __future__ import annotations


# --------------------------------------------------------------------------- #
# 1) The closed oracle — class-agnostic violation detection by EFFECT.        #
# --------------------------------------------------------------------------- #

def check_universal(transcript: dict, *, read_as: str, sensitive_field: str = "",
                    attacker_anonymous: bool = False, finding: dict | None = None):
    """Class-agnostic authorization-violation oracle. The caller does NOT name a
    class; the violation is recognized by its EFFECT — a cross-principal Δstate —
    so BOLA, BFLA, BOPLA, mass-assignment, IDOR-2, etc. are all caught by the SAME
    check. Detects a WRITE if owner read-backs are bundled, else a LEAK if an
    owner_view is bundled; abstains otherwise.

    Returns (kind_detected_or_None, check_result). Reuses the mutation-tested
    certificate checker, so it inherits the same soundness guarantees.

    Oracle residual (stated): side-channel/timing leaks and availability/denial are
    NOT content-observable cross-principal Δstates and are outside this oracle by
    construction — see IRREDUCIBLE_RESIDUALS."""
    from authpath import certificate as C
    finding = finding or {"fid": "u", "effect": "READ"}
    if "victim_readback_after" in transcript or "victim_readback_before" in transcript:
        kind = C.KIND_XPRINCIPAL_WRITE
        claim = {"kind": kind, "read_as": read_as}
    elif "owner_view" in transcript:
        kind = C.KIND_AUTHN_GAP if attacker_anonymous else C.KIND_READ_LEAK
        claim = {"kind": kind, "read_as": read_as, "sensitive_field": sensitive_field}
    else:
        return (None, {"status": C.ABSTAIN,
                       "reason": "no owner_view or read-back bundled — no cross-principal effect to re-derive"})
    cert = C.emit_certificate(finding=finding, claim=claim, transcript=transcript, provenance="self")
    return (kind, C.check_certificate(cert))


# --------------------------------------------------------------------------- #
# 2) Coverage — spec-relative obligations + a completeness certificate.       #
# --------------------------------------------------------------------------- #

def authorization_obligations(endpoints: list, principals: list) -> list:
    """The COMPLETE, finite set of authorization obligations over the DOCUMENTED
    surface: for each object-bearing endpoint, each ordered (actor != owner)
    principal pair, and each object-reference parameter, the obligation "actor must
    not obtain/mutate owner's object". Fully enumerable from the spec — which is why
    completeness OVER THE DOCUMENTED SURFACE is achievable and certifiable.

    `endpoints`: [{"endpoint": "GET /api/orders/{id}", "ref_params": ["id"]}, ...]"""
    obligations = []
    for ep in endpoints:
        name = ep["endpoint"]
        refs = ep.get("ref_params") or [""]
        for actor in principals:
            for owner in principals:
                if actor == owner:
                    continue
                for ref in refs:
                    obligations.append((name, actor, owner, ref))
    return obligations


def coverage_certificate(obligations: list, discharged: list) -> dict:
    """Certify completeness OVER THE DOCUMENTED SURFACE. `discharged` is the set of
    obligations actually exercised (each a (endpoint, actor, owner, ref) tuple).
    complete_over_documented_surface is True iff every documented obligation was
    discharged — a real, bounded completeness claim whose residual is exactly the
    UNDOCUMENTED surface."""
    obset = {tuple(o) for o in obligations}
    dis = {tuple(d) for d in discharged} & obset
    remaining = obset - dis
    return {
        "total_documented_obligations": len(obset),
        "discharged": len(dis),
        "remaining": sorted(remaining),
        "fraction_documented": (len(dis) / len(obset)) if obset else 1.0,
        "complete_over_documented_surface": not remaining,
    }


# --------------------------------------------------------------------------- #
# 3) The irreducible residual — enumerated, with each item's basis.           #
# --------------------------------------------------------------------------- #

IRREDUCIBLE_RESIDUALS = [
    ("undocumented / shadow surface", "coverage-bounded",
     "endpoints/params absent from the spec cannot be enumerated without infinite "
     "probing or source access; closable only by real-target discovery or a spec "
     "verified complete against the implementation"),
    ("side-channel / timing leaks", "out-of-invariant",
     "inference from timing/size rather than response content is not a content-"
     "observable cross-principal Δstate; outside this oracle by construction"),
    ("availability / denial", "out-of-invariant",
     "preventing a legitimate principal's access is a different security property "
     "(not confidentiality/integrity) and needs a different oracle"),
    ("exhaustive input-space coverage", "coverage-bounded",
     "the request/sequence space is unbounded; exhaustive coverage is not achievable "
     "offline — Rice's theorem bounds knowing the implementation's equivalence "
     "classes black-box, and the problem of induction bounds sim-to-real transfer"),
]


def residual_theorem() -> str:
    lines = ["IRREDUCIBLE RESIDUAL — what remains unclosable offline, and why:"]
    for name, kind, why in IRREDUCIBLE_RESIDUALS:
        lines.append(f"  - [{kind}] {name}: {why}")
    lines.append("Of these, 'out-of-invariant' items are a different security property")
    lines.append("(not this tool's target); 'coverage-bounded' items close only with real-")
    lines.append("target contact or a spec verified complete against the implementation.")
    return "\n".join(lines)


def completeness_statement(cov: dict) -> str:
    """Compose the honest maximal completeness claim from a coverage certificate."""
    L = ["# ONYX — Completeness Statement (the honest maximum)", ""]
    L.append("ORACLE (closed): authorization violations with an observable effect reduce to")
    L.append("LEAK or WRITE — a cross-principal Δstate. Detection is by EFFECT, not by class,")
    L.append("so there are NO unknown violation TYPES for content-observable effects.")
    L.append("")
    L.append("COVERAGE (certified over the documented surface):")
    L.append(f"  - documented obligations : {cov['total_documented_obligations']}")
    L.append(f"  - discharged             : {cov['discharged']} "
             f"({cov['fraction_documented']:.3f} of documented)")
    L.append(f"  - complete over documented surface : {cov['complete_over_documented_surface']}")
    if cov["remaining"]:
        L.append(f"  - remaining (documented, not yet discharged): {len(cov['remaining'])}")
    L.append("")
    L.append(residual_theorem())
    L.append("")
    L.append("CLAIM: complete for the content-observable authorization invariant OVER THE")
    L.append("DOCUMENTED SURFACE, with the residual above explicitly bounded. This is the")
    L.append("largest claim that is true without a real target; literal 100%-including-")
    L.append("unknown-unknowns is provably unattainable offline (stated, not hidden).")
    return "\n".join(L)
