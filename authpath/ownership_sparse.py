"""
㉓ Sparse-target ownership learning (Gap G11) — pure logic.

`ownership_pointer` needs >=2 distinct resources + discriminating values to learn an
ownership field. On sparse targets (one resource per principal) it abstains => lost
recall. Add an ALTERNATIVE signal — a match against an ATTESTED (verified) identity —
that confirms ownership even on a single resource, WITHOUT weakening the old guard.

FP gate: OP-0 keep >=2-source rule OR an attested-identity match (alternative, not a
loosening); OP-1 attested identity must come from a verified source, never guessed;
OP-2 neither >=2-resource nor attested match => still abstain; OP-3 default-OFF.
"""
from __future__ import annotations


def owns_via_attestation(field_value, attested_identity) -> bool:
    """Confirmed ownership iff the field value exactly matches a verified attested
    identity — valid even on a single resource. Not a loosening of the >=2 rule."""
    if not attested_identity or field_value in (None, ""):
        return False
    return str(field_value).strip() == str(attested_identity).strip()


def _distinct_across_principals(values_by_principal) -> bool:
    """Old guard: the field takes >=2 distinct values across >=2 principals."""
    if len(values_by_principal) < 2:
        return False
    distinct = set()
    for s in values_by_principal.values():
        distinct |= set(s)
    return len(distinct) >= 2


def ownership_confidence(values_by_principal, attested=None) -> str:
    """Combine both signals: >=2-source (old) OR attested match (new). Else abstain."""
    if _distinct_across_principals(values_by_principal):
        return "confirmed_two_source"
    if attested:
        for vs in values_by_principal.values():
            for v in vs:
                if owns_via_attestation(v, attested):
                    return "confirmed_attested"
    return "abstain"                                        # OP-2
