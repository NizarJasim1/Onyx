"""
Evidence Discipline (RL20) — ONYX applies its own 'prove, don't claim' to itself.
==============================================================================

ONYX's whole thesis is "confirm by proof, never by inference" (RL3). The deadliest
attack on the project is therefore SELF-REFUTATION: presenting a number ABOUT ONYX
("recall 5/5", "zero false positives", "beats Hadrian") that is itself an inference
or a self-graded measurement dressed as proof. A judge who lands that lands a fatal
blow.

This module makes that attack structurally impossible to commit by accident, on two
axes (a tier is NOT a single ladder — a by-construction guarantee is a different
KIND of claim, not a weaker one):

  kind:         EMPIRICAL (a measured number)         | STRUCTURAL (a construction)
  independence: INDEPENDENT (third-party target) / SELF (your own) / NONE (estimate)

      T1 = EMPIRICAL + INDEPENDENT   -> the only tier that may say "proven"
      T2 = EMPIRICAL + SELF          -> "measured on a self-authored simulation"
      T3 = EMPIRICAL + NONE          -> "estimated from the mechanism, not measured"
      T4 = STRUCTURAL                -> "guaranteed by construction, not a measured rate"

The tier of a finding is DERIVED from the target's provenance (declared once on the
scope) + its confirmation status — never chosen by the author. The SAME Δstate-
confirmed finding is T2 on a target you built and T1 on crAPI, automatically. The
enforcement is not cosmetic: `assert_no_bare_metrics` fails the build on any metric
emitted without a tier, and the project's own headline claims are sealed in a
manifest the CI re-grades. No surveyed tool (Hadrian, Salt, Akto) attaches a
falsifiable epistemic tier to its own output.

RED LINES. RL1 the tier is DERIVED from declared facts (provenance + confirmation),
never inferred from "looks solid". RL2 grade() is a pure function. RL5 unknown
provenance defaults to the HUMBLEST tier that still fits the evidence (T2 for a
confirmed finding) — you can only ever under-claim by accident, never over-claim.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum


class EvidenceKind(Enum):
    EMPIRICAL = "empirical"      # a measured number
    STRUCTURAL = "structural"    # a guarantee true by construction


class EvidenceTier(Enum):
    #            (rank, kind,                  independent, qualifier)
    T1_INDEPENDENT = (4, EvidenceKind.EMPIRICAL, True,
                      "measured on an independently-designed target")
    T2_SELF_MEASURED = (3, EvidenceKind.EMPIRICAL, False,
                        "measured on a self-authored simulation (not independent)")
    T3_MECHANISM_ESTIMATE = (2, EvidenceKind.EMPIRICAL, False,
                             "estimated from the mechanism, not measured")
    T4_BY_CONSTRUCTION = (1, EvidenceKind.STRUCTURAL, False,
                          "guaranteed by construction, not a measured rate")

    @property
    def rank(self) -> int: return self.value[0]
    @property
    def kind(self) -> EvidenceKind: return self.value[1]
    @property
    def independent(self) -> bool: return self.value[2]
    @property
    def qualifier(self) -> str: return self.value[3]
    @property
    def may_say_proven(self) -> bool: return self is EvidenceTier.T1_INDEPENDENT


class TargetProvenance(Enum):
    SELF = "self"               # you built the target / proving ground
    THIRD_PARTY = "third_party"  # crAPI, VAmPI, Juice Shop, OWASP labs
    LIVE_BOUNTY = "live_bounty"  # a real program / real software (CVE-class)
    UNKNOWN = "unknown"          # fail-safe default

    @property
    def ceiling(self) -> EvidenceTier:
        return {
            TargetProvenance.SELF: EvidenceTier.T2_SELF_MEASURED,
            TargetProvenance.THIRD_PARTY: EvidenceTier.T1_INDEPENDENT,
            TargetProvenance.LIVE_BOUNTY: EvidenceTier.T1_INDEPENDENT,
            TargetProvenance.UNKNOWN: EvidenceTier.T2_SELF_MEASURED,  # humble
        }[self]


def coerce_provenance(value) -> TargetProvenance:
    if isinstance(value, TargetProvenance):
        return value
    try:
        return TargetProvenance((value or "").strip().lower())
    except Exception:
        return TargetProvenance.UNKNOWN


# --------------------------------------------------------------------------- #
# Graders — derived, never chosen (the anti-circularity core).                 #
# --------------------------------------------------------------------------- #

def grade(confirmed: bool, provenance: TargetProvenance) -> EvidenceTier:
    """A CONFIRMED Δstate finding is a measurement; its independence is capped by
    the target's provenance. An unconfirmed candidate is at best a mechanism
    estimate (T3). Pure function -> the same confirmed finding is T1 on crAPI and
    only T2 on a self-built target, automatically and unfudgeably."""
    if not confirmed:
        return EvidenceTier.T3_MECHANISM_ESTIMATE
    return provenance.ceiling


def grade_structural() -> EvidenceTier:
    """A by-construction guarantee (precision via Δstate, determinism, byte-identical
    calibration). Always T4 — a STRUCTURAL claim, never an empirical rate."""
    return EvidenceTier.T4_BY_CONSTRUCTION


# --------------------------------------------------------------------------- #
# Claims — language is bound to tier; 'proven' is reserved for T1.             #
# --------------------------------------------------------------------------- #

@dataclass
class Claim:
    statement: str
    tier: EvidenceTier
    detail: str = ""

    def render(self) -> str:
        tail = f" — {self.detail}" if self.detail else ""
        return f"[{self.tier.name}] {self.statement} ({self.tier.qualifier}){tail}"

    def overclaims_at(self, asserted: EvidenceTier) -> bool:
        return asserted.rank > self.tier.rank


def decompose_fp_claim(demo_n: int = 0,
                       independent_measured: bool = False,
                       provenance: TargetProvenance = TargetProvenance.UNKNOWN) -> list[Claim]:
    """The subtlest self-refutation: an unqualified 'zero false positives' implies a
    measured rate of 0 over all inputs. It is really THREE claims, each at its own
    tier — refuse the unqualified form, emit the decomposition instead."""
    claims = [
        Claim("no finding can be produced without a Δstate delta",
              grade_structural(), "precision is a construction property, not a rate"),
    ]
    if demo_n > 0:
        claims.append(Claim(f"0 false positives observed on the calibration set (n={demo_n})",
                            EvidenceTier.T2_SELF_MEASURED, "a self-authored fixture"))
    if independent_measured and provenance.ceiling is EvidenceTier.T1_INDEPENDENT:
        claims.append(Claim("false-positive rate measured on an independent target",
                            EvidenceTier.T1_INDEPENDENT))
    else:
        claims.append(Claim("an independent false-positive rate is not yet measured",
                            EvidenceTier.T3_MECHANISM_ESTIMATE, "pending P0"))
    return claims


@dataclass
class EvidenceLedger:
    claims: list[Claim] = field(default_factory=list)

    def add(self, statement: str, tier: EvidenceTier, detail: str = "") -> Claim:
        c = Claim(statement, tier, detail); self.claims.append(c); return c

    def audit(self, max_allowed: EvidenceTier = EvidenceTier.T1_INDEPENDENT) -> list[Claim]:
        """Any claim whose tier exceeds the project's real ceiling. With no
        independent target yet, audit(max_allowed=T2) flags every number silently
        presented as independent proof."""
        return [c for c in self.claims if c.tier.rank > max_allowed.rank]

    def render(self) -> str:
        lines = ["EVIDENCE MAP (every claim carries its tier; 'proven' => T1 only):"]
        for c in sorted(self.claims, key=lambda x: -x.tier.rank):
            lines.append("  " + c.render())
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Sealed claim manifest — the project's headline claims, hash-locked so CI can  #
# re-grade them and fail the build if any claim outruns its evidence.          #
# --------------------------------------------------------------------------- #

@dataclass
class ClaimManifest:
    claims: list[Claim] = field(default_factory=list)

    def add(self, statement: str, tier: EvidenceTier, detail: str = "") -> "ClaimManifest":
        self.claims.append(Claim(statement, tier, detail)); return self

    def seal(self) -> str:
        body = "\n".join(f"{c.tier.name}|{c.statement}|{c.detail}"
                         for c in self.claims)
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def verify(self, sealed_hash: str) -> bool:
        return self.seal() == sealed_hash

    def overclaims(self, ceiling: EvidenceTier) -> list[Claim]:
        return [c for c in self.claims if c.tier.rank > ceiling.rank]


# --------------------------------------------------------------------------- #
# The CI gate — enforcement, not decoration.                                  #
# --------------------------------------------------------------------------- #

_BARE_METRIC = re.compile(
    r"(?<![\w.])(\d{1,3}(?:\.\d+)?\s*%"      # 98%, 12.5 %
    r"|\d+\s*/\s*\d+"                          # 5/5, 39/39
    r"|FP\s*=\s*\d+"                           # FP=0
    r"|(?:recall|precision)\s*[:=]\s*\d)",     # recall: 1
    re.IGNORECASE)

_TIER_NEARBY = re.compile(r"T[1-4]_|EVIDENCE|tier|by construction|self-authored|"
                          r"independently|estimated|simulation|not measured", re.IGNORECASE)


def assert_no_bare_metrics(text: str) -> None:
    """Fail if a quantitative claim appears WITHOUT a tier qualifier nearby. This is
    the load-bearing enforcement: a metric a judge can read must carry its evidence
    class. Used as a CI gate over rendered reports / summaries / READMEs."""
    for m in _BARE_METRIC.finditer(text):
        window = text[max(0, m.start() - 80): m.end() + 80]
        if not _TIER_NEARBY.search(window):
            raise AssertionError(
                f"bare metric without an evidence tier: {m.group(0)!r} "
                f"(context: ...{window.strip()[:120]}...)")


# --------------------------------------------------------------------------- #
# The strongest claim that is 100% defensible at the CURRENT evidence state.   #
# --------------------------------------------------------------------------- #

def strongest_honest_claim(has_independent_recall: bool,
                           has_baseline_delta: bool,
                           has_real_cve_or_bounty: bool) -> str:
    if has_real_cve_or_bounty:
        return ("A fully deterministic, black-box authorization engine with a real-world "
                "confirmed vulnerability (CVE/bounty) — independently validated.")
    if has_independent_recall and has_baseline_delta:
        return ("A fully deterministic, black-box authorization engine whose recall and "
                "false-positive rate are measured on an independently-designed target and "
                "compared head-to-head against a baseline tool.")
    if has_independent_recall:
        return ("A fully deterministic, black-box authorization engine whose recall is "
                "measured on an independently-designed target; a baseline comparison is next.")
    return ("A fully deterministic, black-box authorization engine whose precision is "
            "guaranteed BY CONSTRUCTION (Δstate confirmation, not a measured rate), verified "
            "end-to-end on real HTTP against a sealed oracle, occupying a position no surveyed "
            "tool holds — with independent measurement on a third-party target as the declared, "
            "in-progress next step. No number here is presented as independent proof.")


def evidence_stamp(confirmed: bool, provenance: TargetProvenance) -> str:
    tier = grade(confirmed, provenance)
    how = "independently measured" if tier.may_say_proven else "self-measured (not independent)"
    return f"EVIDENCE TIER: {tier.name} — {tier.qualifier}. Δstate-confirmed and {how}."
