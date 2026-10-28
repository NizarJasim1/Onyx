"""
CVSS 3.1 derivation for findings (improvement #8).

Pure deterministic: a finding's effect-class + impact + evidence map to a CVSS
vector by table-lookup, and the vector → base-score by the published formulas.
No model, no learning — fully compatible with RL1/RL2.

Mapping is intentionally conservative.  When evidence is missing, we err
toward the lower of two reasonable values (fail-safe: do not inflate scores
the operator cannot defend).
"""

from __future__ import annotations

from math import ceil

from .models import EffectClass, Finding, ImpactClass


# ----- CVSS 3.1 metric scoring tables ---------------------------------- #
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}         # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                              # Attack Complexity
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}                 # Privileges Required (Scope:U)
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}                 # Privileges Required (Scope:C)
_UI = {"N": 0.85, "R": 0.62}                              # User Interaction
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}                   # C/I/A impact


def _round_up_01(x: float) -> float:
    return ceil(x * 10) / 10


def _base_score(av, ac, pr, ui, s, c, i, a) -> float:
    pr_v = _PR_C[pr] if s == "C" else _PR_U[pr]
    iss = 1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a])
    if iss <= 0:
        return 0.0
    impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploit = 8.22 * _AV[av] * _AC[ac] * pr_v * _UI[ui]
    if impact <= 0:
        return 0.0
    raw = (impact + exploit) if s == "U" else 1.08 * (impact + exploit)
    return min(_round_up_01(raw), 10.0)


def derive_vector(f: Finding) -> dict:
    """Map a Finding → CVSS 3.1 metric set.  Conservative: when evidence is
    ambiguous, we pick the LOWER reasonable value to avoid inflated scores."""
    # Attack vector: API findings reachable over the network unless stated.
    av = "N"
    ac = "L"   # findings come with a reproducible single-request PoC
    ui = "N"   # automated single-request reproduction — no user interaction
    # Privileges Required, Scope, Impact CIA — by effect class:
    pr, s, c, i, a = "L", "U", "N", "N", "N"
    eff = f.effect
    detail = (f.state_proof.detail or "")
    if eff == EffectClass.OBJECT_ACCESS:
        # IDOR / data leak. BFLA-class diagnosis broadens scope (any authenticated
        # principal can reach), so we drop PR to None.
        pr = "N" if "BFLA-class" in detail else "L"
        # confidentiality: high if sensitive leak; low for partial non-sensitive.
        sens = "sensitive" in (f.state_proof.before or "").lower() or "SENSITIVE" in (f.state_proof.after or "")
        c = "H" if sens else "L"
    elif eff == EffectClass.OWNERSHIP:
        # BOPLA / mass-assignment: integrity high (server-authoritative field changed).
        pr, i = "L", "H"
        if "role" in detail.lower() or "admin" in (f.title or "").lower():
            s, c, a = "C", "H", "H"   # scope change → privilege escalation
    elif eff == EffectClass.AUTHORITY:
        # BFLA: privilege required depends on whether anon could exercise.
        pr = "N" if f.actor_pid == "anon" else "L"
        c, i = "H", "L"
    elif eff == EffectClass.PAYMENT:
        # Financial integrity breach: scope often changed (impacts revenue).
        i, c = "H", "L"; s = "C"
    elif eff == EffectClass.PRICE:
        i = "H"
    elif eff == EffectClass.STATE_GATE:
        i = "H"   # workflow bypass: integrity violation
    elif eff == EffectClass.INVENTORY:
        i = "L"
    elif eff == EffectClass.COUPON:
        i = "L"
    elif eff == EffectClass.TEMPORAL_DRIFT:
        # Stale authority: a credential that should be dead still reaches private
        # state. Network, low complexity, no UI. Privileges 'low' (holds a — now
        # supposedly revoked — credential). Confidentiality high; integrity low
        # unless the access also mutates (kept conservative).
        pr, c, i = "L", "H", "L"
    elif eff == EffectClass.STRUCTURAL_DIVERGENCE:
        # Authorization-path divergence: an under-privileged principal reaches a
        # privileged serialization path. Network, low complexity, low privileges
        # (an authenticated under-privileged actor). Confidentiality HIGH only when
        # a sensitive value actually crossed the filter; otherwise LOW (the path is
        # reachable but values were emptied). Integrity none, availability none.
        sens = "SENSITIVE" in (f.state_proof.after or "")
        pr, c, i = "L", ("H" if sens else "L"), "N"
    elif eff == EffectClass.FIELD_PROJECTION:
        # A real, populated field leaked through the list view that the canonical
        # detail view filters for the same principal. Confidentiality breach;
        # severity rises with field sensitivity. Network, low complexity, low priv.
        sensitive = "sensitive field" in (f.state_proof.before or "").lower()
        pr, c, i = "L", ("H" if sensitive else "L"), "N"
    return {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s, "C": c, "I": i, "A": a}


def derive_score(f: Finding) -> tuple[float, str, str]:
    """Return (base_score, severity_label, vector_string)."""
    v = derive_vector(f)
    score = _base_score(v["AV"], v["AC"], v["PR"], v["UI"], v["S"], v["C"], v["I"], v["A"])
    if score == 0.0:
        label = "None"
    elif score < 4.0:
        label = "Low"
    elif score < 7.0:
        label = "Medium"
    elif score < 9.0:
        label = "High"
    else:
        label = "Critical"
    vector = ("CVSS:3.1/" + "/".join(f"{k}:{v[k]}" for k in
              ("AV", "AC", "PR", "UI", "S", "C", "I", "A")))
    return score, label, vector
