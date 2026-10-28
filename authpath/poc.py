"""
⑦ Evidence→PoC Emitter — §4.6 / RL4 / D9.

A detection that cannot be reported is NOT done. Every CONFIRMED finding emits:
  (a) the causal path  — which value, from which principal's response, granted
      itself which authority;
  (b) a reproducible PoC — the minimal request sequence (curl) that reproduces it;
  (c) an impact narrative — pulled from the violated law's `impact_class`.
The violated invariant names its own impact, so the report writes itself. An
anomaly score cannot do this — it does not know WHY its deviation matters.

The only place an LLM may touch this (RL2): polishing the human-readable prose of
a report that is ALREADY fully proven by the structured evidence above. Off the
hot path, never making a security decision. That hook is left as `draft_prose`.
"""

from __future__ import annotations

import json
import uuid

from .cvss import derive_score
from .models import (
    Candidate,
    classify_enumerability,
    EffectClass,
    Finding,
    ImpactClass,
    PoC,
    Severity,
    StateProof,
    ValueOrigin,
)

_SEV_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def _bump_severity(s: Severity) -> Severity:
    if s == Severity.LOW:
        return Severity.MEDIUM
    if s == Severity.MEDIUM:
        return Severity.HIGH
    return Severity.CRITICAL


# law impact-class → default severity (true by impact definition, not learned)
SEVERITY = {
    ImpactClass.FINANCIAL: Severity.CRITICAL,
    ImpactClass.PRICE_TAMPERING: Severity.HIGH,
    ImpactClass.PRIVILEGE_ESCALATION: Severity.CRITICAL,
    ImpactClass.FUNCTION_AUTHZ: Severity.HIGH,
    ImpactClass.DATA_EXPOSURE: Severity.HIGH,
    ImpactClass.WORKFLOW_BYPASS: Severity.HIGH,
    ImpactClass.INVENTORY_ABUSE: Severity.MEDIUM,
    ImpactClass.COUPON_ABUSE: Severity.MEDIUM,
    ImpactClass.TEMPORAL_DRIFT: Severity.HIGH,
    ImpactClass.AUTHZ_PATH_DIVERGENCE: Severity.HIGH,
    ImpactClass.FIELD_PROJECTION_LEAK: Severity.HIGH,
}


from . import remediation as _remediation
from . import evidence as _evidence


class PoCEmitter:
    def __init__(self, target_provenance: str = "self") -> None:
        # RL20: who designed the target — sets the evidence tier the report may
        # claim (self -> T2, third_party -> T1). Humble default; never over-claims.
        self.target_provenance = target_provenance

    def _resource_ref(self, cand: Candidate) -> str:
        """The concrete resource id accessed in the violating request (first object id in
        the path/query), used by the deficiency #1 policy gate to look up the resource's
        established tenant domain. Best-effort; empty when no id is addressable."""
        try:
            oids = cand.exchange.request.object_ids()
            return str(oids[0]) if oids else ""
        except Exception:
            return ""

    def emit(self, cand: Candidate, proof: StateProof) -> Finding:
        impact = cand.verdict.impact or ImpactClass.DATA_EXPOSURE
        causal = self._causal_path(cand, proof)
        poc = self._poc(cand, proof)
        severity = SEVERITY.get(impact, Severity.MEDIUM)
        # Sensitivity escalation (improvement #7): leak of any field in the
        # closed SENSITIVE_FIELDS vocabulary escalates the report by one rank.
        # The proof.before / proof.after text was authored by the confirmer with
        # a `sensitive fields` marker exactly so this escalation is deterministic.
        if "sensitive fields" in (proof.before or "").lower() or "SENSITIVE" in (proof.after or ""):
            severity = _bump_severity(severity)
        # BFLA-class diagnosis is structurally broader → escalate as well.
        if "BFLA-class" in (proof.detail or ""):
            impact = ImpactClass.FUNCTION_AUTHZ
            severity = max(severity, Severity.HIGH, key=lambda s: _SEV_ORDER[s])
        # Bypass-shape escalation (dev idea #1): reaching the object THROUGH a
        # known bypass shape proves an authorization control exists and is being
        # circumvented — strictly worse than authz simply being absent. Escalate
        # one rank. (Detection already fired; this only sharpens severity.)
        if (cand.verdict.evidence or {}).get("bypass_kind"):
            severity = _bump_severity(severity)
        # The finding's effect is the LAW's effect (verdict.effect), which is the
        # accurate one for cross-cutting laws like TEMPORAL_DRIFT that ride on a
        # request classified as something else (e.g. OBJECT_ACCESS).
        law_effect = getattr(cand.verdict, "effect", None) or cand.classification.effect
        finding = Finding(
            fid="AP-" + uuid.uuid4().hex[:8].upper(),
            title=self._title(cand),
            effect=law_effect,
            impact=impact,
            severity=severity,
            causal_path=causal,
            state_proof=proof,
            poc=poc,
            classification=cand.classification,
            law_name=cand.verdict.law_name,
            actor_pid=cand.exchange.principal.pid,
            target_ref=self._target_ref(cand, proof),
            resource_ref=self._resource_ref(cand),
        )
        # Improvement #8: deterministic CVSS 3.1 vector + score from the
        # confirmed finding's facts.  Computed AFTER severity escalation so
        # sensitive/BFLA enrichments are reflected in the vector.
        score, label, vector = derive_score(finding)
        finding.cvss_score = score
        finding.cvss_label = label
        finding.cvss_vector = vector
        # Blast-radius classification (dev idea #3) — only meaningful for
        # object-access findings, where an exposed id implies a reachable set.
        if cand.classification.effect == EffectClass.OBJECT_ACCESS:
            oid = str((cand.verdict.evidence or {}).get("object_id", "")
                      or finding.target_ref)
            level, note = classify_enumerability(oid)
            finding.enumerability = level
            finding.enumerability_note = note
        finding.report_markdown = self._markdown(finding, cand)
        return finding

    # -- causal path ------------------------------------------------------- #
    def _target_ref(self, cand: Candidate, proof: StateProof) -> str:
        """The object/owner the authority was laundered against (for the graph)."""
        ev = cand.verdict.evidence or {}
        if ev.get("object_id"):
            return str(ev["object_id"])
        oids = cand.exchange.request.object_ids()
        if oids:
            return oids[0]
        order = str((cand.exchange.request.body or {}).get("order_id", ""))
        if order:
            return order
        if proof.read_as and proof.read_as != cand.exchange.principal.pid:
            return proof.read_as
        return "function"

    def _causal_path(self, cand: Candidate, proof: StateProof) -> list[str]:
        ex = cand.exchange
        steps = [
            f"Principal '{ex.principal.pid}' issued "
            f"{ex.request.method} {ex.request.path} and received {ex.response.status}.",
        ]
        origin: ValueOrigin | None = cand.causal_origin or cand.verdict.evidence.get("laundered_from")
        if origin is not None:
            steps.append(
                f"The decisive value originated in principal '{origin.principal_id}'"
                f"'s response to {origin.endpoint} (field {origin.field_path}) — "
                f"it was never granted to '{ex.principal.pid}'."
            )
        steps.append(f"EIL law violated → {cand.verdict.law_name}: {cand.verdict.reason}")
        law_effect = getattr(cand.verdict, "effect", None) or cand.classification.effect
        if law_effect == EffectClass.STRUCTURAL_DIVERGENCE:
            ev = cand.verdict.evidence or {}
            steps.append(
                f"Gate 1 (coherence breach): the value-blind fingerprint fits the "
                f"higher-privilege grammar of '{ev.get('matched')}' (rank "
                f"{ev.get('matched_rank')}) but NOT '{ev.get('acting')}'s own grammar "
                f"(rank {ev.get('acting_rank')}) on family {ev.get('family')}."
            )
            steps.append(
                f"Gate 2 (dimensional control): a genuinely lower-privilege principal "
                f"does NOT receive this shape — so the richness is authorization-driven, "
                f"not object-driven or by-design."
            )
            steps.append(
                f"Gate 3 (functional anchor): privileged-only path(s) "
                f"{ev.get('diverging_paths')} are present in the under-privileged "
                f"response (PRESENT_NULL where the owner sees PRESENT_POPULATED) — the "
                f"branch executed, then output filtering emptied the values."
            )
        bypass_detail = (cand.verdict.evidence or {}).get("bypass_detail")
        if bypass_detail:
            steps.append(
                f"Authorization control was CIRCUMVENTED, not absent: {bypass_detail}. "
                f"The server enforces a check that this request shape evades."
            )
        cross_method = (cand.verdict.evidence or {}).get("cross_method_note")
        if cross_method:
            steps.append(f"Cross-method corroboration: {cross_method}.")
        steps.append(
            f"Confirmed by Δstate via {proof.method}: "
            f"BEFORE [{proof.before}] → AFTER [{proof.after}] (read back as '{proof.read_as}')."
        )
        return steps

    # -- reproducible PoC -------------------------------------------------- #
    def _poc(self, cand: Candidate, proof: StateProof) -> PoC:
        ex = cand.exchange
        host = ex.request.host or "TARGET"
        attacker_curl = _curl(ex.request, host, ex.principal.pid)
        readback_curl = _curl(
            type(ex.request)("GET", _readback_path(cand), host=host),
            host, proof.read_as,
        )
        steps = [
            f"As '{ex.principal.pid}', send: {ex.request.method} {ex.request.path}"
            + (f" with body {json.dumps(ex.request.body)}" if ex.request.body else ""),
            f"Observe the privileged effect succeed ({ex.response.status}).",
            f"As the legitimate owner '{proof.read_as}', read the state back to "
            f"confirm the change/leak persisted.",
        ]
        return PoC(steps=steps, curl=[attacker_curl, readback_curl],
                   notes="Replace $TOKEN_<pid> with each principal's session credential. "
                         "Run only within authorised program scope.")

    # -- prose ------------------------------------------------------------- #
    def _title(self, cand: Candidate) -> str:
        titles = {
            EffectClass.OBJECT_ACCESS: "IDOR / BOLA — cross-principal object access",
            EffectClass.OWNERSHIP: "Mass Assignment / BOPLA — privileged field overwrite",
            EffectClass.AUTHORITY: "BFLA — privileged function reachable without authority",
            EffectClass.PAYMENT: "Payment Tampering — settlement below amount due",
            EffectClass.PRICE: "Price Manipulation — client total trusted as authoritative",
            EffectClass.STATE_GATE: "Business-Logic — workflow gate skipped",
            EffectClass.INVENTORY: "Inventory Abuse — out-of-bounds quantity accepted",
            EffectClass.COUPON: "Promotion Abuse — single-use token replayed",
            EffectClass.TEMPORAL_DRIFT: "Stale Authorization — credential valid after revocation",
            EffectClass.STRUCTURAL_DIVERGENCE:
                "Authorization-Path Divergence — privileged code path reachable by "
                "under-privileged principal",
            EffectClass.FIELD_PROJECTION:
                "Inconsistent Field Projection — list view over-exposes a field the "
                "detail view filters",
        }
        law_effect = getattr(cand.verdict, "effect", None) or cand.classification.effect
        return titles.get(law_effect, "Authorization violation")

    def _markdown(self, f: Finding, cand: Candidate) -> str:
        cls = cand.classification
        lines = [
            f"# {f.title}",
            "",
            f"**Finding ID:** `{f.fid}`  ",
            f"**Severity:** {f.severity.value}  ",
            f"**CVSS 3.1:** {f.cvss_score} ({f.cvss_label})  `{f.cvss_vector}`  ",
            f"**Impact class:** {f.impact.value}  ",
            f"**Effect-class:** `{f.effect.value}`  ",
            f"**Endpoint:** `{cand.exchange.request.endpoint_key()}`  ",
            f"**Classification source:** {cls.source.value}"
            + (" *(inferred — elevated scrutiny)*" if cls.high_caution else ""),
            "",
            f"**TL;DR:** {_remediation.triager_tldr(f)}  ",
            "",
            "## Summary",
            f"The action violates the conservation law **{f.law_name}**, "
            f"which is true by the definition of the `{f.effect.value}` effect-class. "
            f"The violation was **confirmed by proven Δstate**, not a status-code diff.",
            "",
            f"{_evidence.evidence_stamp(True, _evidence.coerce_provenance(self.target_provenance))}",
            "",
            "## Causal path (proof)",
        ]
        for i, step in enumerate(f.causal_path, 1):
            lines.append(f"{i}. {step}")
        lines += ["", "## Proof of Δstate", "```",
                  f"method : {f.state_proof.method}",
                  f"before : {f.state_proof.before}",
                  f"after  : {f.state_proof.after}",
                  f"read as: {f.state_proof.read_as}",
                  f"detail : {f.state_proof.detail}", "```", "",
                  "## Reproduction (PoC)"]
        for i, step in enumerate(f.poc.steps, 1):
            lines.append(f"{i}. {step}")
        lines += ["", "```bash"] + f.poc.curl + ["```", "", f"> {f.poc.notes}", "",
                  "## Impact", f"{f.impact.value}.", ""]
        if f.enumerability_note:
            lines += [f"**Blast radius ({f.enumerability}):** {f.enumerability_note}.", ""]
        lines += ["", _remediation.remediation_block(f)]
        return "\n".join(lines)

    # -- optional, off-hot-path prose polish (RL2) ------------------------- #
    def draft_prose(self, finding: Finding, llm_callable=None) -> str:  # pragma: no cover
        """Optional: hand an ALREADY-PROVEN finding to an LLM only to improve the
        human prose of the report. The LLM makes no security decision (RL2)."""
        if llm_callable is None:
            return finding.report_markdown
        prompt = ("Rewrite this already-proven vulnerability report to be clear and "
                  "submittable. Do not add, infer, or change any technical claim; only "
                  "improve readability:\n\n" + finding.report_markdown)
        return llm_callable(prompt)


def _curl(req, host: str, pid: str) -> str:
    parts = [f"curl -X {req.method}", f"'https://{host}{req.path}'",
             f"-H 'Authorization: Bearer $TOKEN_{pid}'"]
    if req.body:
        parts.append("-H 'Content-Type: application/json'")
        parts.append(f"-d '{json.dumps(req.body)}'")
    return " ".join(parts)


def _readback_path(cand: Candidate) -> str:
    p = cand.exchange.request.path
    if cand.classification.effect in (EffectClass.PAYMENT, EffectClass.STATE_GATE):
        oid = str((cand.exchange.request.body or {}).get("order_id", "")) or next(
            (s for s in p.split("/") if s.isdigit()), "")
        return f"/api/orders/{oid}"
    return p
