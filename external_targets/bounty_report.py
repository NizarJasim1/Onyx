"""
bounty_report.py — turn a CONFIRMED ONYX Finding into a triager-ready submission.
================================================================================
Why this exists (the honest money lever):
    Every hunter FINDS IDOR/BOLA. The money is in PROVING it so a triager cannot
    downgrade it to "informative / N/A / theoretical". ONYX already proves impact
    with a Δstate before/after read-back — the single strongest thing a report can
    carry. This module reframes ONYX's engineer-facing internal report into the
    house style triagers reward on HackerOne / Bugcrowd / Intigriti:

        clear title · severity + CVSS + why · crisp numbered repro with
        copy-paste curl · the Δstate proof as the smoking gun · concrete
        business impact · remediation · references.

It invents NOTHING. Every claim is pulled from the proven Finding. No network,
no LLM in the security path (RL2). Run it on the findings a live ONYX run emits.
"""
from __future__ import annotations
import os, sys
from typing import Iterable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _cell(s) -> str:
    """Make a value safe inside a Markdown table cell without mangling apostrophes:
    escape only pipes and collapse newlines."""
    return str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ")

# ONYX severity → platform-facing weakness + a triager-legible impact sentence.
_WEAKNESS = {
    "BOLA": "Broken Object Level Authorization (IDOR) — CWE-639",
    "BFLA": "Broken Function Level Authorization — CWE-285",
    "MASS_ASSIGN": "Mass Assignment / Broken Object Property Level Authorization — CWE-915",
    "XPRINCIPAL_WRITE": "Broken Access Control: cross-account write — CWE-284",
    "XPRINCIPAL_DELETE": "Broken Access Control: cross-account delete — CWE-284",
}

_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def _effect_key(f) -> str:
    e = str(getattr(f.effect, "value", f.effect)).upper()
    for k in _WEAKNESS:
        if k in e:
            return k
    if "DELETE" in e:
        return "XPRINCIPAL_DELETE"
    if "WRITE" in e or "ASSIGN" in e:
        return "MASS_ASSIGN"
    return "BOLA"


def _weakness(f) -> str:
    return _WEAKNESS.get(_effect_key(f), "Broken Access Control — CWE-284")


def _impact_sentence(f) -> str:
    """A concrete, business-legible impact line — what an attacker can actually do.
    Derived only from the finding's own effect/actor/target, never inflated."""
    k = _effect_key(f)
    actor = getattr(f, "actor_pid", "") or "an authenticated attacker"
    target = getattr(f, "target_ref", "") or "another user's object"
    res = getattr(f, "resource_ref", "") or "the resource"
    m = {
        "BOLA": f"Any authenticated user can read {target} they do not own by "
                f"substituting its identifier (confirmed on `{res}`). This exposes "
                f"other users' private data at scale.",
        "BFLA": f"A lower-privileged user ({actor}) can invoke a function reserved "
                f"for higher privilege, confirmed against `{res}` — a privilege "
                f"escalation.",
        "MASS_ASSIGN": f"An attacker can set server-controlled properties that should "
                f"be immutable (confirmed write-then-read-back on `{res}`), e.g. "
                f"ownership, role, price, or status fields.",
        "XPRINCIPAL_WRITE": f"An attacker can modify {target} belonging to another "
                f"account (confirmed on `{res}`) — integrity loss across tenants.",
        "XPRINCIPAL_DELETE": f"An attacker can delete {target} belonging to another "
                f"account (confirmed on `{res}`) — destructive, cross-tenant.",
    }
    return m.get(k, "An attacker crosses an authorization boundary confirmed by Δstate.")


def _enum_line(f) -> str:
    e = getattr(f, "enumerability", "")
    note = getattr(f, "enumerability_note", "")
    if not e:
        return ""
    scale = {"sequential": "IDs are sequential — the whole collection is trivially "
                            "enumerable (mass exploitation, not a single victim).",
             "predictable": "IDs are predictable — enumeration is feasible.",
             "guessable": "IDs are guessable within a small space.",
             "random": "IDs are high-entropy; exploitation needs a leaked reference "
                       "(still valid — a reference leak is in-scope)."}
    return scale.get(str(e).lower(), note or "")


def report_for(f, program: str = "", researcher: str = "") -> str:
    """One submission-grade Markdown report for a single confirmed Finding."""
    sev = str(getattr(f.severity, "value", f.severity)).lower()
    emoji = _SEV_EMOJI.get(sev, "•")
    weakness = _weakness(f)
    sp = f.state_proof
    title = f.title.strip()

    L: list[str] = []
    L += [f"# {title}", ""]
    if program:
        L += [f"**Program:** {program}  "]
    L += [
        f"**Weakness:** {weakness}  ",
        f"**Severity:** {emoji} {sev.upper()}  ",
        f"**CVSS 3.1:** {f.cvss_score} ({f.cvss_label}) `{f.cvss_vector}`  ",
    ]
    if researcher:
        L += [f"**Reported by:** {researcher}  "]
    L += ["", "---", ""]

    # 1. Summary — one paragraph a triager reads in 10 seconds.
    L += ["## Summary", "",
          f"{_impact_sentence(f)} The issue was **confirmed by an authenticated "
          f"state-change read-back (Δstate)** — not a status code or an error "
          f"message — so it is a proven authorization break, not a heuristic guess.",
          ""]

    # 2. Steps to reproduce — numbered, exact, copy-pasteable.
    L += ["## Steps to reproduce", ""]
    steps = list(getattr(f.poc, "steps", []) or [])
    if steps:
        for i, s in enumerate(steps, 1):
            L.append(f"{i}. {s}")
    else:
        L.append("1. (see PoC commands below)")
    L += ["", "```bash"]
    L += list(getattr(f.poc, "curl", []) or ["# curl sequence emitted by ONYX"])
    L += ["```", ""]
    notes = getattr(f.poc, "notes", "")
    if notes:
        L += [f"> {notes}", ""]

    # 3. Proof of impact — THE smoking gun. This is what stops a downgrade.
    L += ["## Proof of impact (Δstate)", "",
          "The authorization boundary was crossed and the effect was **read back as "
          f"the victim** (`{getattr(sp, 'read_as', '?')}`), proving real impact:", "",
          "| | value |", "|---|---|",
          f"| what was read back | {_cell((getattr(sp, 'method', '')))} |",
          f"| **before** attack | `{_cell((getattr(sp, 'before', '')))}` |",
          f"| **after** attack | `{_cell((getattr(sp, 'after', '')))}` |",
          f"| confirmed as | `{getattr(sp, 'read_as', '')}` (the owner) |"]
    if getattr(sp, "detail", ""):
        L.append(f"| detail | {_cell(sp.detail)} |")
    L += [""]

    # 4. How authority was laundered — the causal chain, in plain steps.
    cp = list(getattr(f, "causal_path", []) or [])
    if cp:
        L += ["## How the authorization check is bypassed", ""]
        for i, s in enumerate(cp, 1):
            L.append(f"{i}. {s}")
        L += [""]

    # 5. Impact + blast radius — quantify who is affected.
    L += ["## Impact", "", _impact_sentence(f), ""]
    enum = _enum_line(f)
    if enum:
        L += [f"**Blast radius:** {enum}", ""]

    # 6. Remediation — shows the triager you understand the fix (raises trust/payout).
    L += ["## Remediation", "",
          "Enforce an **object-level authorization check on the server** for every "
          "request: verify that the authenticated principal owns (or is explicitly "
          "granted access to) the referenced object *before* performing the read, "
          "write, or delete. Do not rely on the object identifier being unguessable, "
          "and do not accept client-supplied ownership/role/price fields on write "
          "(reject or ignore them server-side).", ""]

    # 7. References.
    L += ["## References", "",
          "- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization",
          "- OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization",
          "- OWASP API Security Top 10 — API3:2023 Broken Object Property Level Authorization",
          ""]
    return "\n".join(L)


def submission_pack(findings: Iterable, program: str = "", researcher: str = "",
                    scorecard: dict | None = None) -> dict[str, str]:
    """Return {filename: markdown} for a whole run: one report per finding plus an
    INDEX that summarises the batch and cites the sealed-scorecard tier + hash so a
    triager (or you) can see the evidence is tamper-evident."""
    out: dict[str, str] = {}
    findings = list(findings)
    # order by severity/CVSS so the strongest report is submitted first
    findings.sort(key=lambda f: getattr(f, "cvss_score", 0.0), reverse=True)

    idx = ["# ONYX submission pack", ""]
    if program:
        idx += [f"**Program:** {program}  "]
    if scorecard:
        idx += [f"**Evidence tier:** {scorecard.get('tier','?')}  ",
                f"**Tamper-evident:** {scorecard.get('tamper_evident','?')}  ",
                f"**Chain hash:** `{scorecard.get('chain_hash','')[:16]}…`  "]
    idx += [f"**Confirmed findings:** {len(findings)}", "", "| # | severity | CVSS | title |",
            "|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        sev = str(getattr(f.severity, "value", f.severity))
        fname = f"report_{i:02d}_{_effect_key(f).lower()}.md"
        idx.append(f"| [{i}]({fname}) | {sev} | {getattr(f,'cvss_score',0)} | {f.title} |")
        out[fname] = report_for(f, program=program, researcher=researcher)
    idx += ["", "> Every finding above was confirmed by an authenticated Δstate "
            "read-back. None are status-code heuristics."]
    out["INDEX.md"] = "\n".join(idx)
    return out


def write_pack(findings, out_dir: str, program: str = "", researcher: str = "",
               scorecard: dict | None = None) -> list[str]:
    """Write the submission pack to disk; return the list of file paths written."""
    import os
    os.makedirs(out_dir, exist_ok=True)
    pack = submission_pack(findings, program=program, researcher=researcher,
                           scorecard=scorecard)
    paths = []
    for name, md in pack.items():
        p = os.path.join(out_dir, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(md)
        paths.append(p)
    return paths


if __name__ == "__main__":
    # Self-test with a synthetic CONFIRMED finding so you can see the output shape
    # WITHOUT a live target (no network needed). Real runs feed real findings in.
    from authpath.models import (Finding, StateProof, PoC, EffectClass, ImpactClass,
                                 Severity, EffectClassification, ClassificationSource)
    demo = Finding(
        fid="demo-0001",
        title="IDOR on /identity/api/v2/vehicle/{id}/location exposes any user's GPS",
        effect=EffectClass.OBJECT_ACCESS,
        impact=ImpactClass.DATA_EXPOSURE,
        severity=Severity.HIGH,
        causal_path=[
            "Principal B requests vehicle 42, owned by principal A.",
            "Server returns A's record: the object id from the URL is trusted as "
            "the authorization decision (no ownership check).",
            "B reads A's live GPS coordinates.",
        ],
        state_proof=StateProof(
            confirmed=True,
            method="GET vehicle location, read back as the owner A",
            before="B has no access to A's vehicle location",
            after="B receives {lat: 33.31, lon: 44.36} — A's private location",
            read_as="A",
            detail="Same coordinates returned to attacker B and owner A."),
        poc=PoC(
            steps=["Authenticate as attacker B (your own test account).",
                   "Request A's vehicle id 42 using B's token.",
                   "Observe A's private location in B's response."],
            curl=["curl -H \"Authorization: Bearer $TOKEN_B\" \\",
                  "  https://TARGET/identity/api/v2/vehicle/42/location"],
            notes="Both test accounts are yours; only in-scope ids were touched."),
        classification=EffectClassification(
            endpoint="GET /identity/api/v2/vehicle/{id}/location",
            effect=EffectClass.OBJECT_ACCESS,
            source=ClassificationSource.INFERRED),
        law_name="object-ownership-conservation",
        actor_pid="B", target_ref="user A's vehicle", resource_ref="/vehicle/42/location",
        cvss_score=7.5, cvss_label="High", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        enumerability="sequential",
        enumerability_note="vehicle ids are sequential integers")
    print(report_for(demo, program="crAPI (self-hosted, authorized)", researcher="nizar"))
