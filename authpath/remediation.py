"""
Remediation & Standard Classification (P6) — fix guidance DERIVED FROM the violated
invariant.
====================================================================================

Every other scanner stops at "found an IDOR". ONYX can go further BECAUSE its
findings are tied to a conservation law of a specific effect class: the exact
control that was missing is a function of WHICH invariant broke. This module turns
that structural fact into (1) a precise, law-derived remediation, (2) the standard
taxonomy a triager files under (OWASP API Top-10 + CWE), and (3) a one-line plain-
language TL;DR for a human skimming a queue of reports.

It is pure presentation computed at report time from the finding's effect class — a
FIXED table, true by the definition of each effect class, never learned (RL1). It
changes no detection or confirmation logic, adds no false positive, and weakens
nothing: a finding that was confirmed is still confirmed; this only explains it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import EffectClass


@dataclass(frozen=True)
class TaxonomyEntry:
    owasp_api: str       # OWASP API Security Top 10 (2023) category
    cwe_id: str          # primary CWE
    cwe_name: str
    remediation: str     # the control to add — DERIVED from the violated invariant
    tldr: str            # one-line plain-language summary for a triager


# Each row is true BY THE DEFINITION of the effect class. The remediation states the
# server-side control whose absence the conservation law detected.
EFFECT_TAXONOMY: dict[EffectClass, TaxonomyEntry] = {
    EffectClass.OBJECT_ACCESS: TaxonomyEntry(
        "API1:2023 Broken Object Level Authorization", "CWE-639",
        "Authorization Bypass Through User-Controlled Key",
        "Enforce an ownership check that binds the requested object to the "
        "authenticated principal BEFORE returning it; never trust a client-supplied "
        "object identifier as proof of access.",
        "An authenticated user can read another user's object by changing an ID in the request."),
    EffectClass.OWNERSHIP: TaxonomyEntry(
        "API3:2023 Broken Object Property Level Authorization", "CWE-639",
        "Authorization Bypass Through User-Controlled Key",
        "Verify the authenticated principal owns the resource whose properties are "
        "being mutated; reject ownership transfer or property writes supplied in the "
        "request body.",
        "A user can modify a resource (or its ownership) that belongs to someone else."),
    EffectClass.FIELD_PROJECTION: TaxonomyEntry(
        "API3:2023 Broken Object Property Level Authorization", "CWE-213",
        "Exposure of Sensitive Information Due to Incompatible Policies",
        "Return only the fields the principal is authorized to see; whitelist "
        "response fields per role and per object — never serialize the full object "
        "and rely on the client to hide fields.",
        "The response exposes internal/sensitive fields the user should not see (excessive data exposure)."),
    EffectClass.AUTHORITY: TaxonomyEntry(
        "API5:2023 Broken Function Level Authorization", "CWE-862",
        "Missing Authorization",
        "Enforce a function-level authorization check on this action: verify the "
        "principal's ROLE grants this operation, not merely that they are "
        "authenticated.",
        "An ordinary user can invoke an action restricted to higher-privileged roles (BFLA)."),
    EffectClass.AUTHORITY_GRANT: TaxonomyEntry(
        "API5:2023 Broken Function Level Authorization", "CWE-269",
        "Improper Privilege Management",
        "Constrain every grant so the role/privilege conferred is a subset of the "
        "GRANTER's own authority; reject self-elevation and any grant that exceeds "
        "the grantor's scope.",
        "A user can grant themselves (or others) privileges beyond what the grantor holds — privilege escalation."),
    EffectClass.PAYMENT: TaxonomyEntry(
        "API6:2023 Unrestricted Access to Sensitive Business Flows", "CWE-840",
        "Business Logic Errors",
        "Re-derive the charge server-side from the authoritative price × quantity; "
        "never trust a client-supplied amount, currency, or total.",
        "A user can alter the amount charged (e.g. pay less) by tampering with the payment request."),
    EffectClass.PRICE: TaxonomyEntry(
        "API6:2023 Unrestricted Access to Sensitive Business Flows", "CWE-602",
        "Client-Side Enforcement of Server-Side Security",
        "Compute price server-side from the catalog at transaction time; reject any "
        "client-supplied price or discount field.",
        "A user can set or manipulate an item's price by editing the request."),
    EffectClass.STATE_GATE: TaxonomyEntry(
        "API6:2023 Unrestricted Access to Sensitive Business Flows", "CWE-841",
        "Improper Enforcement of Behavioral Workflow",
        "Enforce the required state precondition server-side before the action; do "
        "not allow a later step to execute when prior workflow steps were skipped.",
        "A user can skip a required prior step (e.g. payment/verification) and still reach a gated action."),
    EffectClass.INVENTORY: TaxonomyEntry(
        "API6:2023 Unrestricted Access to Sensitive Business Flows", "CWE-770",
        "Allocation of Resources Without Limits or Throttling",
        "Decrement and check inventory atomically server-side within the "
        "transaction; reject quantities that exceed available stock or negative "
        "quantities.",
        "A user can order more than the available stock, or abuse quantity to break inventory limits."),
    EffectClass.COUPON: TaxonomyEntry(
        "API6:2023 Unrestricted Access to Sensitive Business Flows", "CWE-837",
        "Improper Enforcement of a Single, Unique Action",
        "Enforce single-use server-side with an atomic claim (e.g. conditional "
        "update); reject any replay of an already-consumed coupon or promotion.",
        "A user can reuse a single-use coupon/promo by replaying the request."),
    EffectClass.TEMPORAL_DRIFT: TaxonomyEntry(
        "API1:2023 Broken Object Level Authorization", "CWE-613",
        "Insufficient Session Expiration",
        "Re-validate authorization on every request against CURRENT state; honor "
        "revocation immediately and do not cache or trust a previously-issued grant "
        "after it has been withdrawn.",
        "A revoked/expired credential is still honored — authorization is stale, not re-checked."),
    EffectClass.CROSS_SURFACE: TaxonomyEntry(
        "API1:2023 Broken Object Level Authorization", "CWE-639",
        "Authorization Bypass Through User-Controlled Key",
        "Apply the SAME ownership check across EVERY surface that exposes the "
        "resource (REST, GraphQL, BFF, internal RPC); a single unguarded surface "
        "defeats the guard on the others.",
        "The resource is protected on one surface but reachable unguarded through another (e.g. GraphQL)."),
    EffectClass.STRUCTURAL_DIVERGENCE: TaxonomyEntry(
        "API5:2023 Broken Function Level Authorization", "CWE-863",
        "Incorrect Authorization",
        "Ensure all code paths to the resource share ONE authorization check; a "
        "privileged or legacy path must not bypass the guard the primary path "
        "enforces.",
        "A privileged or alternate code path reaches the resource while bypassing the main authorization check."),
    EffectClass.AUTH_REGRESSION: TaxonomyEntry(
        "API5:2023 Broken Function Level Authorization", "CWE-863",
        "Incorrect Authorization",
        "A previously-denied action must remain denied; add the authorization "
        "decision as a regression test so a refactor cannot silently re-open it.",
        "An action that used to be correctly denied is now allowed — an authorization regression."),
    EffectClass.EMERGENT_BREAK: TaxonomyEntry(
        "API5:2023 Broken Function Level Authorization", "CWE-863",
        "Incorrect Authorization",
        "A global authorization invariant is violated by the combination of "
        "individually-allowed steps; enforce the invariant centrally rather than per "
        "endpoint so no step sequence can break it.",
        "A sequence of individually-permitted actions combines to break a global authorization rule."),
    EffectClass.IDENTITY_SPOOF: TaxonomyEntry(
        "API2:2023 Broken Authentication", "CWE-290",
        "Authentication Bypass by Spoofing",
        "Key identity ONLY on an immutable, issuer-asserted, signature-verified claim "
        "(e.g. `iss`+`sub`); never on a client-settable claim such as `email`, `upn`, "
        "or an unverified `name`. Verify token audience (`aud`) and issuer (`iss`), and "
        "parse assertions with ONE canonical, strict parser so no parser-differential "
        "lets a forged identity through.",
        "The server trusts a user-settable claim as the identity key, so an attacker can be treated as another user (nOAuth-class account takeover)."),
    EffectClass.CROSS_TENANT: TaxonomyEntry(
        "API1:2023 Broken Object Level Authorization", "CWE-639",
        "Authorization Bypass Through User-Controlled Key",
        "Scope EVERY object lookup to the caller's tenant: resolve ids only within a "
        "tenant predicate, never by a global/wildcard key, and reject sibling- or "
        "legacy-tenant identifiers. The tenant boundary must be enforced server-side on "
        "every surface, not inferred from a client-supplied org/tenant value.",
        "A user in one tenant/org can read or modify another tenant's objects — the isolation boundary is not enforced."),
    EffectClass.PARSER_DIFFERENTIAL: TaxonomyEntry(
        "API2:2023 Broken Authentication", "CWE-436",
        "Interpretation Conflict",
        "Use ONE canonical, strict parser for the security token/assertion, and verify "
        "the signature over the SAME canonicalized bytes the authorization layer reads. "
        "Reject any token that does not round-trip identically; never let a second "
        "parser (XML/JWT/JSON) yield a different subject than the one that was signed.",
        "Two components parse the same token differently, so a forged identity the signer never approved is trusted (SAML-roulette-class bypass)."),
    EffectClass.REBAC_BYPASS: TaxonomyEntry(
        "API1:2023 Broken Object Level Authorization", "CWE-863",
        "Incorrect Authorization",
        "Evaluate the FULL relationship graph server-side on every request (group "
        "membership -> group ownership -> containment); deny access that has no "
        "authorized relationship path to the object. A direct-ownership check alone "
        "misses both illegitimate derived access and relationships that were revoked "
        "upstream.",
        "A user reaches an object with no legitimate relationship path to it — relationship-based (transitive) authorization is broken."),
    EffectClass.CONSISTENCY_WINDOW: TaxonomyEntry(
        "API1:2023 Broken Object Level Authorization", "CWE-613",
        "Insufficient Session Expiration",
        "Make authorization decisions read-your-writes consistent: carry a snapshot/"
        "zookie token so a decision never rides a relationship-cache state older than "
        "the latest revocation. A relationship removed at T must be enforced on every "
        "request after T, not after the cache propagates.",
        "A relationship was just revoked, but the authorization decision still allows access during the cache-propagation window (new-enemy problem)."),
    EffectClass.GRAPHQL_FIELD_AUTHZ: TaxonomyEntry(
        "API3:2023 Broken Object Property Level Authorization", "CWE-213",
        "Exposure of Sensitive Information Due to Incompatible Policies",
        "Enforce field-level authorization on EVERY selected field at any depth or "
        "alias — not only root fields. A restricted field must be denied or nulled "
        "server-side however it is selected (alias, nested selection, fragment); never "
        "authorize the operation and then trust the resolver to hide fields.",
        "A restricted field is returned inside an otherwise-authorized GraphQL query by selecting it via an alias or a nested path (BOPLA / alias smuggling)."),
}

# Safe fallback for any effect class not in the table — no fabricated CWE.
_FALLBACK = TaxonomyEntry(
    "OWASP API Security Top 10 (2023)", "CWE-285",
    "Improper Authorization",
    "Add a server-side authorization check appropriate to this action and verify it "
    "against the authenticated principal's actual permissions.",
    "An authorization control is missing or incorrect for this action.")


def classify(effect: EffectClass) -> TaxonomyEntry:
    """Map an effect class to its standard taxonomy + law-derived remediation.
    Unknown effects get a safe generic entry (CWE-285) — never a fabricated CWE."""
    return EFFECT_TAXONOMY.get(effect, _FALLBACK)


def remediation_block(finding) -> str:
    """Render the report sections: TL;DR, standard classification, and the law-
    derived remediation. Pure presentation; deterministic table lookup."""
    t = classify(finding.effect)
    return "\n".join([
        "## Standard classification",
        f"- **OWASP API:** {t.owasp_api}  ",
        f"- **CWE:** {t.cwe_id} — {t.cwe_name}",
        "",
        "## Remediation (derived from the violated invariant)",
        f"Because the **`{finding.effect.value}`** conservation law was violated, the "
        f"missing control is specific and known:",
        "",
        f"> {t.remediation}",
    ])


def triager_tldr(finding) -> str:
    """One plain-language line for a human skimming a report queue."""
    return classify(finding.effect).tldr
