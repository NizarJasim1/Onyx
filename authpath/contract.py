"""
② Contract Resolver — §4.3 / D4 / D5.

Resolves each endpoint to an effect-class.  Two hard rules from the WHY doc:

  * D4 — the contract resolves EFFECT-CLASS ONLY, never forbiddenness.  The target
          is untrusted; its contract tells you *what an endpoint does*, not *what is
          safe*.  "Forbidden" comes only from the EIL.
  * D5 — this is the ONLY probabilistic step in the whole engine, and it is
          FAIL-SAFE: a misclassification errs toward MORE scrutiny (flag a
          candidate), never toward silently passing a violation.  Inferred
          classifications carry `high_caution=True`.

So a missing/partial contract only weakens *classification* (fail-safe) and can
never compromise a law's soundness.
"""

from __future__ import annotations

from .models import (
    ClassificationSource,
    EffectClass,
    EffectClassification,
    Exchange,
    HTTPRequest,
)
from .provenance import ValueClass, classify_field, extract_values


class ContractResolver:
    def __init__(self, contract: dict | None = None):
        # contract: { endpoint_key: {"effect": "...", "critical_params": [...]} }
        self.contract = contract or {}
        self._cache: dict[str, EffectClassification] = {}

    def classify(self, ex: Exchange) -> EffectClassification:
        key = ex.request.endpoint_key()
        if key in self._cache:
            return self._cache[key]

        decl = self.contract.get(key)
        if decl:
            cls = EffectClassification(
                endpoint=key,
                effect=EffectClass(decl["effect"]),
                source=ClassificationSource.CONTRACT,
                critical_params=list(decl.get("critical_params", [])),
                high_caution=False,
                notes="declared by target contract",
            )
        else:
            cls = self._infer(ex)
        self._cache[key] = cls
        return cls

    # -- dynamic effect inference (§7.2) — fallback, higher caution ---------- #
    def _infer(self, ex: Exchange) -> EffectClassification:
        req: HTTPRequest = ex.request

        # GraphQL inference (improvement #2): operation-name heuristics. Higher
        # caution, exactly like REST inference — the verdict still needs Δstate.
        if req.is_graphql():
            gql_op = req.graphql_op()
            if gql_op is not None:
                from .graphql import infer_effect_class
                eff_name = infer_effect_class(gql_op)
                effect = EffectClass(eff_name) if eff_name else (
                    EffectClass.OBJECT_ACCESS if gql_op.op_type == "query"
                    else EffectClass.OWNERSHIP
                )
                return EffectClassification(
                    endpoint=req.endpoint_key(),
                    effect=effect,
                    source=ClassificationSource.INFERRED,
                    critical_params=list(gql_op.variables.keys()),
                    high_caution=True,
                    notes=f"GraphQL {gql_op.op_type} '{gql_op.op_name or gql_op.root_fields}' "
                          f"— operation-name heuristic (review before submission)",
                )

        method = req.method.upper()
        path = req.path.lower()
        body = req.body or {}
        resp_body = ex.response.body or {}

        critical: list[str] = []
        effect = EffectClass.NONE

        # Field-shape signals (routing only, never a verdict).
        req_classes = {tv.value_class for tv in extract_values(body)}
        for tv in extract_values(body):
            if tv.value_class in (ValueClass.ROLE,):
                critical.append(tv.field_path)

        has_amount = ValueClass.AMOUNT in req_classes or any(
            classify_field(k, v) == ValueClass.AMOUNT for k, v in _flat(resp_body)
        )
        has_role_field = ValueClass.ROLE in req_classes
        has_coupon = ValueClass.TOKEN in req_classes or "coupon" in path or "promo" in path
        has_qty = ValueClass.QTY in req_classes

        path_id = any(seg.isdigit() for seg in path.split("/"))

        # Priority order chosen so the more security-critical class wins ties
        # (fail-safe toward more scrutiny — D5).
        # RL13: an edit to the authority graph (IAM role/permission grant) is the
        # most security-critical write — checked FIRST so it is never shadowed by
        # the generic OWNERSHIP/AUTHORITY routes.
        from .iam import is_authority_grant
        if is_authority_grant(method, path, body):
            effect = EffectClass.AUTHORITY_GRANT
            critical += [k for k, _ in _flat(body) if "role" in k.lower()]
        elif "checkout" in path or "pay" in path or "settle" in path or has_amount and method in ("POST", "PUT", "PATCH"):
            effect = EffectClass.PAYMENT
            critical += [k for k, _ in _flat(body) if classify_field(k, _g(body, k)) == ValueClass.AMOUNT]
        elif has_coupon and method in ("POST", "PUT", "PATCH"):
            effect = EffectClass.COUPON
        elif has_qty and method in ("POST", "PUT", "PATCH"):
            effect = EffectClass.INVENTORY
        elif "fulfil" in path or "ship" in path or "complete" in path or "approve" in path:
            effect = EffectClass.STATE_GATE
        elif has_role_field and method in ("POST", "PUT", "PATCH"):
            effect = EffectClass.OWNERSHIP
        elif "admin" in path or "manage" in path or "internal" in path:
            effect = EffectClass.AUTHORITY
        elif method in ("PUT", "PATCH", "POST") and path_id:
            effect = EffectClass.OWNERSHIP
        elif method in ("GET", "HEAD") and path_id:
            effect = EffectClass.OBJECT_ACCESS
        elif method in ("GET", "HEAD"):
            effect = EffectClass.READ
        else:
            # Unknown shape: fail-safe to OBJECT_ACCESS so it still gets scrutinised.
            effect = EffectClass.OBJECT_ACCESS

        return EffectClassification(
            endpoint=req.endpoint_key(),
            effect=effect,
            source=ClassificationSource.INFERRED,
            critical_params=sorted(set(critical)),
            high_caution=True,
            notes="inferred (no contract) — elevated scrutiny per D5",
        )


def _flat(body):
    for tv in extract_values(body):
        yield tv.field_path.split(".")[-1].split("[")[0], tv.value


def _g(body, key):
    for tv in extract_values(body):
        if tv.field_path.split(".")[-1].split("[")[0] == key:
            return tv.value
    return None
