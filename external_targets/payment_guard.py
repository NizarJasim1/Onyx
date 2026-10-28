#!/usr/bin/env python3
"""payment_guard.py — INDEPENDENT payment re-confirmation (isolated additions layer).

WHY THIS EXISTS (measured, not assumed — see measure_payment.py):
  The engine's PaymentLaw confirms a bypass when a success exposes amount_paid < amount_due.
  Its amount reader scans the REQUEST body first, so a client-supplied `amount_paid` in the
  request is trusted even when the server's authoritative RESPONSE recomputed a correct
  amount. That is a real false-positive mode: a safe server (which ignored the client's low
  amount and charged the full due) still gets flagged because paid is read from the request.

  onyx_recon.reconfirm passes WRITE findings through untouched ("engine's write audit governs
  them"); a POST /checkout is a write, so PAYMENT findings currently have NO independent
  money gate. This module is that missing second gate.

THE GATE (doubled survival principle — a FP must fool TWO independent systems):
  Re-derive (paid, due) from the SERVER RESPONSE BODY ALONE — its authoritative Δstate.
  A client-supplied request amount is advisory and is NEVER read here.
    * response shows paid < due (or currency mismatch)  -> KEEP  (server's own record proves it)
    * response shows paid >= due                         -> DROP  (server corrected the underpayment)
    * response does not expose both amounts              -> DROP  (unprovable from Δstate; abstain)

  It reuses the engine's OWN proven amount parser (eil._find_amount_with_currency) so it
  handles the same flat/nested/prefixed-currency shapes — zero new parsing logic. It only
  DROPS; it never fabricates a finding and never touches the engine.
"""
from __future__ import annotations
import copy


def _response_only_ctx(exchange):
    """A shallow exchange clone whose REQUEST body is emptied, so the engine's amount
    parser can only read the server's authoritative response — never a client amount."""
    ex = copy.copy(exchange)
    ex.request = copy.copy(exchange.request)
    ex.request.body = {}          # strip client-supplied amounts
    return ex


def payment_reconfirm(exchange):
    """Return (keep: bool, reason: str) for a single PAYMENT exchange, judged on the
    server's response state alone. Import eil lazily so this module stays isolated."""
    from authpath import eil

    class _Ctx:                    # minimal LawContext shim: the parser only reads .exchange
        def __init__(self, ex): self.exchange = ex

    resp = getattr(exchange.response, "body", None)
    if not isinstance(resp, dict) or not resp:
        return False, "no server response body to re-confirm from"

    ctx = _Ctx(_response_only_ctx(exchange))
    due,  cur_due  = eil._find_amount_with_currency(
        ctx, ("due", "total", "amount_due", "subtotal", "grand_total"))
    paid, cur_paid = eil._find_amount_with_currency(
        ctx, ("paid", "amount_paid", "charged", "captured", "amount"))

    if due is None or paid is None:
        return False, ("server response does not expose both amounts — "
                       "underpayment not provable from Δstate (stays a hypothesis)")
    if cur_due and cur_paid and cur_due.upper() != cur_paid.upper():
        return True, (f"server settled across currencies: {paid} {cur_paid} vs "
                      f"{due} {cur_due} — not comparable, conservation breach")
    if paid < due:
        return True, (f"server's own settlement record shows paid={paid} < due={due} "
                      f"(shortfall {round(due - paid, 2)}) — real value-conservation breach")
    return False, (f"server response shows paid={paid} >= due={due} — the client's low "
                   f"amount was corrected server-side (no breach)")


def _find_exchange(capture, finding):
    """Best-effort map a PAYMENT finding to the exchange that produced it, by path.
    Matches the mutating request whose path is named in the finding's endpoint/PoC."""
    path = None
    ref = getattr(finding, "resource_ref", None) or getattr(finding, "target_ref", None)
    poc = getattr(finding, "poc", None)
    if poc and getattr(poc, "steps", None):
        for step in poc.steps:
            for verb in ("POST", "PUT", "PATCH", "DELETE"):
                if verb in step and "/" in step:
                    seg = step.split(verb, 1)[1].strip()
                    path = seg.split()[0].split("?")[0] if seg else None
                    break
            if path:
                break
    best = None
    for ex in capture:
        m = (getattr(ex.request, "method", "") or "").upper()
        if m not in ("POST", "PUT", "PATCH", "DELETE"):
            continue
        p = (getattr(ex.request, "path", "") or "").split("?")[0]
        if path and p == path:
            return ex
        best = ex                  # fall back to the most recent mutating exchange
    return best


def filter_payment_findings(findings, capture):
    """Apply the independent money gate to PAYMENT/FINANCIAL findings; pass all others
    through untouched. Returns (kept, dropped) where dropped = [(finding, reason)].
    Pure — mutates nothing on the engine."""
    kept, dropped = [], []
    for f in findings:
        eff = getattr(f, "effect", None)
        imp = getattr(f, "impact", None)
        is_payment = (getattr(eff, "name", "") == "PAYMENT") or \
                     (getattr(imp, "name", "") == "FINANCIAL")
        if not is_payment:
            kept.append(f)
            continue
        ex = _find_exchange(capture, f)
        if ex is None:
            dropped.append((f, "could not locate settlement exchange to re-confirm"))
            continue
        ok, reason = payment_reconfirm(ex)
        (kept if ok else dropped).append(f if ok else (f, reason))
    return kept, dropped
