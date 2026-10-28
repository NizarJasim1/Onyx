"""
Detector comparison (P2) — ONYX vs an Autorize-equivalent baseline on the SAME
labeled traffic.
=================================================================================

Runs both detectors over the demo's labeled probes (each carries a ground-truth
`expect` of "finding"/"clean") and computes precision / recall / F1 for each. The
baseline is given a full-strength owner reference: for every probe it is handed the
largest 2xx response any principal receives for that request — the "high-privilege
original" Autorize would have from the privileged walk — so its length discriminator
is at maximum power.

This is a SELF-BUILT, controlled comparison: the target and the traffic are ours, so
the result is **T2 (self-measured)**, not independent proof. The independent run
(the real Autorize against a third-party target such as crAPI) is P0. The harness
stamps its own output with that tier; it never claims more than it measured.
"""

from __future__ import annotations

from dataclasses import dataclass

from .baseline import AutorizeBaseline


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def add(self, predicted: bool, actual: bool) -> None:
        if predicted and actual:      self.tp += 1
        elif predicted and not actual: self.fp += 1
        elif not predicted and actual: self.fn += 1
        else:                          self.tn += 1


def _owner_reference(target, request, principals):
    """The largest 2xx response any principal gets for this request — the strongest
    possible 'high-privilege original' to feed the baseline's length discriminator."""
    from .transport import make_exchange
    best = None
    best_len = -1
    for p in principals.values():
        try:
            ex = make_exchange(target, request, p)
            resp = ex.response
        except Exception:
            continue
        if resp is None or not (200 <= int(getattr(resp, "status", 0) or 0) < 300):
            continue
        n = len(str(getattr(resp, "body", "") or ""))
        if n > best_len:
            best_len, best = n, resp
    return best


def run_comparison(engine_factory) -> dict:
    """Drive a fresh engine through the labeled demo, then score ONYX and the
    Autorize-equivalent baseline against the same ground truth. Returns a dict with
    both detectors' metrics, a per-case table, and the evidence tier."""
    from . import baseline as _baseline  # noqa
    from .transport import MockTarget, make_exchange
    from fixtures.demo_scenario import build_principals, build_contract, build_steps

    principals = build_principals()
    target = MockTarget()
    contract = build_contract()
    engine = engine_factory(target, principals, contract)
    for flag in ("provisional_leads", "active_probing", "chain_provenance",
                 "temporal_drift", "cross_surface", "temporal_shape",
                 "combinatorial", "global_invariants"):
        setattr(engine, flag, True)

    steps = build_steps()
    bl = AutorizeBaseline()
    onyx_m, base_m = Metrics(), Metrics()
    rows = []

    probe_idx = 0
    for step in steps:
        p = principals[step.principal]
        ex = make_exchange(target, step.request, p)
        if step.kind == "seed":
            engine.observe(ex)
            continue
        # probe: ONYX prediction = did this probe become a confirmed finding?
        engine.analyze(ex)
        tr = engine.traces[probe_idx]
        probe_idx += 1
        actual = (step.expect == "finding")
        onyx_pred = (tr.outcome == "finding")

        # baseline prediction on the same exchange, with the strongest owner ref
        owner_ref = _owner_reference(target, step.request, principals)
        base_pred = bl.predicts_finding(ex.response, owner_ref)

        onyx_m.add(onyx_pred, actual)
        base_m.add(base_pred, actual)
        rows.append({
            "label": step.label, "truth": "finding" if actual else "clean",
            "onyx": "finding" if onyx_pred else "clean",
            "baseline": "bypassed" if base_pred else "enforced",
            "onyx_correct": onyx_pred == actual,
            "baseline_correct": base_pred == actual,
        })

    return {
        "evidence_tier": "T2_SELF_MEASURED",
        "evidence_note": ("self-built target + self-authored traffic; the independent "
                          "comparison (real Autorize vs a third-party target) is P0"),
        "onyx": {"precision": round(onyx_m.precision, 3), "recall": round(onyx_m.recall, 3),
                 "f1": round(onyx_m.f1, 3), "tp": onyx_m.tp, "fp": onyx_m.fp,
                 "fn": onyx_m.fn, "tn": onyx_m.tn},
        "baseline": {"precision": round(base_m.precision, 3), "recall": round(base_m.recall, 3),
                     "f1": round(base_m.f1, 3), "tp": base_m.tp, "fp": base_m.fp,
                     "fn": base_m.fn, "tn": base_m.tn},
        "rows": rows,
    }


def format_report(result: dict) -> str:
    o, b = result["onyx"], result["baseline"]
    lines = [
        f"[{result['evidence_tier']}] ONYX vs Autorize-equivalent baseline "
        f"({result['evidence_note']})",
        "",
        f"  ONYX     precision={o['precision']} recall={o['recall']} f1={o['f1']} "
        f"(tp={o['tp']} fp={o['fp']} fn={o['fn']} tn={o['tn']})",
        f"  baseline precision={b['precision']} recall={b['recall']} f1={b['f1']} "
        f"(tp={b['tp']} fp={b['fp']} fn={b['fn']} tn={b['tn']})",
        "",
        "  Cases where the heuristic baseline false-positives but ONYX drops:",
    ]
    for r in result["rows"]:
        if (not r["baseline_correct"]) and r["onyx_correct"]:
            lines.append(f"    - {r['label']} (truth={r['truth']}; "
                         f"baseline={r['baseline']}, ONYX={r['onyx']})")
    return "\n".join(lines)
