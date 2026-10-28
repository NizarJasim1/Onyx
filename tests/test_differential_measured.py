"""
Protocol [21] gap G4 — the deep-axis differential, MEASURED not claimed.

On a suite that spans the cases separating ownership+Δstate from response-diffing, the fair
competitor model (status+length+body diff) shows measurable FALSE POSITIVES and FALSE
NEGATIVES, while ONYX's ownership-aware Δstate oracle stays precision 1.0 with full recall.
That delta is the encoded structural advantage.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.differential import (measure, standard_suite, response_diff_oracle,
                                   onyx_delta_state_oracle, Scenario)


def test_g4_onyx_is_precision_1_and_full_recall_on_the_suite():
    m = measure(standard_suite())
    assert m["onyx_delta_state"]["precision"] == 1.0, m
    assert m["onyx_delta_state"]["recall"] == 1.0, m
    assert m["onyx_delta_state"]["fp"] == 0 and m["onyx_delta_state"]["fn"] == 0


def test_g4_response_diff_competitor_has_measurable_fp_and_fn():
    m = measure(standard_suite())
    diff = m["response_diff"]
    # the encoded differential: the diffing class is strictly worse on this suite
    assert diff["fp"] >= 1, f"response-diff must show a false positive: {diff}"
    assert diff["fn"] >= 1, f"response-diff must show a false negative: {diff}"
    assert (diff["precision"] < 1.0) or (diff["recall"] < 1.0)


def test_g4_specific_fn_write_bypass_generic_success():
    # a cross-principal WRITE returning a generic success for everyone: diff sees an identical
    # response and misses it; ONYX confirms the victim-resource Δstate and catches it
    sc = [s for s in standard_suite() if s.name == "bfla-write-generic-success"][0]
    assert response_diff_oracle(sc) is False        # identical success body -> diff misses (FN)
    assert onyx_delta_state_oracle(sc) is True      # confirmed Δstate on victim -> caught


def test_g4_specific_fp_benign_length_diff():
    # a benign extra public field: diff flags a leak that isn't one; ONYX abstains
    sc = [s for s in standard_suite() if s.name == "benign-length-diff"][0]
    assert response_diff_oracle(sc) is True         # length differs -> diff FALSE POSITIVE
    assert onyx_delta_state_oracle(sc) is False     # no foreign value -> ONYX clean


def test_g4_differential_delta_is_reported():
    m = measure(standard_suite())
    onyx_clean = m["onyx_delta_state"]["fp"] == 0 and m["onyx_delta_state"]["fn"] == 0
    diff_errors = m["response_diff"]["fp"] + m["response_diff"]["fn"]
    assert onyx_clean and diff_errors >= 2          # the measured structural advantage


if __name__ == "__main__":
    import json
    print(json.dumps(measure(standard_suite()), indent=2))
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
