"""P6 — law-derived remediation + standard classification. Proves every finding-
producing effect class maps to a valid CWE + OWASP-API category + a concrete,
non-generic remediation, and that unknown effects fall back safely."""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from authpath.models import EffectClass
from authpath.remediation import (classify, remediation_block, triager_tldr,
                                   EFFECT_TAXONOMY, _FALLBACK)

# effect classes that actually produce findings (READ/NONE do not)
_FINDABLE = [e for e in EffectClass if e.name not in ("READ", "NONE")]
_CWE = re.compile(r"^CWE-\d+$")
_OWASP = re.compile(r"API\d:2023|OWASP API")

class _F:  # tiny finding stub
    def __init__(self, effect): self.effect = effect

def test_every_findable_effect_has_an_entry():
    missing = [e.name for e in _FINDABLE if e not in EFFECT_TAXONOMY]
    assert not missing, f"effect classes without a taxonomy entry: {missing}"

def test_entries_have_valid_cwe_and_owasp():
    for e, t in EFFECT_TAXONOMY.items():
        assert _CWE.match(t.cwe_id), f"{e.name}: bad CWE {t.cwe_id!r}"
        assert _OWASP.search(t.owasp_api), f"{e.name}: bad OWASP {t.owasp_api!r}"
        assert len(t.cwe_name) > 5 and len(t.remediation) > 40 and len(t.tldr) > 20

def test_remediation_is_specific_not_generic():
    # the OBJECT_ACCESS fix must mention ownership; PAYMENT must mention server-side amount
    assert "ownership" in classify(EffectClass.OBJECT_ACCESS).remediation.lower()
    assert "server-side" in classify(EffectClass.PAYMENT).remediation.lower()
    assert "single-use" in classify(EffectClass.COUPON).remediation.lower()
    assert "subset" in classify(EffectClass.AUTHORITY_GRANT).remediation.lower()

def test_distinct_remediations_per_family():
    # BOLA / BFLA / payment families must not collapse to one generic string
    rem = {classify(e).remediation for e in
           (EffectClass.OBJECT_ACCESS, EffectClass.AUTHORITY, EffectClass.PAYMENT,
            EffectClass.FIELD_PROJECTION, EffectClass.STATE_GATE)}
    assert len(rem) == 5, "each effect family must have its own remediation"

def test_unknown_effect_falls_back_safely():
    t = classify(EffectClass.READ)               # not a finding effect -> fallback
    assert t is _FALLBACK and t.cwe_id == "CWE-285"
    assert "authorization" in t.remediation.lower()

def test_block_and_tldr_render():
    f = _F(EffectClass.OBJECT_ACCESS)
    blk = remediation_block(f)
    assert "## Standard classification" in blk and "CWE-639" in blk
    assert "## Remediation (derived from the violated invariant)" in blk
    assert "ownership" in blk.lower()
    assert "another user's object" in triager_tldr(f).lower()


def test_report_integration_self_is_t2():
    import os as _os
    sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "tests"))
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig
    from fixtures import demo_scenario as ds
    e = ds.run_demo(lambda t,p,c: AuthPathEngine(t,p,
        ScopeConfig(allowed_hosts=["demo.local"], automation_permitted=True),
        contract=c))[0]
    md = e.findings[0].report_markdown
    assert "**TL;DR:**" in md and "## Remediation (derived" in md and "CWE-" in md
    # self target -> the report stamps T2, never T1 (P6xP8 closes the L-B leak)
    assert "T2_SELF_MEASURED" in md and "T1_INDEPENDENT" not in md

def test_report_integration_third_party_is_t1():
    import os as _os
    sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "tests"))
    from authpath.engine import AuthPathEngine
    from authpath.scope_guard import ScopeConfig
    from fixtures import demo_scenario as ds
    e = ds.run_demo(lambda t,p,c: AuthPathEngine(t,p,
        ScopeConfig(allowed_hosts=["demo.local"], automation_permitted=True,
                    target_provenance="third_party"), contract=c))[0]
    md = e.findings[0].report_markdown
    assert "T1_INDEPENDENT" in md, "a third-party target report may claim T1"

if __name__ == "__main__":
    fns=[(n,f) for n,f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    print("\nP6 remediation (session 4)\n"+"-"*50); p=0; fail=0
    for n,f in fns:
        try: f(); p+=1; print(f"  [PASS] {n}")
        except Exception as e: fail+=1; print(f"  [FAIL] {n}: {e!r}")
    print("-"*50); print(f"  {p}/{len(fns)} passed\n"); sys.exit(1 if fail else 0)
