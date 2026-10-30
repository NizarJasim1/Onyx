"""
Falsification suite for G14 (nonce provenance). Each test encodes a clause of the
Anti-Patch Gate or the No-Regression Invariant. If any fails, G14 is NOT solved.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.nonce_provenance import (
    NonceAuthority, NonceSeeker, PlantStrategy, choose_strategy,
    attributed_stick_check,
)


def test_mint_is_collision_proof():
    a = NonceAuthority()
    tokens = {a.mint("x").value for _ in range(10000)}
    assert len(tokens) == 10000  # zero collisions across 10k mints


def test_authority_recognises_only_its_own():
    a, b = NonceAuthority(), NonceAuthority()
    na = a.mint("p")
    assert a.recognises(na.value) is True
    assert b.recognises(na.value) is False           # P-2: not b's token
    assert a.recognises("admin") is False            # never attribute target data
    assert a.recognises("oxpv-deadbeef-1") is False  # look-alike, not actually minted


def test_pure_text_field_gets_pure_nonce():
    strat, comp = choose_strategy("display_name")
    assert strat is PlantStrategy.PURE_TEXT and comp is None


def test_semantic_field_needs_companion_or_abstains():
    # role is constrained → cannot carry a nonce directly
    strat, comp = choose_strategy("role", object_fields={"role": "user", "bio": ""})
    assert strat is PlantStrategy.HYBRID_COMPANION and comp == "bio"

    # no free-text sibling, no isolation → MUST abstain (never downgrade the bar)
    strat2, comp2 = choose_strategy("role", object_fields={"role": "user", "status": "x"})
    assert strat2 is PlantStrategy.ABSTAIN and comp2 is None

    # isolation available as last resort
    strat3, _ = choose_strategy("role", object_fields={"role": "user"},
                                isolation_available=True)
    assert strat3 is PlantStrategy.ISOLATION


def test_exact_match_only_no_prefix_no_substring_fp():
    a = NonceAuthority(); s = NonceSeeker(a)
    n = a.mint("p"); s.register_planted(n)
    # prefix of the token must NOT attribute (P-1)
    assert s.seek(n.value[:-3]) is None
    # the self-identifying prefix alone must NOT attribute
    assert s.seek("oxpv-") is None
    # full token embedded in a larger blob DOES attribute
    assert s.seek({"note": f"hello {n.value} world"}) is not None


def test_pre_plant_absence_gate():
    a = NonceAuthority(); s = NonceSeeker(a)
    n = a.mint("p")
    assert s.pre_plant_absent(n, {"bio": "nothing here"}) is True
    assert s.pre_plant_absent(n, {"bio": n.value}) is False   # already present → abort


def test_attribution_is_not_authorization():
    """P-3: nonce found but NOT cross-principal ⇒ abstain, never a finding."""
    a = NonceAuthority(); s = NonceSeeker(a)
    n = a.mint("mass-assign role"); s.register_planted(n)
    body = {"role": "admin", "bio": f"ONYX-{n.value}"}  # our stamp landed
    # cross-principal unproven ⇒ must abstain
    r = attributed_stick_check(seeker=s, planted=n, readback_body=body,
                               cross_principal_ok=False)
    assert r.attributed is False and "cross-principal" in r.reason
    # same landing, but cross-principal proven ⇒ finding
    r2 = attributed_stick_check(seeker=s, planted=n, readback_body=body,
                                cross_principal_ok=True)
    assert r2.attributed is True


def test_effect_did_not_land_abstains():
    a = NonceAuthority(); s = NonceSeeker(a)
    n = a.mint("p"); s.register_planted(n)
    r = attributed_stick_check(seeker=s, planted=n,
                               readback_body={"role": "admin"},  # no nonce → not ours
                               cross_principal_ok=True)
    assert r.attributed is False and "did not land" in r.reason


def test_channel_agnostic_same_logic_for_oob():
    """G1 readiness: the SAME exact-match works on an 'export' or 'webhook' channel."""
    a = NonceAuthority(); s = NonceSeeker(a)
    n = a.mint("export"); s.register_planted(n)
    csv_text = f"id,name,email\n42,Victim,onyx+{n.value}@onyx.test\n"
    hit = s.seek(csv_text, channel="export")
    assert hit is not None and hit.channel == "export"


def test_cannot_plant_foreign_nonce():
    a, b = NonceAuthority(), NonceAuthority()
    s = NonceSeeker(a)
    foreign = b.mint("p")
    try:
        s.register_planted(foreign)
        raise AssertionError("should have refused a foreign nonce")
    except ValueError:
        pass


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS  {fn.__name__}"); passed += 1
        except Exception:
            print(f"FAIL  {fn.__name__}"); traceback.print_exc()
    print(f"\n{passed}/{len(fns)} passed")
