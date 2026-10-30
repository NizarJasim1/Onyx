"""
Falsification suite for G1 (out-of-band channels). Each test encodes a clause of
the Anti-Patch Gate / No-Regression Invariant. If any fails, G1 is NOT solved.
Deterministic, no network (all I/O is injected).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.nonce_provenance import NonceAuthority, NonceSeeker
from authpath.oob_channels import (
    ExportFileChannel, OASTChannel, MailboxChannel, AuditFeedChannel,
    confirm_oob_leak,
)


def _wire(payloads_over_time):
    """Build a seeker with one planted nonce and a channel that yields the given
    list-of-lists (one inner list per poll)."""
    a = NonceAuthority(); s = NonceSeeker(a)
    n = a.mint("oob"); s.register_planted(n)
    calls = {"i": 0}
    def poll():
        i = calls["i"]; calls["i"] += 1
        return payloads_over_time[i] if i < len(payloads_over_time) else []
    return a, s, n, poll


def test_export_leak_confirmed_with_nonce_and_victim_datum():
    # build explicitly (nonce needed inside payload)
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("export"); s.register_planted(n)
    csv = f"id,name,secret\n42,VICTIM,SECRET-9931\n# request marker ONYX-{n.value}\n"
    ch = ExportFileChannel(fetch=lambda: csv)
    r = confirm_oob_leak(channel=ch, seeker=s, planted=n, victim_datum="SECRET-9931")
    assert r.confirmed is True and r.channel == "export"


def test_nonce_present_but_no_victim_datum_abstains():
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("export"); s.register_planted(n)
    csv = f"just my own export marker ONYX-{n.value}, nothing leaked\n"
    ch = ExportFileChannel(fetch=lambda: csv)
    r = confirm_oob_leak(channel=ch, seeker=s, planted=n, victim_datum="SECRET-9931")
    assert r.confirmed is False and "attribution" in r.reason.lower()


def test_victim_datum_present_but_no_nonce_abstains():
    """Un-attributable: victim data appears but not OUR nonce → could be background
    data / another tester. Must abstain (no FP)."""
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("export"); s.register_planted(n)
    csv = "id,secret\n42,SECRET-9931\n"   # leak-looking, but no nonce
    ch = ExportFileChannel(fetch=lambda: csv)
    r = confirm_oob_leak(channel=ch, seeker=s, planted=n, victim_datum="SECRET-9931")
    assert r.confirmed is False and "no attributed artifact" in r.reason


def test_settling_window_timeout_abstains():
    """Channel never yields anything → bounded poll → abstain (Q-0)."""
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("wh"); s.register_planted(n)
    ch = OASTChannel(poll=lambda: [])
    r = confirm_oob_leak(channel=ch, seeker=s, planted=n, victim_datum="X",
                         attempts=4, interval_s=0.0)
    assert r.confirmed is False and "settling window" in r.reason


def test_late_arrival_within_window_is_caught():
    """Effect arrives on the 3rd poll, not the 1st — must still be caught."""
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("wh"); s.register_planted(n)
    seq = [[], [], [f"callback body ONYX-{n.value} leaked SECRET-42"]]
    calls = {"i": 0}
    def poll():
        i = calls["i"]; calls["i"] += 1
        return seq[i] if i < len(seq) else []
    ch = OASTChannel(poll=poll)
    r = confirm_oob_leak(channel=ch, seeker=s, planted=n, victim_datum="SECRET-42",
                         attempts=5, interval_s=0.0)
    assert r.confirmed is True and r.channel == "webhook"


def test_victim_datum_equal_to_nonce_is_rejected():
    """Q-3: victim_datum must not be the nonce itself (circular)."""
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("export"); s.register_planted(n)
    payload = f"ONYX-{n.value}"
    ch = ExportFileChannel(fetch=lambda: payload)
    r = confirm_oob_leak(channel=ch, seeker=s, planted=n, victim_datum=n.value)
    assert r.confirmed is False


def test_foreign_nonce_in_payload_never_attributes():
    """A DIFFERENT authority's token in the payload must not attribute to us."""
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("export"); s.register_planted(n)
    b = NonceAuthority(); foreign = b.mint("evil")
    payload = f"ONYX-{foreign.value} SECRET-9931"
    ch = ExportFileChannel(fetch=lambda: payload)
    r = confirm_oob_leak(channel=ch, seeker=s, planted=n, victim_datum="SECRET-9931")
    assert r.confirmed is False and "no attributed artifact" in r.reason


def test_mailbox_and_audit_channels_share_the_same_logic():
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("m"); s.register_planted(n)
    mail = MailboxChannel(read=lambda: [f"To: onyx+{n.value}@x\nBody: pwd=VICTIMPW"])
    r1 = confirm_oob_leak(channel=mail, seeker=s, planted=n, victim_datum="VICTIMPW")
    assert r1.confirmed is True and r1.channel == "email"

    a2 = NonceAuthority(); s2 = NonceSeeker(a2); n2 = a2.mint("a"); s2.register_planted(n2)
    audit = AuditFeedChannel(fetch=lambda: {"actor": f"ONYX-{n2.value}", "read": "VICTIMDOC"})
    r2 = confirm_oob_leak(channel=audit, seeker=s2, planted=n2, victim_datum="VICTIMDOC")
    assert r2.confirmed is True and r2.channel == "audit"


def test_evidence_excerpt_captured_on_finding():
    a = NonceAuthority(); s = NonceSeeker(a); n = a.mint("export"); s.register_planted(n)
    ch = ExportFileChannel(fetch=lambda: f"leak SECRET-1 marker ONYX-{n.value}")
    r = confirm_oob_leak(channel=ch, seeker=s, planted=n, victim_datum="SECRET-1")
    assert r.confirmed is True and n.value in r.evidence


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
