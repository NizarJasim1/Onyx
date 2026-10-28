"""
Integration test: G1 (OOB channels) + G14 (nonce) wired into ActBridge as a
second-order out-of-band leak confirmer. Models a real bug: the attacker triggers
an export whose content leaks the OWNER's private field, and the export is tagged
with the attacker's request marker. No network; deterministic.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.models import HTTPRequest, HTTPResponse, Principal
from authpath.act_bridge import ActBridge
from authpath.nonce_provenance import NonceAuthority, NonceSeeker
from authpath.oob_channels import ExportFileChannel


class _Conf:
    """Owner read returns the owner's private field value. `_read` is the only
    member ActBridge.confirm_field_leak_oob uses here."""
    def __init__(self, owner_secret="SSN-777-55"):
        self._owner_secret = owner_secret
    def _read(self, req, principal):
        # owner GET exposes their real datum for the hidden field 'ssn'
        return HTTPResponse(200, {"id": 1, "ssn": self._owner_secret})


def _conf_obj(resource="/export/1", declared="ssn", accessor="B"):
    class C: pass
    c = C(); c.kind = "hidden_field"; c.resource = resource
    c.accessor = accessor; c.declared = declared; c.owner_hint = "A"
    return c


def _bridge():
    a = NonceAuthority(); s = NonceSeeker(a)
    ppl = {"B": Principal("B", "B"), "A": Principal("A", "A")}
    return ActBridge(_Conf(), ppl, nonce_authority=a, seeker=s), a, s


def test_oob_export_leak_confirmed():
    b, a, s = _bridge()
    box = {"file": None}
    # trigger: attacker requests an export tagged with the nonce; the export leaks
    # the owner's ssn AND carries the attacker's nonce marker.
    def trigger(nonce):
        box["file"] = f"id,name,ssn\n1,OWNER,SSN-777-55\n# export tag ONYX-{nonce.value}\n"
    channel = ExportFileChannel(fetch=lambda: box["file"])
    f = b.confirm_field_leak_oob(_conf_obj(), owner_identity="A", channel=channel,
                                 trigger=trigger,
                                 read_request=HTTPRequest("GET", "/u/A", host="h"))
    assert f is not None and f.kind == "second_order_oob_leak"


def test_export_without_owner_datum_abstains():
    """Nonce present (our export) but the owner's secret is NOT in it → no leak proven."""
    b, a, s = _bridge()
    box = {"file": None}
    def trigger(nonce):
        box["file"] = f"id,name\n1,OWNER\n# export tag ONYX-{nonce.value}\n"  # no ssn
    channel = ExportFileChannel(fetch=lambda: box["file"])
    f = b.confirm_field_leak_oob(_conf_obj(), owner_identity="A", channel=channel,
                                 trigger=trigger,
                                 read_request=HTTPRequest("GET", "/u/A", host="h"))
    assert f is None
    assert any("oob-leak" in r[1] for r in b.abstained)


def test_export_without_nonce_abstains():
    """Owner secret leaks but our nonce is absent → un-attributable (could be
    background data) → abstain, no FP."""
    b, a, s = _bridge()
    box = {"file": None}
    def trigger(nonce):
        box["file"] = "id,name,ssn\n1,OWNER,SSN-777-55\n"  # leak but no nonce marker
    channel = ExportFileChannel(fetch=lambda: box["file"])
    f = b.confirm_field_leak_oob(_conf_obj(), owner_identity="A", channel=channel,
                                 trigger=trigger,
                                 read_request=HTTPRequest("GET", "/u/A", host="h"))
    assert f is None


def test_abstains_without_authority():
    ppl = {"B": Principal("B", "B"), "A": Principal("A", "A")}
    b = ActBridge(_Conf(), ppl)   # no authority
    channel = ExportFileChannel(fetch=lambda: "x")
    f = b.confirm_field_leak_oob(_conf_obj(), owner_identity="A", channel=channel,
                                 trigger=lambda n: None,
                                 read_request=HTTPRequest("GET", "/u/A", host="h"))
    assert f is None and any("no nonce authority" in r[1] for r in b.abstained)


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
