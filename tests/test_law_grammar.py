"""
Deficiency #8 (generative law grammar) — solved-criterion, every gap.

ONYX abstracts its hand-written laws into a grammar and GENERATES novel violation classes.
Generation expands only the PATTERN; confirmation stays the proven Δstate machinery — so a
generated law can raise recall but can never manufacture a false positive. The killer proof:
a law matching NONE of the hand-written 25 confirms a real violation, tagged AUTO-GENERATED.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.grammar import LawGrammar, GeneratedLaw, KNOWN_LAWS
from authpath.models import HTTPRequest, HTTPResponse, Principal, Exchange


def test_gap1_gap2_grammar_generates_novel_laws_beyond_the_hand_written_set():
    g = LawGrammar()
    novel = g.novel_laws()
    assert len(novel) > 0
    for law in novel:
        assert law.signature() not in KNOWN_LAWS         # genuinely outside the manual set


# a NOVEL law: cross-principal read addressed by a SECONDARY KEY (email/slug), not a path id
NOVEL = GeneratedLaw("cross_principal", "read", "secondary_key", "direct_readback")


def test_novel_law_is_actually_novel():
    assert NOVEL.is_novel() and NOVEL.signature() not in KNOWN_LAWS


def _owner_of(v):
    # provenance stub: victim@corp.test and B's secrets belong to B
    return "B" if isinstance(v, str) and ("victim" in v or v == "bravo-secret") else None


def test_gap3_gap4_generated_law_confirms_a_seeded_novel_violation():
    """A target with a SECONDARY-KEY BOLA: /users/lookup?email=<victim> leaks the victim's
    private data to any caller. No hand-written law addresses objects by secondary key."""
    def target_send(req):
        if req.query.get("email") == "victim@corp.test":
            return HTTPResponse(200, {"email": "victim@corp.test", "secret": "bravo-secret"})
        return HTTPResponse(404, {})

    req = HTTPRequest("GET", "/users/lookup", query={"email": "victim@corp.test"}, host="h")
    ex = Exchange(request=req, response=target_send(req), principal=Principal("A", "A", auth={}))
    finding = NOVEL.evaluate(ex, owner_of=_owner_of, reread=lambda: target_send(req))
    assert finding is not None, "the generated novel law must confirm the seeded violation"
    assert finding["novel"] is True and finding["tag"] == "AUTO-GENERATED / UNREVIEWED"
    assert finding["actor"] == "A" and finding["owner"] == "B"


def test_gap5_fp_safety_generated_law_emits_nothing_on_a_safe_target():
    """Same novel law, but the endpoint enforces authz (403 to non-owners). Confirmation is
    still Δstate, so nothing is emitted — generation cannot add a false positive."""
    def safe_send(req):
        return HTTPResponse(403, {"error": "forbidden"})    # properly enforced
    req = HTTPRequest("GET", "/users/lookup", query={"email": "victim@corp.test"}, host="h")
    ex = Exchange(request=req, response=safe_send(req), principal=Principal("A", "A", auth={}))
    finding = NOVEL.evaluate(ex, owner_of=_owner_of, reread=lambda: safe_send(req))
    assert finding is None, "a safe target must yield no finding (zero-FP preserved)"


def test_same_principal_access_is_not_flagged():
    # actor reads their OWN object -> not a cross-principal violation
    def send(req):
        return HTTPResponse(200, {"email": "victim@corp.test", "secret": "bravo-secret"})
    req = HTTPRequest("GET", "/users/lookup", query={"email": "victim@corp.test"}, host="h")
    ex = Exchange(request=req, response=send(req), principal=Principal("B", "B", auth={}))  # B is owner
    assert NOVEL.evaluate(ex, owner_of=_owner_of, reread=lambda: send(req)) is None


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
