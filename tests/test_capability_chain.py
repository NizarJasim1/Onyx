"""
Deficiency #5 (chain synthesis / capability graph) — solved-criterion, every gap.

Individual primitives are composed into an escalation PATH. Composition never relaxes
confirmation: a chain is reported only if EVERY edge is a Δstate-confirmed primitive, so
chaining raises the severity/recall of escalation paths but can never manufacture an FP.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from authpath.chain import Capability, Primitive, CapabilityGraph


def _two_hop_graph(second_confirmed=True, second_fid="F2"):
    """Seed a 2-hop escalation: a BOLA leaks an admin token (hop 1), the token authorizes a
    delete no low-priv principal could do (hop 2)."""
    g = CapabilityGraph()
    attacker = Capability("principal", "attacker")
    admin_token = Capability("token", "ADMIN_TOKEN", principal="victim_admin")
    deleted = Capability("resource_deleted", "order_9")
    g.add_start(attacker)
    # hop 1: confirmed BOLA -> possess admin token
    g.add_primitive(Primitive(consumes=attacker, produces=admin_token,
                              finding_id="F1", law="BOLA_leak_token"))
    # hop 2: use the token to delete (confirmed or not, per the test)
    g.add_primitive(Primitive(consumes=admin_token, produces=deleted,
                              finding_id=second_fid, law="token_authorizes_delete",
                              confirmed=second_confirmed))
    return g, deleted


def _is_delete(cap):
    return cap.kind == "resource_deleted"


def test_gap1_2_3_5_novel_chain_is_synthesized_and_confirmed():
    g, deleted = _two_hop_graph(second_confirmed=True)
    chains = g.synthesize(_is_delete)
    assert len(chains) == 1, f"expected one confirmed escalation chain, got {len(chains)}"
    ch = chains[0]
    assert ch.confirmed() and ch.target().key() == "resource_deleted:order_9"
    assert ch.finding_ids() == ["F1", "F2"]                 # both hops, in order
    assert "BOLA_leak_token" in ch.describe() and "token_authorizes_delete" in ch.describe()


def test_gap4_fp_safety_unconfirmed_hop_breaks_the_chain():
    # the second hop is NOT Δstate-confirmed -> it must be refused, so NO chain reaches the target
    g, deleted = _two_hop_graph(second_confirmed=False)
    chains = g.synthesize(_is_delete)
    assert chains == [], "an unconfirmed hop must break the chain (no FP by composition)"


def test_gap4_missing_finding_id_hop_is_refused():
    g, deleted = _two_hop_graph(second_confirmed=True, second_fid="")   # no proof id
    chains = g.synthesize(_is_delete)
    assert chains == [], "an edge with no confirming finding must never enter the graph"


def test_bounded_depth_no_blowup():
    g = CapabilityGraph(max_depth=3)
    prev = Capability("principal", "attacker"); g.add_start(prev)
    for i in range(10):                                     # a long confirmable line
        nxt = Capability("step", f"s{i}")
        g.add_primitive(Primitive(consumes=prev, produces=nxt, finding_id=f"F{i}", law="hop"))
        prev = nxt
    # target is the very last node, beyond max_depth -> not reachable within the bound
    chains = g.synthesize(lambda c: c.ref == "s9")
    assert chains == []                                     # bounded search, no blowup


def test_single_confirmed_primitive_is_a_trivial_chain():
    g = CapabilityGraph()
    a = Capability("principal", "attacker"); g.add_start(a)
    leaked = Capability("pii", "victim_ssn")
    g.add_primitive(Primitive(consumes=a, produces=leaked, finding_id="F1", law="BOLA"))
    chains = g.synthesize(lambda c: c.kind == "pii")
    assert len(chains) == 1 and chains[0].confirmed()


if __name__ == "__main__":
    p = 0; fns = [g for n, g in sorted(globals().items()) if n.startswith("test_")]
    for fn in fns:
        try: fn(); p += 1; print(f"  ok  {fn.__name__}")
        except AssertionError as e: print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e: print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
