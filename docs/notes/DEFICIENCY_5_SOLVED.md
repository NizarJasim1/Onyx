# Deficiency #5 (chain synthesis / capability graph) — SOLVED under [18]+[19]+[20]

ONYX reported each finding in isolation. Real criticality is usually a CHAIN: the output of
one confirmed primitive enables the next (a BOLA leaks an admin token → the token authorizes
an admin action → a delete). Each hop alone is lower severity; composed, it is critical, and
some target states no single law reaches. The old `_chain_provenance` saw one value hop as a
lead — there was no capability graph and no path synthesis.

## The root move ([4].R5 / [12]) — a capability graph of confirmed primitives
`authpath/chain.py`: nodes are capabilities ONYX has CONFIRMED it can obtain (possess token,
access resource, acquire role); edges are confirmed PRIMITIVES that consume one capability
and produce another, each carrying the Δstate-confirmed finding that proves it; a chain is a
bounded-depth path from a start capability to a high-value target.

**The FP-safety split (same discipline as #8):** composition never relaxes confirmation. A
chain is reported only if EVERY edge is an independently Δstate-confirmed primitive — an edge
with no confirmed finding is refused entry to the graph, and a hop that cannot be confirmed
breaks the chain there. So chaining raises the severity and recall of escalation PATHS but
can never manufacture a false positive. GP5 holds by construction.

## Gap inventory ([19] band 1) and closure

| Gap | Closure |
|-----|---------|
| **1 capability nodes** | Typed `Capability` (kind/ref/principal) for confirmed assets. |
| **2 enabling edges** | `Primitive(consumes → produces, finding_id)`; only confirmed edges admitted. |
| **3 synthesis** | `synthesize(is_target)` finds bounded-depth confirmed paths to a high-value target. |
| **4 confirmed-chain only (FP-safety)** | An unconfirmed hop or a missing finding-id refuses the edge → the chain breaks → nothing reported. Verified two ways. |
| **5 novelty** | A 2-hop escalation (BOLA leaks admin token → token authorizes a delete) — a critical state no single law flags — is synthesized and confirmed, both finding-ids in order. |

Tests: `tests/test_capability_chain.py` (5 cases). MSI byte-identical (chain graph is opt-in,
not in the default path); full suite 537 green; dedup lint clean.

## The wall ([19] band 3) — declared
ONYX composes only the CONFIRMABLE sub-graph, bounded-depth. A path needing a hop it cannot
confirm (an external or unobservable effect) is not synthesized, and the search depth is
capped so there is no combinatorial blow-up — it finds the proven escalation paths, not every
conceivable one. This is a special case of #8 (composition over the confirmed primitive set),
as the file notes.

## The [18] card
- **(أ) Structural constraint removed:** findings are no longer isolated — ONYX composes them
  into escalation paths, reaching critical states that only emerge from a chain, which is
  where a mature target's real risk usually lives.
- **(ب) Hypothesis the solution requires:** the target/high-value predicate to reach, and the
  capability types to model — declared by the operator; the primitives themselves are ONYX's
  own confirmed findings.
- **(ج) Weakest remaining link:** only confirmable, bounded-depth paths; and each hop still
  depends on the underlying confirmation channels (#4) and discovered surface (#2).

## Graduation
Proven on a seeded 2-hop escalation + FP-safety when a hop is unconfirmed. Next honest
station: register a real run's confirmed findings as primitives and synthesise the chains a
human then validates — not a Google/Microsoft claim.
