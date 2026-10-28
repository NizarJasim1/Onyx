"""
authpath.bva_unification — the single law under which BOTH nerves and the four engines
are instances.

This is the meta-unification reached after building the Broadcast-vs-Act nerve. It is
DESCRIPTIVE ONLY (no detection, no conviction) and records the architecture so a test can
pin it.

THE ONE LAW
-----------
    A target broadcasts its authorization decision on two channels — DECLARATION (what it
    shows vs. hides: owner fields, present/absent fields, _links, named 403s, schema) and
    ACT (what it executes / returns). The conserved quantity is that the two channels must
    AGREE. Every ONYX detector is an instance of "the target must not contradict its own
    broadcast", differing only in WHICH broadcast and WHICH act they compare.

THE INSTANCES (empirically grounded, not asserted)
--------------------------------------------------
  * identity⇄ownership (first nerve) — DECLARATION = the owner field present in the body
    (a broadcast: "this object is X's"); ACT = serving the object to a non-owner Y. The
    owner field is literally in the declaration channel (see test), so this nerve is the
    owner-field instance of Broadcast-vs-Act.
  * cross-surface / temporal / combinatorial / hierarchy (RL15-18) — both sides are the
    ACT channel: the target's decision must be consistent across door / time / sibling /
    parent. (Act-vs-act consistency.)
  * Broadcast-vs-Act (second nerve) — DECLARATION (field/action shown-vs-hidden, named
    403) vs ACT (the field the act actually exposes, the action it actually executes).
    The only detector that reads the declaration channel and confronts it with the act.

WHY THIS IS THE GENERAL LAW
---------------------------
The first nerve compares one declaration form (owner field) to the act. The four engines
compare act to act. Broadcast-vs-Act generalises: ANY declaration the target emits must
not be contradicted by ANY act. The others are special cases by which declaration/act
pair they fix. Conviction in every case is Δstate; selection is always quote-not-induce.

Imported by nothing in the live pipeline — byte-identical inert.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Instance:
    name: str
    declaration: str       # what is read on the declaration channel (or "act" if none)
    act: str               # what is compared on the act channel
    detector: str          # the module/flag that implements it


THE_LAW = (
    "A target broadcasts its authorization decision on two channels — DECLARATION (what "
    "it shows vs. hides) and ACT (what it executes). The conserved quantity is that the "
    "two must agree; a vulnerability is the target contradicting its own broadcast, "
    "confirmed by Δstate. Selection of what to test is always quoted from the target, "
    "never induced."
)

INSTANCES = (
    Instance(
        name="identity-ownership (nerve 1)",
        declaration="owner field present in the body ('this object belongs to X')",
        act="the object is served to a non-owner Y",
        detector="nerve / nerve_findings (authpath.nerve_bridge)"),
    Instance(
        name="cross-surface (RL15)",
        declaration="act",
        act="same object via two surfaces must get the same decision",
        detector="cross_surface engine"),
    Instance(
        name="temporal (RL16)",
        declaration="act",
        act="same object across time must get the same decision",
        detector="temporal_shape engine"),
    Instance(
        name="combinatorial (RL17)",
        declaration="act",
        act="sibling objects under one relation must get the same decision",
        detector="combinatorial engine"),
    Instance(
        name="hierarchy (RL18)",
        declaration="act",
        act="a child inherits its parent's decision",
        detector="global_invariants engine"),
    Instance(
        name="broadcast-vs-act (nerve 2)",
        declaration="field/action shown-vs-hidden across principals; named 403; _links",
        act="the field the act actually exposes / the action it actually executes",
        detector="bva / bva_findings (authpath.broadcast + act_confront + act_bridge)"),
)


def instance_names() -> set:
    return {i.name for i in INSTANCES}


def declaration_channel_instances() -> set:
    """Instances that read the DECLARATION channel (not pure act-vs-act). Both nerves do;
    the four engines do not."""
    return {i.name for i in INSTANCES if i.declaration != "act"}
