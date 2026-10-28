"""
authpath.cross_operation — CROSS-OPERATION FAMILY EXTRACTOR (FCE).

WHAT THIS ANSWERS, AND THE ONE THING IT REFUSES TO DO
--------------------------------------------------------------------------------
`VERITAS_RANGE_REPORT.md` declares blind spot U1 in its own words:

    "a differently-named operation (`orgWebhooks`) returns the same data the
     primary withholds. ONYX unifies identities by (type, id) from the root
     field, so `orgWebhooks` is not unified with `org`. ... Capability needed: an
     operation-equivalence declaration ONYX does not synthesise."

That last clause is exactly right, and FCE does not pretend otherwise. **Operation
equivalence cannot be synthesised from names.** "`orgWebhooks` looks like `org`" is
resemblance, which is the induction RL1 forbids, and no amount of string distance
turns it into knowledge. A module that unified them by name would be worse than
the blind spot it replaced, because it would be confidently wrong.

So FCE takes a different route to the same leak, one that needs no equivalence at
all. The link is a LITERAL LEAF NAME appearing on both sides of a contradiction:

    MEASURED   the server itself refused `webhook_secret` for principal P
               (`graphql.authz_denied_paths` — the target stating its own policy)
    DECLARED   the client bundle ships an operation that SELECTS `webhook_secret`
               (`query GetOrgWebhooks { orgWebhooks(id:$id) { webhook_secret } }`)

Neither side is a guess. The refusal is a measurement; the selection is a literal
in the shipped source, carried with `source_file:line`. The two are joined on the
field name they both spell out — never on how the operations are named, never on
what they resemble. `org` and `orgWebhooks` are never asserted to be the same type,
because they need not be: the question is whether a leaf the server refused is
reachable through another door the client itself declares.

FAMILIES ARE FORMED ONLY ON A DECLARED BASIS
--------------------------------------------
When operations ARE grouped, the basis is always something written down, in a
fixed precedence:

  1. `operator_declared`  — an explicit `operation_families` mapping. The
                            declaration the VERITAS note says ONYX lacks; FCE
                            consumes it, and still does not invent it.
  2. `schema_return_type` — a GraphQL introspection document declares each root
                            field's return type. Two roots returning one type are
                            one family, said by the schema, not by us.
  3. `same_root_field`    — identical root field names across bundles. Trivially
                            sound.

Anything else lands in `unfamilied_operations`, which is a first-class output.
Recall loss is visible rather than papered over.

WHAT IS DELIBERATELY NOT EXTRACTED
----------------------------------
Each refusal has a negative-control test:

  * an operation binding inside a `//` or `/* */` comment, or inside another
    string literal — the FCX lexer makes both impossible;
  * `gql(BASE + "{ org { id } }")` — the prefix is a runtime value, so the
    binding is DROPPED, not approximated;
  * a template whose interpolation is not a fragment defined literally in the
    same bundle — a dynamic spread abstains;
  * an operation whose query text does not parse — no partial credit;
  * an operation named only by resemblance to a root type — the only binding that
    counts is the one written inside the query literal.

Every drop is counted in `dropped_unresolvable`.

WHAT IS REUSED RATHER THAN REBUILT
----------------------------------
  lexing ........... `frontend_contract._lex` — the same single-pass scanner, so a
                     path in a comment or a nested string is impossible here too.
  GraphQL parsing .. `graphql.parse_graphql_request` — the project's OWN parser.
                     Writing a second one would drift from the first the moment
                     either is touched. FCE hands it `{"query": <literal text>}`
                     and reads back `op_type`, `op_name`, `root_fields`.
  denials .......... `graphql.authz_denied_paths` — the existing authz-class
                     filter, including its "a null is not a denial" rule.
  sensitivity ...... `intrinsic.name_sensitivity` — the existing closed lexicon.
  scope ............ `frontend_contract.js_sources_from_har`, which puts every
                     asset through the real `ScopeGuard`.

The only genuinely new parsing is the SELECTION SET reader: `graphql._root_selections`
returns top-level fields only, and FCE needs the leaves beneath them.

AN OPERATION BINDING IS A DOOR, NOT A POLICY (D4)
--------------------------------------------------
A query literal selecting `webhook_secret` is not a vulnerability, not evidence
the server serves that field, and not evidence it withholds it. It is the target
declaring a second door. FCE therefore emits probe suggestions, never candidates:
it imports nothing from `eil`, `confirmer` or `engine` (asserted by test), emits no
`Candidate` and no `Finding`, and can change only WHAT is tested, never WHETHER
something is reported.

THE MISLEADING-BUNDLE ATTACK, STATED ACCURATELY
------------------------------------------------
A hostile target could plant `mutation WipeAll { wipeAll { id } }` to induce a
scanner into destructive calls. The FCX changelog's phrasing of the mitigation
does not transfer here and should not be repeated: GraphQL operations are POST, so
they can never ride `discovery.generate_probes`' GET-only rails at all — not as a
safety feature of those rails, but because they are structurally ineligible.

The real mitigations are three, and they are stated plainly:
  * FCE issues nothing. Every probe is a described plan; execution stays with the
    engine, under `ScopeGuard` and the budget ledger.
  * A probe is emitted ONLY where the capture already recorded the server refusing
    that leaf. A planted operation that no measurement contradicts produces
    nothing at all (tested).
  * Mutations are never planned. `_PLANNABLE_OP_TYPES` is `("query",)`.

FAIL-SAFE (RL5)
---------------
Unlexable source -> empty result plus an explicit record, and the bindings found
before the error are DISCARDED (a half-read bundle is not a contract). Unresolvable
binding -> dropped and counted. An operation matching two family bases with
different answers -> both suppressed. Empty scope -> nothing analysed, and the
exclusion is reported so "the bundle declared nothing" stays distinguishable from
"scope excluded every bundle". Absence of bindings is never reported as absence of
operations.

DETERMINISM
-----------
Same bytes in, same output. Everything sorted; no set iteration reaches the
output.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .frontend_contract import (
    JSSource, SourceReport, _lex, _LexError, _skip_balanced,
    UNLEXABLE, OVER_BUDGET, EMPTY_SOURCE,
    _MAX_SOURCE_BYTES, _MAX_TOTAL_BYTES, _MAX_SCAN_SPAN,
)

# Tag functions whose template literal IS a GraphQL document, by the published
# convention of the graphql-tag / Apollo / Relay ecosystems. A CLOSED list: a tag
# outside it is not read as GraphQL, because "a tag whose name looks graphql-ish"
# is the resemblance this module exists to refuse.
_GQL_TAGS = ("gql", "graphql", "graphqlTag")

# Only queries are ever planned. A mutation is never proposed by this module.
_PLANNABLE_OP_TYPES = ("query",)

_MAX_QUERY_LEN = 20_000
_MAX_OPERATIONS = 2000
_MAX_LEAVES = 500
_MAX_PROBES = 500
_MAX_FRAGMENTS = 500
_MAX_EXPR_LEN = 200

# Family bases, in precedence order.
FAMILY_OPERATOR = "operator_declared"
FAMILY_SCHEMA = "schema_return_type"
FAMILY_ROOT = "same_root_field"

# The only regexes here, both applied to already-bounded slices.
_IDENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_FRAGMENT_DEF = re.compile(r"\bfragment\s+([A-Za-z_]\w*)\s+on\s+([A-Za-z_]\w*)")


# --------------------------------------------------------------------------- #
# selection-set reading — the one genuinely new parse                          #
# --------------------------------------------------------------------------- #

def selection_leaves(query: str) -> tuple:
    """Field names selected BELOW the root selections, in document order.

    `graphql._root_selections` gives the top level; FCE needs what is chosen
    underneath it, because that is where a sensitive leaf lives. A single
    depth-tracked character scan — arguments, directives, variable declarations
    and fragment headers are skipped, and nothing is inferred from a name.
    """
    if not isinstance(query, str) or not query or len(query) > _MAX_QUERY_LEN:
        return ()
    out: list = []
    depth = 0
    # A fragment definition's fields sit one brace shallower than an operation's,
    # because there is no root selection above them. Tracking which construct we
    # are inside keeps a spliced fragment's leaves readable without lowering the
    # threshold for operations, where a root field is not a leaf.
    frag_mode = False
    i, n = 0, len(query)
    while i < n and len(out) < _MAX_LEAVES:
        ch = query[i]
        if ch in "\"'":                              # string argument value
            q = ch
            i += 1
            while i < n and query[i] != q:
                i += 2 if query[i] == "\\" else 1
            i += 1
            continue
        if ch == "#":                                # GraphQL comment
            j = query.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if ch == "(":                                # argument list — skip whole
            d, i = 1, i + 1
            while i < n and d:
                if query[i] == "(":
                    d += 1
                elif query[i] == ")":
                    d -= 1
                i += 1
            continue
        if ch == "{":
            depth += 1
            i += 1
            continue
        if ch == "}":
            depth -= 1
            if depth <= 0:
                depth = 0
                frag_mode = False
            i += 1
            continue
        if ch == "$" or ch == "@":                   # variable ref / directive
            i += 1
            while i < n and (query[i].isalnum() or query[i] in "_"):
                i += 1
            continue
        if ch == "." and query[i:i + 3] == "...":
            # A spread names a FRAGMENT or a type, never a field. Skip the name —
            # counting `...OrgBits` as a selected field would invent a leaf.
            i += 3
            for _ in range(2):
                while i < n and query[i] in " \t\r\n":
                    i += 1
                j = i
                while j < n and (query[j].isalnum() or query[j] == "_"):
                    j += 1
                if j == i:
                    break
                word = query[i:j]
                i = j
                if word != "on":
                    break
            continue
        if ch.isalpha() or ch == "_":
            j = i
            while j < n and (query[j].isalnum() or query[j] == "_"):
                j += 1
            word = query[i:j]
            k = j
            while k < n and query[k] in " \t\r\n":
                k += 1
            aliased = k < n and query[k] == ":"
            i = j
            if aliased:
                continue                             # alias label, not the field
            if word == "fragment" and depth == 0:
                frag_mode = True
                continue
            if word in ("query", "mutation", "subscription", "fragment", "on",
                        "true", "false", "null"):
                continue
            if depth >= (1 if frag_mode else 2):
                if word not in out:
                    out.append(word)
            continue
        i += 1
    return tuple(out)


def sensitive_leaves(leaves) -> tuple:
    """Leaves the existing closed lexicon marks sensitive. No new vocabulary."""
    try:
        from .intrinsic import name_sensitivity
    except Exception:                                # noqa: BLE001
        return ()
    return tuple(sorted({leaf for leaf in leaves if name_sensitivity(leaf) >= 6}))


# --------------------------------------------------------------------------- #
# data                                                                         #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class OperationBinding:
    """One GraphQL operation the client bundle declares it can issue."""
    op_type: str                    # "query" | "mutation" | "subscription"
    op_name: str                    # "" when anonymous
    root_fields: tuple = ()
    leaves: tuple = ()
    sensitive: tuple = ()
    found_in: str = ""              # "bundle.js:1423" — open it and the text is there
    query: str = ""                 # the literal document, truncated

    @property
    def key(self) -> str:
        if self.op_name:
            return f"{self.op_type.upper()} {self.op_name}"
        leaf = self.root_fields[0] if self.root_fields else "<unknown>"
        return f"{self.op_type.upper()} <anonymous>:{leaf}"


@dataclass
class CrossOperationContract:
    operations: list = field(default_factory=list)
    families: dict = field(default_factory=dict)
    unfamilied_operations: list = field(default_factory=list)
    sensitive_leaf_index: dict = field(default_factory=dict)
    cross_operation_probes: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def analyzable(self) -> bool:
        return any(s.analyzed for s in self.sources)

    def to_dict(self) -> dict:
        return {
            "operations": [
                {"key": o.key, "op_type": o.op_type, "op_name": o.op_name,
                 "root_fields": list(o.root_fields), "leaves": list(o.leaves),
                 "sensitive": list(o.sensitive), "found_in": o.found_in}
                for o in self.operations
            ],
            "families": {k: {"basis": v["basis"],
                             "operations": sorted(v["operations"])}
                         for k, v in sorted(self.families.items())},
            "unfamilied_operations": sorted(self.unfamilied_operations),
            "sensitive_leaf_index": {k: sorted(v) for k, v
                                     in sorted(self.sensitive_leaf_index.items())},
            "cross_operation_probes": list(self.cross_operation_probes),
            "analysis": {
                "analyzable": self.analyzable,
                "sources": [{"name": s.name, "analyzed": s.analyzed,
                             "reason": s.reason, "bytes": s.bytes,
                             "tokens": s.tokens, "call_sites": s.call_sites,
                             "dropped_unresolvable": s.dropped_unresolvable}
                            for s in self.sources],
                "unanalyzable": [{"name": s.name, "reason": s.reason}
                                 for s in self.sources if not s.analyzed],
            },
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- #
# extraction                                                                   #
# --------------------------------------------------------------------------- #

def _template_text(tok, fragments: dict) -> Optional[str]:
    """Static text of a template literal, splicing only LITERALLY-DEFINED fragments.

    An interpolation whose expression is a bare identifier naming a `gql` fragment
    defined elsewhere in the same bundle is spliced in — the text is written down,
    just in two places. Any other interpolation makes the document unresolvable,
    and it is dropped rather than approximated.
    """
    parts: list = []
    for kind, val in tok.value:
        if kind == "s":
            parts.append(val)
            continue
        expr = str(val).strip()
        if len(expr) > _MAX_EXPR_LEN or not _IDENT.match(expr):
            return None
        frag = fragments.get(expr)
        if frag is None:
            return None
        parts.append("\n" + frag)
    text = "".join(parts)
    return text if 0 < len(text) <= _MAX_QUERY_LEN else None


def _collect_fragments(toks) -> dict:
    """Identifier -> literal fragment document, for `const F = gql\\`fragment ...\\``."""
    out: dict = {}
    n = len(toks)
    for i in range(n):
        if len(out) >= _MAX_FRAGMENTS:
            break
        t = toks[i]
        if t.kind != "IDENT" or t.value not in _GQL_TAGS:
            continue
        if i + 1 >= n or toks[i + 1].kind != "TPL":
            continue
        text = "".join(v for k, v in toks[i + 1].value if k == "s")
        if "fragment" not in text:
            continue
        if not _FRAGMENT_DEF.search(text[:_MAX_QUERY_LEN]):
            continue
        # name the fragment by the identifier it was assigned to: `const F = gql`...``
        if i >= 2 and toks[i - 1].kind == "PUNCT" and toks[i - 1].value in ("=", ":") \
                and toks[i - 2].kind == "IDENT":
            out[toks[i - 2].value] = text
    return out


def _extract_from_tokens(toks, src_name: str, rep: SourceReport) -> list:
    """Operation bindings declared in one lexed source."""
    from .graphql import parse_graphql_request

    fragments = _collect_fragments(toks)
    out: list = []
    n = len(toks)
    for i in range(n):
        if len(out) >= _MAX_OPERATIONS:
            break
        t = toks[i]
        if t.kind != "IDENT" or t.value not in _GQL_TAGS:
            continue

        text = None
        if i + 1 < n and toks[i + 1].kind == "TPL":
            rep.call_sites += 1
            text = _template_text(toks[i + 1], fragments)
        elif i + 2 < n and toks[i + 1].value == "(":
            rep.call_sites += 1
            # `gql("...")` — a single fully-static argument, or nothing
            arg = toks[i + 2]
            end = _skip_balanced(toks, i + 1, _MAX_SCAN_SPAN)
            if arg.kind == "STR" and not arg.oversized and end == i + 4:
                text = arg.value
            elif arg.kind == "TPL" and end == i + 4:
                text = _template_text(arg, fragments)
        else:
            continue

        if not text:
            rep.dropped_unresolvable += 1
            continue

        # The project's OWN parser decides what this document is. No second parser.
        op = parse_graphql_request({"query": text})
        if op is None or not op.root_fields:
            rep.dropped_unresolvable += 1
            continue

        leaves = selection_leaves(text)
        out.append(OperationBinding(
            op_type=op.op_type, op_name=op.op_name,
            root_fields=tuple(op.root_fields), leaves=leaves,
            sensitive=sensitive_leaves(leaves),
            found_in=f"{src_name}:{t.line}", query=text[:1200],
        ))
    return out


def extract(sources: list) -> CrossOperationContract:
    """Extract operation bindings from JS sources. No I/O, no execution."""
    fc = CrossOperationContract()
    total = 0
    seen: set = set()

    for s in sorted(sources, key=lambda x: (x.name, x.host)):
        name = s.name
        if name in seen:
            k = 2
            while f"{name}#{k}" in seen:
                k += 1
            name = f"{name}#{k}"
        seen.add(name)

        rep = SourceReport(name=name, bytes=len(s.text or ""))
        fc.sources.append(rep)
        if not s.text:
            rep.reason = EMPTY_SOURCE
            continue
        if rep.bytes > _MAX_SOURCE_BYTES or total + rep.bytes > _MAX_TOTAL_BYTES:
            rep.reason = OVER_BUDGET
            continue
        total += rep.bytes

        try:
            toks = _lex(s.text)
        except (_LexError, RecursionError):
            # RL5: a source we cannot read cleanly contributes NOTHING. The
            # bindings found before the error are discarded — a half-read bundle
            # is not a contract.
            rep.reason = UNLEXABLE
            continue

        rep.tokens = len(toks)
        rep.analyzed = True
        fc.operations.extend(_extract_from_tokens(toks, name, rep))

    fc.operations = sorted(set(fc.operations),
                           key=lambda o: (o.key, o.found_in))
    for o in fc.operations:
        for leaf in o.sensitive:
            fc.sensitive_leaf_index.setdefault(leaf, [])
            if o.key not in fc.sensitive_leaf_index[leaf]:
                fc.sensitive_leaf_index[leaf].append(o.key)

    if not fc.analyzable and fc.sources:
        fc.notes.append("no source was analyzable — empty contract emitted "
                        "(fail-safe); absence of operation bindings is NOT "
                        "evidence of absence")
    fc.notes = sorted(set(fc.notes))
    return fc


# --------------------------------------------------------------------------- #
# families — declared bases only                                               #
# --------------------------------------------------------------------------- #

def _schema_return_types(introspection) -> dict:
    """root field -> declared return type name, from an introspection document.

    The schema is the target's own declaration of what each root field returns.
    Reading it is transcription; nothing here compares names for resemblance.
    """
    out: dict = {}
    if not isinstance(introspection, dict):
        return out
    schema = introspection.get("data", introspection).get("__schema")
    if not isinstance(schema, dict):
        return out
    names = set()
    for k in ("queryType", "mutationType", "subscriptionType"):
        v = schema.get(k)
        if isinstance(v, dict) and v.get("name"):
            names.add(v["name"])
    for t in (schema.get("types") or []):
        if not isinstance(t, dict) or t.get("name") not in names:
            continue
        for f in (t.get("fields") or []):
            if not isinstance(f, dict) or not f.get("name"):
                continue
            tn = _unwrap_type(f.get("type"))
            if tn:
                out[f["name"]] = tn
    return out


def _unwrap_type(t) -> str:
    """Strip NON_NULL / LIST wrappers to the named type. Structural only."""
    depth = 0
    while isinstance(t, dict) and depth < 12:
        if t.get("name"):
            return str(t["name"])
        t = t.get("ofType")
        depth += 1
    return ""


def build_families(contract: CrossOperationContract, operation_families=None,
                   introspection=None) -> CrossOperationContract:
    """Group operations on a DECLARED basis, in fixed precedence.

    An operation that two bases place in different families is suppressed from
    both and reported — an ambiguity resolved by preference would be a guess.
    """
    declared: dict = {}
    for fam, members in (operation_families or {}).items():
        for m in (members if isinstance(members, (list, tuple, set)) else []):
            declared.setdefault(str(m), set()).add((FAMILY_OPERATOR, str(fam)))

    ret = _schema_return_types(introspection)

    assign: dict = {}
    for op in contract.operations:
        cands: set = set()
        for root in op.root_fields:
            cands |= declared.get(root, set())
            if root in ret:
                cands.add((FAMILY_SCHEMA, ret[root]))
            cands.add((FAMILY_ROOT, root))
        best = None
        for basis in (FAMILY_OPERATOR, FAMILY_SCHEMA, FAMILY_ROOT):
            tier = sorted({c for c in cands if c[0] == basis})
            if not tier:
                continue
            if len(tier) > 1:
                contract.notes.append(
                    f"operation {op.key} is placed in {len(tier)} different "
                    f"families by basis '{basis}' — suppressed from all (fail-safe)")
                best = None
                break
            best = tier[0]
            break
        if best is None:
            contract.unfamilied_operations.append(op.key)
            continue
        assign.setdefault(best, []).append(op.key)

    for (basis, fam), members in sorted(assign.items()):
        contract.families[f"{basis}:{fam}"] = {"basis": basis,
                                               "operations": sorted(set(members))}
    contract.unfamilied_operations = sorted(set(contract.unfamilied_operations))
    contract.notes = sorted(set(contract.notes))
    return contract


# --------------------------------------------------------------------------- #
# the product: a measured refusal contradicted by a declared door              #
# --------------------------------------------------------------------------- #

def observed_denials(exchanges) -> dict:
    """(principal, leaf) -> the operation that was refused, from real traffic.

    Uses `graphql.authz_denied_paths`, so the "a null is not a denial" rule and
    the authz-class filter are the project's own, not a second copy.
    """
    from .graphql import authz_denied_paths
    out: dict = {}
    for ex in exchanges or []:
        try:
            body = getattr(ex.response, "body", None)
            paths = authz_denied_paths(body)
            if not paths:
                continue
            pid = getattr(getattr(ex, "principal", None), "pid", "") or ""
            try:
                op = ex.request.graphql_op()
                where = op.endpoint_key() if op else ex.request.endpoint_key()
            except Exception:                        # noqa: BLE001
                where = ""
            for p in paths:
                leaf = p.split(".")[-1].split("[")[0]
                if leaf:
                    out.setdefault((pid, leaf), []).append(where)
        except Exception:                            # noqa: BLE001
            continue
    return {k: sorted(set(v)) for k, v in sorted(out.items())}


def cross_operation_probes(contract: CrossOperationContract, denials: dict) -> list:
    """Where the server refused a leaf, list the OTHER declared doors selecting it.

    This is the whole product, and it needs no operation-equivalence claim: the
    join is the literal leaf name, spelled out by the server in its own error path
    and by the client in its own query text. `org` and `orgWebhooks` are never
    asserted to be the same type, because the question is not whether they are —
    it is whether a refused leaf is reachable through another declared door.
    """
    probes: list = []
    for (pid, leaf), refused_at in sorted(denials.items()):
        for op in contract.operations:
            if leaf not in op.sensitive and leaf not in op.leaves:
                continue
            if op.op_type not in _PLANNABLE_OP_TYPES:
                continue                             # mutations are never planned
            if op.key in refused_at:
                continue                             # the door that was refused
            probes.append({
                "principal": pid, "leaf": leaf,
                "declared_operation": op.key,
                "declared_at": op.found_in,
                "refused_at": list(refused_at),
                "probe": (f"as principal '{pid}', issue POST /graphql "
                          f"{op.key}; a 2xx carrying '{leaf}' with substantive "
                          f"content CONTRADICTS the recorded refusal of that same "
                          f"leaf and is a cross-surface candidate — confirm by "
                          f"Delta-state read-back, never by the status code alone"),
                "epistemic_status": ("the refusal is MEASURED and the selection is "
                                     "DECLARED; no claim is made that these two "
                                     "operations are equivalent, and none is needed"),
                "resolved": False,
            })
    probes.sort(key=lambda d: (d["principal"], d["leaf"], d["declared_operation"]))
    return probes[:_MAX_PROBES]


# --------------------------------------------------------------------------- #
# capture bridge                                                               #
# --------------------------------------------------------------------------- #

def from_har(har: dict, scope=None, in_scope_hosts=None, operation_families=None,
             introspection=None, enabled: bool = False) -> CrossOperationContract:
    """Extract operation bindings from a capture's bundles and confront them with
    the refusals the same capture recorded.

    DEFAULT OFF. Zero network, zero execution: assets come from the capture, and
    every probe is DESCRIBED, never issued.
    """
    if not enabled:
        return CrossOperationContract()

    from .frontend_contract import js_sources_from_har
    from .harimport import parse_har_exchanges

    excluded: list = []
    sources = js_sources_from_har(har, scope, in_scope_hosts, excluded)
    contract = extract(sources)
    build_families(contract, operation_families, introspection)

    try:
        _principals, exchanges = parse_har_exchanges(har, in_scope_hosts)
    except Exception:                                # noqa: BLE001
        exchanges = []
    contract.cross_operation_probes = cross_operation_probes(
        contract, observed_denials(exchanges))

    if excluded:
        contract.notes.append(f"{len(excluded)} JS asset(s) excluded by scope: "
                              + ", ".join(sorted(excluded)[:10]))
    if contract.operations and not contract.cross_operation_probes:
        contract.notes.append("operation bindings were found but no recorded refusal "
                              "contradicts any of them — a planted or merely unused "
                              "operation produces no probe by design")
    contract.notes.append("no operation-equivalence is synthesised; families come "
                          "only from an operator declaration, a schema, or an "
                          "identical root field")
    contract.notes = sorted(set(contract.notes))
    return contract
