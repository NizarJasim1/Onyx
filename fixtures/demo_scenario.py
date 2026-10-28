"""
Labeled demo scenario (§9 offline harness).

Builds principals + a MockTarget + a contract, then defines:
  * SEED actions   — legitimate, each principal acting on its OWN objects. These
                     build the measured envelopes (observe phase).
  * PROBE actions  — the things a bounty hunter would try, each LABELED with its
                     expected outcome so calibration can assert: the law fires on
                     the planted bug AND stays silent on the benign path.

Expected outcomes are ground truth for tests/calibration.py — not used by the
engine itself (which derives everything deterministically).
"""

from __future__ import annotations

from dataclasses import dataclass

from authpath.models import HTTPRequest, Principal
from authpath.transport import MockTarget, make_exchange


# --------------------------------------------------------------------------- #
# Principals — provisioned by the tester, never fabricated (D6)               #
# --------------------------------------------------------------------------- #

def build_principals() -> dict[str, Principal]:
    return {
        "A": Principal("A", "Alice (victim / order-101 owner)", {"Authorization": "Bearer tokenA"}),
        "B": Principal("B", "Bob (attacker / order-202 owner)", {"Authorization": "Bearer tokenB"}),
        "C": Principal("C", "Carol (widget control / low-privilege)", {"Authorization": "Bearer tokenC"}),
        "D": Principal("D", "Dave (folder owner — RL18 hierarchy)", {"Authorization": "Bearer tokenD"}),
        "anon": Principal("anon", "Anonymous (no session)", {}, is_anonymous=True),
    }


# --------------------------------------------------------------------------- #
# Contract — declares effect-classes only, never forbiddenness (D4)           #
# --------------------------------------------------------------------------- #

def build_contract() -> dict:
    return {
        "GET /api/orders/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "GET /api/profiles/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "PATCH /api/users/{id}": {"effect": "OWNERSHIP", "critical_params": ["role", "is_admin"]},
        "GET /api/admin/users": {"effect": "AUTHORITY"},
        "POST /api/checkout": {"effect": "PAYMENT", "critical_params": ["amount_paid", "amount_due"]},
        "POST /api/cart/price": {"effect": "PRICE", "critical_params": ["total"]},
        "POST /api/orders/{id}/fulfil": {"effect": "STATE_GATE"},
        "POST /api/coupon/redeem": {"effect": "COUPON", "critical_params": ["coupon"]},
        "GET /api/me": {"effect": "OBJECT_ACCESS"},
        "POST /api/account/password": {"effect": "NONE"},
        # SAIE structural-divergence demo families. widgets/reports are object
        # reads (so the existing OBJECT_ACCESS law also runs and correctly
        # abstains on filtered content — letting SAIE fire alone); config/feed are
        # plain reads with no effect-class law.
        "GET /api/widgets/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "GET /api/reports/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "GET /api/config": {"effect": "READ"},
        "GET /api/feed": {"effect": "READ"},
        "GET /api/directory": {"effect": "READ"},
        "GET /api/admin/billing": {"effect": "AUTHORITY"},
        "GET /api/vault/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "GET /api/session": {"effect": "READ"},
        "GET /api/cases/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "QUERY GetOrder": {"effect": "READ"},
        "GET /api/handoff": {"effect": "READ"},
        "POST /api/claim": {"effect": "READ"},
        "GET /api/dossier": {"effect": "READ"},
        "POST /api/role/downgrade": {"effect": "NONE"},
        # RL16 temporal families.
        "GET /api/profile2/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "GET /api/clearance/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "POST /api/promote": {"effect": "NONE"},
        "GET /api/payouts/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        # RL18 hierarchy families + the DECLARED parent links (child identity → parent).
        "GET /api/folders/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "GET /api/docs/{id}": {"effect": "OBJECT_ACCESS", "critical_params": ["id"]},
        "POST /api/folders/{id}/transfer": {"effect": "NONE"},
        "resource_parents": {"doc:d1": "folder:f1", "doc:d2": "folder:f2",
                             "doc:d3": "folder:f1"},
        "role_change_events": [
            {"endpoint": "POST /api/role/downgrade",
             "affects_principals": ["C"], "kind": "role_downgrade"},
            {"endpoint": "POST /api/promote",
             "affects_principals": ["B"], "kind": "role_promote"}],
        # Temporal-drift: a successful password change should invalidate A's token.
        "revocation_events": [
            {"endpoint": "POST /api/account/password",
             "invalidates_principals": ["A"], "kind": "password_change"},
        ],
    }


# --------------------------------------------------------------------------- #
# Scenario steps                                                              #
# --------------------------------------------------------------------------- #

@dataclass
class Step:
    kind: str                  # "seed" | "probe"
    principal: str
    request: HTTPRequest
    label: str = ""
    expect: str = ""           # ground truth: "finding" | "clean" (probes only)
    expect_effect: str = ""


def build_steps() -> list[Step]:
    return [
        # ---- SEED: each principal legitimately touches its OWN objects ----
        Step("seed", "A", HTTPRequest("GET", "/api/orders/101"),
             "Alice reads her own order 101"),
        Step("seed", "B", HTTPRequest("GET", "/api/orders/202"),
             "Bob reads his own order 202"),
        Step("seed", "B", HTTPRequest("GET", "/api/orders/303"),
             "Bob reads his own (unpaid) order 303"),
        Step("seed", "A", HTTPRequest("PATCH", "/api/users/A", body={"name": "Alice A."}),
             "Alice updates her own display name"),
        Step("seed", "A", HTTPRequest("GET", "/api/profiles/A"),
             "Alice reads her own protected profile"),

        # ---- SAIE SEED: each principal repeats identical reads (>=2) so Layer 0
        # can prove a stable grammar. Existing families above are read once each,
        # so they never become SAIE-eligible (additive isolation). ----
        Step("seed", "A", HTTPRequest("GET", "/api/widgets/50"),
             "Alice reads her own PRIVILEGED widget 50 (#1 — builds rich grammar)"),
        Step("seed", "A", HTTPRequest("GET", "/api/widgets/50"),
             "Alice reads her own PRIVILEGED widget 50 (#2 — proves shape-stable)"),
        Step("seed", "B", HTTPRequest("GET", "/api/widgets/70"),
             "Bob reads his own standard widget 70 (#1 — builds lean grammar)"),
        Step("seed", "B", HTTPRequest("GET", "/api/widgets/70"),
             "Bob reads his own standard widget 70 (#2 — proves shape-stable)"),
        Step("seed", "C", HTTPRequest("GET", "/api/widgets/60"),
             "Carol reads her own standard widget 60 (#1 — lower-priv control)"),
        Step("seed", "C", HTTPRequest("GET", "/api/widgets/60"),
             "Carol reads her own standard widget 60 (#2 — proves shape-stable)"),
        # reports family (object-driven richness — Gate-2 negative)
        Step("seed", "A", HTTPRequest("GET", "/api/reports/80"),
             "Alice (report admin) reads featured report 80 (#1 — rich populated)"),
        Step("seed", "A", HTTPRequest("GET", "/api/reports/80"),
             "Alice (report admin) reads featured report 80 (#2)"),
        Step("seed", "C", HTTPRequest("GET", "/api/reports/80"),
             "Carol reads the SAME featured report 80 (#1 — rich shape, filtered)"),
        Step("seed", "C", HTTPRequest("GET", "/api/reports/80"),
             "Carol reads the SAME featured report 80 (#2)"),
        Step("seed", "B", HTTPRequest("GET", "/api/reports/90"),
             "Bob reads his own lean report 90 (#1)"),
        Step("seed", "B", HTTPRequest("GET", "/api/reports/90"),
             "Bob reads his own lean report 90 (#2)"),
        # config family (map-like reorder — negative)
        Step("seed", "B", HTTPRequest("GET", "/api/config"),
             "Bob reads /api/config (#1)"),
        Step("seed", "B", HTTPRequest("GET", "/api/config"),
             "Bob reads /api/config (#2 — keys reordered, must stay map-like-stable)"),
        # feed family (volatile topology — negative)
        Step("seed", "B", HTTPRequest("GET", "/api/feed"),
             "Bob reads /api/feed (#1)"),
        Step("seed", "B", HTTPRequest("GET", "/api/feed"),
             "Bob reads /api/feed (#2 — topology varies, must be excluded)"),
        # vault family — observed ONCE each (no stability proof): the relational
        # finding path stays silent; the PROVISIONAL lead path covers it.
        Step("seed", "A", HTTPRequest("GET", "/api/vault/200"),
             "Alice reads her own PRIVILEGED vault 200 (single observation)"),
        Step("seed", "B", HTTPRequest("GET", "/api/vault/210"),
             "Bob reads his own standard vault 210 (single observation)"),
        # session family — the SAME request issued repeatedly; a sensitive field
        # appears intermittently (authorization-conditional emission).
        Step("seed", "B", HTTPRequest("GET", "/api/session"),
             "Bob reads /api/session (#1 — internal_token present)"),
        Step("seed", "B", HTTPRequest("GET", "/api/session"),
             "Bob reads /api/session (#2 — internal_token absent)"),
        Step("seed", "B", HTTPRequest("GET", "/api/session"),
             "Bob reads /api/session (#3 — internal_token present again)"),
        # cases family — the SAME record read by two principals with DIFFERENT
        # field-level projection (junior C sees an 'internal' branch senior A doesn't).
        Step("seed", "A", HTTPRequest("GET", "/api/cases/300"),
             "Alice (senior) reads case 300 — no internal branch"),
        Step("seed", "C", HTTPRequest("GET", "/api/cases/300"),
             "Carol (junior) reads the SAME case 300 — receives the internal branch"),

        # ---- PROBE: benign (MUST stay silent — confirm-by-Δstate test) ----
        Step("probe", "B", HTTPRequest("GET", "/api/orders/202"),
             "Bob re-reads his OWN order 202 (benign)", expect="clean",
             expect_effect="OBJECT_ACCESS"),
        Step("probe", "A", HTTPRequest("PATCH", "/api/users/A", body={"name": "Alice Allison"}),
             "Alice updates her OWN non-privileged field (benign)", expect="clean",
             expect_effect="OWNERSHIP"),
        Step("probe", "B", HTTPRequest("GET", "/api/profiles/A"),
             "Bob requests Alice's profile, server soft-denies with 200 (D3 trap — "
             "candidate flagged, Δstate must DROP it)", expect="clean",
             expect_effect="OBJECT_ACCESS"),

        # ---- PROBE: planted bugs (MUST become confirmed findings) ----
        Step("probe", "B", HTTPRequest("GET", "/api/orders/101"),
             "Bob reads Alice's order 101 (IDOR/BOLA)", expect="finding",
             expect_effect="OBJECT_ACCESS"),
        Step("probe", "B", HTTPRequest("PATCH", "/api/users/B", body={"role": "admin"}),
             "Bob sets his own role=admin (mass assignment/BOPLA)", expect="finding",
             expect_effect="OWNERSHIP"),
        Step("probe", "anon", HTTPRequest("GET", "/api/admin/users"),
             "Anonymous lists all users (BFLA)", expect="finding",
             expect_effect="AUTHORITY"),
        Step("probe", "B", HTTPRequest("POST", "/api/checkout",
                                       body={"order_id": "202", "amount_due": 90.0, "amount_paid": 1.0}),
             "Bob pays 1.00 on a 90.00 order (payment tampering)", expect="finding",
             expect_effect="PAYMENT"),
        Step("probe", "B", HTTPRequest("POST", "/api/cart/price",
                                       body={"total": 5.0, "items": [{"sku": "y", "price": 90.0, "qty": 1}]}),
             "Bob declares total=5.00 for a 90.00 cart (price tampering)", expect="finding",
             expect_effect="PRICE"),
        Step("probe", "B", HTTPRequest("POST", "/api/orders/303/fulfil"),
             "Bob fulfils unpaid order 303 (state-gate skip)", expect="finding",
             expect_effect="STATE_GATE"),
        Step("probe", "B", HTTPRequest("POST", "/api/coupon/redeem", body={"coupon": "SAVE20", "limit": 1}),
             "Bob redeems single-use coupon (1st time)", expect="clean",
             expect_effect="COUPON"),
        Step("probe", "B", HTTPRequest("POST", "/api/coupon/redeem", body={"coupon": "SAVE20", "limit": 1}),
             "Bob redeems the SAME single-use coupon again (coupon reuse)", expect="finding",
             expect_effect="COUPON"),

        # ---- TEMPORAL DRIFT: stale credential after a revocation event ----
        Step("seed", "A", HTTPRequest("GET", "/api/me"),
             "Alice reads her own session profile (legit, pre-event)"),
        Step("seed", "A", HTTPRequest("POST", "/api/account/password", body={"new": "s3cret!"}),
             "Alice changes her password (revocation event — should kill old token)"),
        Step("probe", "A", HTTPRequest("GET", "/api/me"),
             "Alice's OLD token still reads private data AFTER password change "
             "(temporal authorization drift — token never revoked)", expect="finding",
             expect_effect="TEMPORAL_DRIFT"),

        # ---- SAIE: structural authorization-path divergence ----
        # POSITIVE: Bob reads Alice's PRIVILEGED widget 50. Content is filtered
        # (every sensitive value nulled), so the existing OBJECT_ACCESS confirmer
        # finds nothing substantive and DROPS its candidate — yet the response
        # carries the privileged STRUCTURE (internal.*/audit.* present-but-null)
        # that only the owner's grammar has. SAIE proves the privileged code path
        # executed: Gate 1 breach + lower-priv control (Carol) clean + functional
        # anchor. This is the one finding content-diffing tools cannot see.
        Step("probe", "B", HTTPRequest("GET", "/api/widgets/50"),
             "Bob reads Alice's PRIVILEGED widget 50 — values filtered to null, but "
             "the privileged SHAPE leaks the authorization path (structural divergence)",
             expect="finding", expect_effect="STRUCTURAL_DIVERGENCE"),

        # NEGATIVE 1 — value-only difference, same lean shape: Bob re-reads a widget
        # whose shape matches his own grammar → coherent → no finding.
        Step("probe", "B", HTTPRequest("GET", "/api/widgets/70"),
             "Bob re-reads his OWN standard widget 70 (value-only, shape coherent)",
             expect="clean", expect_effect="OBJECT_ACCESS"),
        # NEGATIVE 2 — map-like key reorder: order signal disabled by Layer 0 → clean.
        Step("probe", "B", HTTPRequest("GET", "/api/config"),
             "Bob reads /api/config again (key reorder must NOT diverge — map-like)",
             expect="clean", expect_effect="READ"),
        # NEGATIVE 3 — object-driven richness with a matching control: Bob reads the
        # featured report 80 (rich shape) but a genuine lower-priv control (Carol)
        # ALSO receives that shape → SAIE Gate 2 finds no clean control → suppressed.
        Step("probe", "B", HTTPRequest("GET", "/api/reports/80"),
             "Bob reads featured report 80 (rich shape is by-design / object-driven — "
             "Gate 2 must suppress: a lower-priv control also receives it)",
             expect="clean", expect_effect="OBJECT_ACCESS"),
        # NEGATIVE 4 — volatile topology: Layer 0 excludes the unstable nodes → clean.
        Step("probe", "B", HTTPRequest("GET", "/api/feed"),
             "Bob reads /api/feed (volatile topology — excluded by the stability gate)",
             expect="clean", expect_effect="READ"),
        # INTRINSIC ELEVATION (reference-free → confirmed finding in ONE read-back):
        # the finding-pipeline passes this list as clean, but one member row leaks a
        # privileged overlay (salary/internal). Intrinsic interrogation flags it from
        # ONE response; the engine then confirms with a SINGLE canonical detail
        # read-back (the detail view filters what the list leaked) → a real finding.
        Step("probe", "B", HTTPRequest("GET", "/api/directory"),
             "Bob reads /api/directory — one row leaks salary/internal; intrinsic lead "
             "elevated to a finding by a single list-vs-detail read-back",
             expect="finding", expect_effect="FIELD_PROJECTION"),
        # INTRINSIC RECON — the endpoint correctly denies Bob (403, no finding), but
        # the denial body discloses the exact gate (required_role/missing_scopes):
        # an AUTHZ_ORACLE lead that maps the attack surface with zero extra traffic.
        Step("probe", "B", HTTPRequest("GET", "/api/admin/billing"),
             "Bob is denied /api/admin/billing (403) but the body leaks required_role/"
             "missing_scopes — intrinsic AUTHZ_ORACLE recon lead",
             expect="clean", expect_effect="AUTHORITY"),
        # PROVISIONAL (single-observation relational hint): Bob reads Alice's
        # privileged vault 200. Neither grammar is stability-proven (one read each),
        # so the finding path stays silent — but the provisional path emits a
        # lowest-tier lead flagging the privileged-named paths, with the exact
        # repeats needed to promote it to a confirmed finding.
        Step("probe", "B", HTTPRequest("GET", "/api/vault/200"),
             "Bob reads Alice's PRIVILEGED vault 200 (unstable grammars — provisional "
             "relational lead, not yet a finding)",
             expect="clean", expect_effect="OBJECT_ACCESS"),
        # INTERMITTENT PRESENCE: the same /api/session request emits the sensitive
        # 'internal_token' only sometimes — a flicker under identical input that the
        # normalisation layer flags as authorization-conditional (current tools see
        # only inconsistent noise). Lead-only; the response itself stays clean.
        Step("probe", "B", HTTPRequest("GET", "/api/session"),
             "Bob reads /api/session again — internal_token flickers across identical "
             "requests (intermittent-presence lead)",
             expect="clean", expect_effect="READ"),
        # MISSING SHADOW: re-reading the same case 300 triggers the field-level
        # authorization map — the 'internal' branch is populated for junior C yet
        # ABSENT for senior A on an identical record (no PRESENT_NULL residue). An
        # ABSENCE_MAP recon lead no passive tool produces.
        Step("probe", "C", HTTPRequest("GET", "/api/cases/300"),
             "Carol re-reads case 300 — field-level absence differential vs Alice "
             "on the same record (missing-shadow map)",
             expect="clean", expect_effect="OBJECT_ACCESS"),
        # GRAPHQL FIELD-LEVEL BOLA: one GraphQL endpoint; A and B issue the identical
        # selection on the SAME order 101. A receives order.internal; B is denied it
        # with a FORBIDDEN field error. The demultiplexer maps (operation, object) and
        # the field-level lens flags the differential — invisible to path-based tools.
        Step("probe", "C", HTTPRequest("POST", "/graphql", body={
            "operationName": "GetOrder", "variables": {"id": "101"},
            "query": "query GetOrder($id: ID!){ order(id:$id){ id status internal{ margin } } }"}),
             "Carol queries order 101 via GraphQL — receives the internal field",
             expect="clean", expect_effect="READ"),
        Step("probe", "B", HTTPRequest("POST", "/graphql", body={
            "operationName": "GetOrder", "variables": {"id": "101"},
            "query": "query GetOrder($id: ID!){ order(id:$id){ id status internal{ margin } } }"}),
             "Bob queries the SAME order 101 — internal is authz-denied (FORBIDDEN); "
             "the active probe reproduces the differential → confirmed field-level BOLA",
             expect="finding", expect_effect="READ"),
        # CHAIN PROVENANCE: a sensitive transfer token surfaces in Alice's private
        # handoff response, then Bob consumes that very token in his claim request —
        # a cross-principal value migration spanning the request chain.
        Step("seed", "A", HTTPRequest("GET", "/api/handoff"),
             "Alice receives a sensitive transfer_token in her handoff response"),
        Step("probe", "B", HTTPRequest("POST", "/api/claim",
                                       body={"token": "tok_AB12cd34ef56gh"}),
             "Bob claims using Alice's transfer_token — cross-step value migration",
             expect="clean", expect_effect="READ"),
        # TEMPORAL STRUCTURAL DRIFT: Carol's role is downgraded (her credential stays
        # VALID, so the value-based revocation law never fires), yet her later dossier
        # response still carries the privileged 'internal' branch structurally — the
        # downgrade was not enforced at the authorization layer.
        Step("probe", "C", HTTPRequest("POST", "/api/role/downgrade"),
             "Carol's role is downgraded (credential remains valid)",
             expect="clean", expect_effect="NONE"),
        Step("probe", "C", HTTPRequest("GET", "/api/dossier"),
             "Carol's post-downgrade dossier still structurally exposes the privileged "
             "'internal' branch — temporal structural drift (role narrowed, code path didn't)",
             expect="clean", expect_effect="READ"),

        # ---- RL15 CROSS-SURFACE CONSISTENCY (the boundary law) ----
        # SEED: B reads the CANONICAL detail of his own account 900. The detail
        # serializer correctly filters `iban` — this is the server's authoritative
        # answer to "what may B see of account 900". It is recorded as the reference.
        Step("seed", "B", HTTPRequest("GET", "/api/accounts/900"),
             "Bob reads the canonical detail of his own account 900 (iban filtered — "
             "authoritative reference)"),
        # SEED: canonical reference for the decoy resource (detail richer than list).
        Step("seed", "B", HTTPRequest("GET", "/api/cards/c1"),
             "Bob reads the canonical detail of his card c1 (detail carries full_pan)"),

        # POSITIVE: B reads the LIST view of accounts. A different serializer leaks
        # `iban` for his OWN account 900 — a sensitive field the canonical view
        # withholds from the very same principal. Cross-surface inconsistency; the
        # confirmer proves it by re-reading the canonical detail (still no iban).
        # This is invisible to every per-endpoint tool: neither door is wrong alone.
        Step("probe", "B", HTTPRequest("GET", "/api/accounts"),
             "Bob lists /api/accounts — the list serializer over-projects `iban` that the "
             "canonical detail filters for the SAME principal (cross-surface leak)",
             expect="finding", expect_effect="CROSS_SURFACE"),
        # NEGATIVE (directional): the cards LIST is LEANER than the canonical detail
        # (summary vs full). The detail exposing more than the list is by-design, so
        # the cross-surface law must stay silent (no non-canonical over-projection).
        Step("probe", "B", HTTPRequest("GET", "/api/cards"),
             "Bob lists /api/cards — the lean list exposes nothing the canonical detail "
             "hides (detail-richer-than-list is by-design — must NOT fire)",
             expect="clean", expect_effect="READ"),

        # ---- RL15 RESIDUE-A: INTENT-DECLARED CANONICAL (GraphQL, no REST detail) ----
        # SEED: B asks for vault 500's `secret` via GraphQL; the server EXPLICITLY
        # refuses it (FORBIDDEN) at the field level. This explicit denial is the
        # intent-declared canonical — the server's own authoritative "B may not see
        # vault.secret". There is NO REST detail door for vaults to use instead.
        Step("seed", "B", HTTPRequest("POST", "/graphql", body={
            "operationName": "GetVault", "variables": {"id": "500"},
            "query": "query GetVault($id: ID!){ vault(id:$id){ id secret } }"}),
             "Bob queries vault 500's secret via GraphQL — server returns FORBIDDEN "
             "(intent-declared canonical: secret is withheld from Bob)"),
        # POSITIVE: B lists /api/vaults through a REST door that over-projects the
        # very `secret` the GraphQL layer forbids him. No REST detail exists, so only
        # the intent-declared reference can catch it; the confirmer replays the
        # GraphQL op and proves the denial is still live while the list served it.
        Step("probe", "B", HTTPRequest("GET", "/api/vaults"),
             "Bob lists /api/vaults — the list leaks `secret` for vault 500, the exact "
             "field GraphQL declares FORBIDDEN to Bob (cross-surface vs explicit denial)",
             expect="finding", expect_effect="CROSS_SURFACE"),

        # ---- RL15 Residue-A (#2-a): PERSISTED / APQ queries (hash-only intent) ----
        # SEED (registration): the FULL wallet query is observed ONCE with its hash —
        # ONYX learns hash→operation (measured, never guessed). No denial recorded
        # here matters; this is purely the intent registration.
        Step("seed", "A", HTTPRequest("POST", "/graphql", body={
            "operationName": "GetWallet", "variables": {"id": "700"},
            "extensions": {"persistedQuery": {"version": 1,
                                              "sha256Hash": "wallet_sha256_demo"}},
            "query": "query GetWallet($id: ID!){ wallet(id:$id){ id private_key } }"}),
             "Alice registers the wallet APQ query (text + hash observed once → "
             "ONYX learns hash→intent)"),
        # SEED (HASH-ONLY): Bob asks for wallet 700 with ONLY the persisted hash — no
        # query text. ONYX resolves the hash to the wallet operation, binds the
        # resource identity, and records the server's FORBIDDEN on `private_key`.
        # To every per-request tool this request is an opaque hash.
        Step("seed", "B", HTTPRequest("POST", "/graphql", body={
            "operationName": "GetWallet", "variables": {"id": "700"},
            "extensions": {"persistedQuery": {"version": 1,
                                              "sha256Hash": "wallet_sha256_demo"}}}),
             "Bob queries wallet 700 by HASH ONLY (no query text) — server returns "
             "FORBIDDEN on private_key; ONYX resolves the hash to record the denial"),
        # POSITIVE: Bob lists /api/wallets; the list over-projects `private_key` —
        # the field the server forbade him via a HASH-ONLY persisted query. The
        # confirmer replays that hash-only request and proves the denial is live.
        Step("probe", "B", HTTPRequest("GET", "/api/wallets"),
             "Bob lists /api/wallets — the list leaks `private_key` for wallet 700, the "
             "field forbidden to Bob via a PERSISTED (hash-only) GraphQL query "
             "(APQ intent recovered → cross-surface leak)",
             expect="finding", expect_effect="CROSS_SURFACE"),

        # ---- RL16: TEMPORAL AUTHORIZATION-SHAPE REGRESSION (deploy drift) ----
        # SEED (T1): Bob reads his profile; `ssn` is correctly NULLED (withheld).
        # ONYX snapshots the value-blind authorization-shape.
        Step("seed", "B", HTTPRequest("GET", "/api/profile2/900"),
             "T1: Bob's profile correctly withholds `ssn` (null) — snapshot recorded"),
        # PROBE (T2): a deploy regressed the field filter; the SAME read now serves a
        # populated `ssn` to the SAME principal with no role change. `nickname` also
        # appears but is non-sensitive (must be ignored). Confirmed by live read-back.
        Step("probe", "B", HTTPRequest("GET", "/api/profile2/900"),
             "T2 (post-deploy): Bob's profile now exposes `ssn` that was withheld at T1 — "
             "an authorization regression over time, no role change (deploy drift)",
             expect="finding", expect_effect="AUTH_REGRESSION"),

        # NEGATIVE (legitimate role change): clearance.secret was withheld at T1; Bob
        # is then PROMOTED (a declared role-change event), and at T2 the secret is
        # populated. Because the role epoch advanced, the temporal law must NOT treat
        # the widening as a regression.
        Step("seed", "B", HTTPRequest("GET", "/api/clearance/300"),
             "T1: Bob's clearance withholds `secret` (null) — snapshot recorded"),
        Step("probe", "B", HTTPRequest("POST", "/api/promote"),
             "Bob is legitimately promoted (declared role-change event → epoch advances)",
             expect="clean", expect_effect="NONE"),
        Step("probe", "B", HTTPRequest("GET", "/api/clearance/300"),
             "T2: clearance now exposes `secret`, but Bob's role changed in between — a "
             "promotion is not a regression; the temporal law must stay silent",
             expect="clean", expect_effect="READ"),

        # ---- RL17: COMBINATORIAL ORCHESTRATION (one proof → a family campaign) ----
        # SEED: only payout 600 is read canonically (iban filtered → reference for 600).
        Step("seed", "B", HTTPRequest("GET", "/api/payouts/600"),
             "Bob reads the canonical detail of payout 600 (iban filtered — reference)"),
        # PROBE: the payouts LIST leaks `iban` for 600,601,602,603. RL15 convicts 600
        # (it has a reference) and the hypothesis engine generalises the proof into a
        # rule, then ORCHESTRATES per-cell Δstate on the siblings: 601 & 602 are
        # confirmed (canonical hides iban), while 603 — a public payout whose detail
        # legitimately exposes iban — is REFUTED per-cell (zero false positive). The
        # engine discovers 601 & 602 it never observed canonically, from one proof.
        Step("probe", "B", HTTPRequest("GET", "/api/payouts"),
             "Bob lists /api/payouts — RL15 convicts payout 600; the hypothesis engine "
             "then orchestrates targeted Δstate on siblings, confirming 601 & 602 "
             "(never observed directly) and clearing the public payout 603",
             expect="finding", expect_effect="CROSS_SURFACE"),

        # ---- RL18: GLOBAL INVARIANT (emergent break across an operation sequence) ----
        # The SEQUENCE, observed in legitimate traffic: A owns F1 and reads D1 inside
        # it; F1 is then transferred to B; A loses F1 — but D1 never followed.
        Step("seed", "D", HTTPRequest("GET", "/api/folders/F1"),
             "D owns folder F1 (reads it 200) — baseline of the parent authority"),
        Step("seed", "D", HTTPRequest("GET", "/api/folders/F2"),
             "D owns folder F2 (200)"),
        Step("seed", "D", HTTPRequest("GET", "/api/docs/D1"),
             "D reads doc D1 inside F1 (200) — child accessible via the parent"),
        Step("seed", "D", HTTPRequest("GET", "/api/docs/D2"),
             "D reads doc D2 inside F2 (200) — into D's envelope"),
        Step("seed", "D", HTTPRequest("GET", "/api/docs/D3"),
             "D reads doc D3 (independently shared with D) (200) — into D's envelope"),
        Step("probe", "D", HTTPRequest("POST", "/api/folders/F1/transfer"),
             "F1's ownership is transferred to B (a permitted operation)",
             expect="clean", expect_effect="NONE"),
        Step("seed", "D", HTTPRequest("GET", "/api/folders/F1"),
             "D now reads F1 → 403: the parent authority moved to B (observed loss)"),
        # POSITIVE: D still reads D1 — the child did not follow the parent. No single
        # step broke a rule; the SEQUENCE did. Proven by read-only read-backs.
        Step("probe", "D", HTTPRequest("GET", "/api/docs/D1"),
             "D still reads D1 while its declared parent F1 is forbidden to D — an "
             "emergent authorization break the composition produced and no step checked",
             expect="finding", expect_effect="EMERGENT_BREAK"),
        # NEGATIVE (no parent loss): D2's parent F2 was never transferred → no break.
        Step("probe", "D", HTTPRequest("GET", "/api/docs/D2"),
             "D reads D2 under F2 which D still owns — no parent loss, so no break",
             expect="clean", expect_effect="READ"),
        # NEGATIVE (independent grant): D3 is under the lost F1 but is explicitly shared
        # with D — its access is independent of the parent, so it must NOT fire.
        Step("probe", "D", HTTPRequest("GET", "/api/docs/D3"),
             "D reads D3 under the lost F1, but D3 is independently shared with D — a "
             "legitimate grant, not a propagation break; the engine must abstain",
             expect="clean", expect_effect="READ"),
    ]


def run_demo(engine_factory):
    """Drive a fresh engine through seed + probe phases. engine_factory(target,
    principals, contract) -> AuthPathEngine. Returns (engine, steps)."""
    principals = build_principals()
    target = MockTarget()
    contract = build_contract()
    engine = engine_factory(target, principals, contract)
    engine.provisional_leads = True   # demo: surface lead-only relational hints too
    engine.active_probing = True      # demo: confirm field-BOLA via a controlled read-only probe
    engine.chain_provenance = True    # demo: surface cross-step value migration
    engine.temporal_drift = True      # demo: surface temporal structural drift on a revoked credential
    engine.cross_surface = True       # demo (RL15): surface cross-surface canonical-vs-door leaks
    engine.temporal_shape = True      # demo (RL16): surface authorization-shape regression over time
    engine.combinatorial = True       # demo (RL17): orchestrate one proof into a family-wide campaign
    engine.global_invariants = True   # demo (RL18): detect emergent breaks across operation sequences

    steps = build_steps()
    for step in steps:
        p = principals[step.principal]
        ex = make_exchange(target, step.request, p)
        if step.kind == "seed":
            engine.observe(ex)
        else:
            engine.analyze(ex)
    return engine, steps
