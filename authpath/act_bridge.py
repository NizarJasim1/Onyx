"""
authpath.act_bridge — confirm a broadcast-vs-act contradiction by live Δstate.

THE BROADCAST-vs-ACT NERVE (FORGE build, step 3: the only place this nerve touches a
conviction path)
-----------------------------------------------------------------------------------
Steps 1-2 produced, from the target's own words, a CONFRONTATION: the principal B to whom
the target broadcast a field as HIDDEN (or an action as FORBIDDEN). Step 3 confirms the
contradiction the only RL1-safe way — by live reads, reusing the audited `confirmer._read`
(scope-halt, budget, WAF-block and auth-expiry guards all apply):

  hidden_field: read the object AS B → does B actually receive the field with a real,
    non-empty value? AND read AS the declared owner → is that the owner's real value, and
    does B's value MATCH it (so it is genuinely the owner's private datum, leaked)?
  hidden_action: (mutating) only when scope.may_mutate already allowed it — left to the
    existing action confirmer; this bridge confirms the read-exposure case end-to-end and
    PROPOSES mutating cases to the existing confirmer (never forces a mutation itself).

SAFETY CONTRACT (never weaken the project, never add a false positive)
---------------------------------------------------------------------
  * Not imported by the engine/confirmer/any live path → byte-identical.
  * Introduces NO new heuristic conviction. A finding requires two live reads proving the
    contradiction; any ambiguity ⇒ ABSTAIN (RL5). Reuses `_read` only.

F7 PRE-MORTEM — the four abstain guards (written before the code):
  B-1 the field is present for B but null/empty (not real data) → abstain.
  B-2 the owner read-back fails / owner not provisioned → cannot prove it is real → abstain.
  B-3 B's value differs from the owner's value (so it is not the owner's private datum —
      maybe B's own legitimate data) → abstain.
  B-4 a mutating confrontation blocked by scope → abstain; never force a mutation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .attestation import _scalar_fields

# values that are not "real leaked data" even if the field is present
_EMPTY = (None, "", [], {}, "null", "None", "REDACTED", "***")


@dataclass
class BvAFinding:
    kind: str                          # "hidden_field_leak"
    accessor: str                      # the principal the target broadcast it hidden to
    resource: str
    field: str
    owner: str
    why: str


class ActBridge:
    """Confirms broadcast-vs-act contradictions via live Δstate. Read-exposure cases are
    confirmed end-to-end here (reusing _read); mutating cases are handed to the existing
    confirmer. Findings are a SEPARATE channel — never written to engine.findings."""

    def __init__(self, confirmer, principals_by_identity: dict,
                 nonce_authority=None, seeker=None):
        self.confirmer = confirmer
        self.by_identity = principals_by_identity      # attested identity -> Principal
        self.abstained: list = []
        # G14 integration (opt-in). When BOTH are wired, the *_attributed path can
        # prove a write is THIS test's (companion nonce) — killing the "value was
        # pre-existing" ambiguity. When None (default), legacy behavior is unchanged.
        self.nonce_authority = nonce_authority
        self.seeker = seeker

    def confirm_field_leak(self, conf, owner_identity: str,
                           read_request) -> Optional[BvAFinding]:
        """Confirm a `hidden_field` confrontation: the target broadcast `conf.declared`
        as hidden to `conf.accessor`, but the act leaks it. Proven by two live reads."""
        if conf.kind != "hidden_field":
            return None
        accessor = self.by_identity.get(conf.accessor)
        owner = self.by_identity.get(owner_identity)
        if accessor is None:
            self.abstained.append((conf.resource, "accessor not provisioned"))
            return None
        if owner is None:                              # B-2
            self.abstained.append((conf.resource, "declared owner not provisioned"))
            return None
        # live read AS the accessor the field was hidden from
        acc_resp = self.confirmer._read(read_request, accessor)
        if acc_resp is None or not (200 <= getattr(acc_resp, "status", 0) < 300):
            self.abstained.append((conf.resource, "accessor read failed/blocked"))
            return None                                # B-4 / read fail
        acc_fields = _scalar_fields(getattr(acc_resp, "body", None))
        acc_val = acc_fields.get(conf.declared)
        if acc_val in _EMPTY:                          # B-1: not real data, or absent
            self.abstained.append((conf.resource, "field not actually exposed to accessor"))
            return None
        # live read AS the declared owner to prove it is the owner's real private datum
        own_resp = self.confirmer._read(read_request, owner)
        if own_resp is None or not (200 <= getattr(own_resp, "status", 0) < 300):
            self.abstained.append((conf.resource, "owner read-back failed/blocked"))
            return None                                # B-2
        own_val = _scalar_fields(getattr(own_resp, "body", None)).get(conf.declared)
        if own_val in _EMPTY:
            self.abstained.append((conf.resource, "owner has no real value for the field"))
            return None
        if str(acc_val) != str(own_val):               # B-3
            self.abstained.append((conf.resource, "accessor value != owner value (not the owner's datum)"))
            return None
        return BvAFinding(
            kind="hidden_field_leak", accessor=conf.accessor, resource=conf.resource,
            field=conf.declared, owner=owner_identity,
            why=(f"target broadcast field '{conf.declared}' of {conf.resource} as HIDDEN "
                 f"to {conf.accessor}, but the act exposed it with the owner "
                 f"({owner_identity})'s real value — broadcast-vs-act contradiction "
                 f"confirmed by live Δstate."))

    def confirm_field_leak_oob(self, conf, owner_identity, channel, trigger,
                               read_request, host="", attempts=5):
        """G1-integrated second-order OOB leak confirmer.

        Confirms a leak that surfaces NOT in the direct response but in an
        out-of-band channel (an exported file, a webhook callback, an email, an
        audit feed) that the attacker's action triggers. Chains three gap-modules:
          * G14 (nonce): mint a unique token, embed it in the triggering action so
            any artifact carrying it is provably THIS test's,
          * G1 (channel): poll the OOB sink over a settling window,
          * cross-principal: the OWNER's real datum for `conf.declared` must appear
            in that same attributed artifact → a genuine cross-principal leak.

        `trigger(nonce)` is the caller's closure that fires the OOB-producing request
        AS THE ATTACKER with the nonce embedded (e.g., request an export tagged with
        the nonce). `channel` is a wired OOBChannel that polls the real sink.

        A finding requires BOTH our nonce AND the owner's datum in one payload;
        either alone ⇒ abstain (attribution ≠ leak). Opt-in; abstains if no authority
        wired. Reuses the audited `_read` for the owner-datum capture.
        """
        from .oob_channels import confirm_oob_leak

        if conf.kind != "hidden_field":
            return None
        if self.nonce_authority is None or self.seeker is None:            # A-0
            self.abstained.append((conf.resource, "oob-leak: no nonce authority — abstain"))
            return None
        accessor = self.by_identity.get(conf.accessor)
        owner = self.by_identity.get(owner_identity)
        if accessor is None or owner is None:
            self.abstained.append((conf.resource, "oob-leak: accessor/owner not provisioned"))
            return None

        # capture the OWNER's real discriminating datum for the hidden field (the thing
        # whose OOB appearance proves a cross-principal leak).
        own_resp = self.confirmer._read(read_request, owner)
        if own_resp is None or not (200 <= getattr(own_resp, "status", 0) < 300):
            self.abstained.append((conf.resource, "oob-leak: owner read-back failed/blocked"))
            return None
        own_val = _scalar_fields(getattr(own_resp, "body", None)).get(conf.declared)
        if own_val in _EMPTY:
            self.abstained.append((conf.resource, "oob-leak: owner has no real value for the field"))
            return None

        # mint + embed the attribution nonce, then fire the OOB-producing action.
        nonce = self.nonce_authority.mint(f"oob-leak {conf.declared} via {conf.resource}")
        self.seeker.register_planted(nonce)
        try:
            trigger(nonce)                                                 # attacker action
        except Exception:
            self.abstained.append((conf.resource, "oob-leak: trigger failed — abstain"))
            return None

        res = confirm_oob_leak(channel=channel, seeker=self.seeker, planted=nonce,
                               victim_datum=str(own_val), attempts=attempts, interval_s=0.0)
        if not res.confirmed:
            self.abstained.append((conf.resource, f"oob-leak: {res.reason}"))
            return None
        return BvAFinding(
            kind="second_order_oob_leak", accessor=conf.accessor, resource=conf.resource,
            field=conf.declared, owner=str(owner_identity),
            why=(f"attacker {conf.accessor} triggered an out-of-band artifact "
                 f"({res.channel}) — provably THIS test's (unique nonce) — that leaked "
                 f"{owner_identity}'s private '{conf.declared}' value; second-order "
                 f"cross-principal leak confirmed via {res.channel} channel (G1) with "
                 f"cryptographic attribution (G14)."))

    def confirm_action(self, conf, mutate_request) -> Optional[BvAFinding]:
        """Confirm a `hidden_action` confrontation (BFLA): the target broadcast the action
        `conf.declared` as NOT available to `conf.accessor` (the action link was offered to
        the owner but withheld from this non-owner), yet the act EXECUTES it.

        Safety (the zero-harm red line): the mutation goes through the audited
        `confirmer._read`, which runs `scope.check` first — so in dry_run / unarmed scope it
        is BLOCKED and this returns None (ABSTAIN). A finding only arises when the operator
        has armed destructive testing on an authorized target AND the act returns 2xx,
        proving the non-owner executed an action the broadcast declared forbidden.
        Guards: A-1 accessor not provisioned → abstain; A-2 scope blocked / read failed →
        abstain; A-3 the act was denied (401/403 — declaration honored) → abstain."""
        if conf.kind != "hidden_action":
            return None
        accessor = self.by_identity.get(conf.accessor)
        if accessor is None:                                        # A-1
            self.abstained.append((conf.resource, "accessor not provisioned"))
            return None
        # ZERO-HARM GATE: _read only checks host/path allow-lists, NOT the mutation policy.
        # The destructive-method / dry_run / allow_destructive decision lives in
        # scope.may_mutate — consult it explicitly and ABSTAIN unless the operator has
        # armed destructive testing. Without this, a DELETE would execute under dry_run.
        from .scope_guard import ScopeVerdict
        gate = self.confirmer.scope.may_mutate(mutate_request)
        if gate.verdict is ScopeVerdict.HALT:                       # A-2a (unarmed/dry_run)
            self.abstained.append((conf.resource,
                                   f"mutation gated by scope ({gate.reason}) — abstain"))
            return None
        resp = self.confirmer._read(mutate_request, accessor)       # scope.check host/path
        if resp is None:                                            # A-2b (blocked/fail)
            self.abstained.append((conf.resource, "mutation blocked by scope or read failed"))
            return None
        if not (200 <= getattr(resp, "status", 0) < 300):          # A-3 plain verb denied
            # GENERALIZE the vector (not the action): the same quoted action may be
            # deliverable via a standard verb-tunnel that the gate forgot to check. Try the
            # bounded set; each is scope-gated; a 2xx proves the gate checks the method but
            # not the override (verb-tunneling BFLA). The ACTION is still quoted from the
            # broadcast — only the delivery vector varies (RL1-safe confrontation).
            tun = self._try_verb_tunnels(conf, mutate_request, accessor)
            if tun is not None:
                return tun
            self.abstained.append((conf.resource,
                                   f"act denied ({getattr(resp,'status',0)}) — declaration honored"))
            return None
        return BvAFinding(
            kind="function_escalation", accessor=conf.accessor, resource=conf.resource,
            field=conf.declared, owner=str(conf.owner_hint),
            why=(f"target broadcast action '{conf.declared}' on {conf.resource} as "
                 f"withheld from non-owner {conf.accessor} (offered only to the owner), "
                 f"but the act EXECUTED it ({getattr(resp,'status',0)}) — broadcast-vs-act "
                 f"contradiction on the action channel (BFLA), confirmed live."))

    def confirm_action_conditional(self, conf, mutate_request, owner_identity,
                                   drift_marker, host="") -> Optional[BvAFinding]:
        """G2-integrated object-binding-drift confirmer (TOCTOU-of-authorization).

        Uses the ETag/If-Match oracle as a DETERMINISTIC instrument to detect that the
        object's version/binding changed between check and commit, then proves the
        effect landed cross-principal by an owner read-back.

        Flow:
          1. read the resource AS THE ATTACKER → capture a STRONG ETag (E-0).
          2. issue the mutation with `If-Match:<etag>` (E-1), scope-gated (zero-harm).
          3. interpret the status: 412 ⇒ VERSION_CHANGED = re-bind window FIRED (E-2/E-3,
             proxy-aware); anything else ⇒ abstain.
          4. read the resource AS THE OWNER; a finding requires `drift_marker` (the
             attacker-written value) to be present in the OWNER's view — the effect
             drifted onto the victim's object (E-4). Otherwise abstain (observation ≠ finding).

        Opt-in and additive: reuses the audited `confirmer._read` + `scope.may_mutate`
        (unarmed/dry_run ⇒ abstain). Legacy `confirm_action` is untouched.
        """
        from .models import HTTPRequest
        from .scope_guard import ScopeVerdict
        from .conditional_oracle import (parse_etag, build_if_match, interpret,
                                         proxy_suspected_from, Verdict)

        accessor = self.by_identity.get(conf.accessor)
        owner = self.by_identity.get(owner_identity)
        if accessor is None or owner is None:                        # A-1
            self.abstained.append((conf.resource, "drift: accessor/owner not provisioned"))
            return None

        # 1. capture the attacker-side ETag
        check = self.confirmer._read(HTTPRequest("GET", conf.resource, host=host), accessor)
        etag = parse_etag(getattr(check, "headers", None))
        if etag is None or etag.weak:                                # E-0
            self.abstained.append((conf.resource,
                "drift: no strong ETag validator on the object — abstain"))
            return None

        # 2. conditional mutation, zero-harm gated
        cond = build_if_match(mutate_request, etag)                  # E-1 (refuses weak)
        if cond is None:
            self.abstained.append((conf.resource, "drift: weak validator refused for If-Match — abstain"))
            return None
        if self.confirmer.scope.may_mutate(cond).verdict is ScopeVerdict.HALT:
            self.abstained.append((conf.resource, "drift: conditional mutation gated by scope — abstain"))
            return None
        commit = self.confirmer._read(cond, accessor)

        # 3. interpret (proxy-aware): only a genuine 412 counts as the window firing
        proxy = proxy_suspected_from(getattr(commit, "headers", None)) or \
                proxy_suspected_from(getattr(check, "headers", None))
        verdict = interpret(commit, proxy_suspected=proxy)
        if verdict is not Verdict.VERSION_CHANGED:                   # E-2/E-3
            self.abstained.append((conf.resource,
                f"drift: no confirmable re-bind window ({verdict.value}) — abstain"))
            return None

        # 4. cross-principal read-back: did the attacker's write drift onto the owner's object?
        owner_view = self.confirmer._read(HTTPRequest("GET", conf.resource, host=host), owner)
        marker = str(drift_marker).strip()
        blob = owner_view.body if owner_view is not None else None
        import json as _json
        present = bool(marker) and marker in (blob if isinstance(blob, str)
                                              else _json.dumps(blob, default=str, sort_keys=True)) \
                  if blob is not None else False
        if not present:                                             # E-4
            self.abstained.append((conf.resource,
                "drift: re-bind window fired but attacker's write did not land on the "
                "owner's object — abstain (observation ≠ finding)"))
            return None
        return BvAFinding(
            kind="authz_drift", accessor=conf.accessor, resource=conf.resource,
            field=conf.declared, owner=str(owner_identity),
            why=(f"object-binding authorization drift on {conf.resource}: the object's "
                 f"version changed between check and commit (412/If-Match, proxy-checked), "
                 f"and the attacker {conf.accessor}'s write ({drift_marker!r}) landed on "
                 f"{owner_identity}'s object — TOCTOU-of-authorization confirmed by "
                 f"deterministic oracle + cross-principal Δstate (G2)."))

    def confirm_authn_gap(self, resource, anon_accessor, owner_ref, owner,
                          read_request) -> Optional[BvAFinding]:
        """Confirm an AUTHN-gap: the anonymous principal received a 200 body for `resource`
        that DECLARES owner `owner_ref` (a private resource). Confirm by live Δstate — read
        the resource AS the declared owner; the body must carry that owner's real private
        datum (the owner_ref value matches), proving anon received owner-scoped private data
        rather than a coincidentally-public field.
        Guards: G-1 owner read-back failed/blocked → abstain; G-2 the owner's view does not
        actually declare owner_ref as its own → abstain (not the owner's private datum)."""
        own_resp = self.confirmer._read(read_request, owner)
        if own_resp is None or not (200 <= getattr(own_resp, "status", 0) < 300):
            self.abstained.append((resource, "authn-gap: owner read-back failed/blocked"))
            return None                                            # G-1
        own_vals = {str(v) for v in _scalar_fields(getattr(own_resp, "body", None)).values()}
        if str(owner_ref) not in own_vals:                         # G-2
            self.abstained.append((resource, "authn-gap: owner view does not confirm ownership"))
            return None
        return BvAFinding(
            kind="authn_gap", accessor=anon_accessor, resource=resource,
            field="<unauthenticated>", owner=str(owner_ref),
            why=(f"an ANONYMOUS principal received {resource} (200) whose body declares "
                 f"owner {owner_ref} — a private, owner-scoped resource served with no "
                 f"credential; confirmed the owner ({owner_ref}) is the real owner by live "
                 f"read-back. Authentication gap (private ⇒ must authenticate)."))

    # standard verb-tunneling vectors: a POST that smuggles the real method. Bounded,
    # well-known set — trying them delivers the SAME quoted action, never a new one.
    _VERB_TUNNELS = ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override")

    def _try_verb_tunnels(self, conf, mutate_request, accessor) -> Optional[BvAFinding]:
        """When the plain verb is denied, try standard verb-tunnels (POST + override
        header). Each is gated by scope.may_mutate (armed-only); a 2xx convicts. Returns a
        finding on the first vector that executes, else None (abstain)."""
        from .models import HTTPRequest
        from .scope_guard import ScopeVerdict
        real_verb = getattr(mutate_request, "method", "DELETE")
        path = getattr(mutate_request, "path", "")
        host = getattr(mutate_request, "host", "")
        for header in self._VERB_TUNNELS:
            tunneled = HTTPRequest("POST", path, host=host,
                                   headers={header: real_verb})
            if self.confirmer.scope.may_mutate(tunneled).verdict is ScopeVerdict.HALT:
                continue                                   # unarmed/dry_run ⇒ skip (zero-harm)
            resp = self.confirmer._read(tunneled, accessor)
            if resp is not None and 200 <= getattr(resp, "status", 0) < 300:
                return BvAFinding(
                    kind="function_escalation", accessor=conf.accessor,
                    resource=conf.resource, field=conf.declared, owner=str(conf.owner_hint),
                    why=(f"target broadcast action '{conf.declared}' on {conf.resource} as "
                         f"withheld from non-owner {conf.accessor}, and denied the PLAIN "
                         f"{real_verb}; but a verb-tunnel ({header}: {real_verb}) EXECUTED "
                         f"it ({getattr(resp,'status',0)}) — the function gate checks the "
                         f"method but not the override (verb-tunneling BFLA), confirmed live."))
        return None

    def confirm_mass_assignment(self, member_identity, self_path, field, privileged_value,
                                host="") -> Optional[BvAFinding]:
        """Confirm a mass-assignment (write-side BOPLA): the privilege-bound `field` is
        blindly bound from a member's request body. Propose PATCH {field: privileged_value}
        AS THE MEMBER, then read back AS THE MEMBER; if the privileged value PERSISTED
        (Δstate), the member escalated their own privilege.

        Zero-harm: the write is a mutation → gated by scope.may_mutate; HALT under dry_run /
        unarmed ⇒ abstain (propose-but-do-not-write). A finding only when armed AND the
        value sticks. Guards: M-1 member not provisioned; M-2 write gated ⇒ abstain;
        M-3 write/read failed ⇒ abstain; M-4 value did NOT stick ⇒ abstain (server ignored)."""
        from .models import HTTPRequest
        from .scope_guard import ScopeVerdict
        member = self.by_identity.get(member_identity)
        if member is None:                                          # M-1
            self.abstained.append((self_path, "mass-assign: member not provisioned"))
            return None
        patch = HTTPRequest("PATCH", self_path, host=host, body={field: privileged_value})
        if self.confirmer.scope.may_mutate(patch).verdict is ScopeVerdict.HALT:   # M-2
            self.abstained.append((self_path, f"mass-assign: write of '{field}' gated by scope — abstain"))
            return None
        wresp = self.confirmer._read(patch, member)
        if wresp is None:                                           # M-3
            self.abstained.append((self_path, "mass-assign: write blocked/failed"))
            return None
        readback = self.confirmer._read(HTTPRequest("GET", self_path, host=host), member)
        if readback is None or not isinstance(getattr(readback, "body", None), dict):
            self.abstained.append((self_path, "mass-assign: read-back failed"))
            return None
        got = readback.body.get(field)
        if str(got).strip().lower() != str(privileged_value).strip().lower():        # M-4
            self.abstained.append((self_path, f"mass-assign: '{field}' did not stick (got {got!r}) — abstain"))
            return None
        return BvAFinding(
            kind="mass_assignment", accessor=member_identity, resource=self_path,
            field=field, owner=str(privileged_value),
            why=(f"member {member_identity} wrote the privilege-bound field '{field}'="
                 f"{privileged_value!r} via {self_path} and it PERSISTED on read-back — the "
                 f"target binds '{field}' from the request body without an authority check "
                 f"(mass-assignment / write-side BOPLA), confirmed by live Δstate."))

    def confirm_mass_assignment_attributed(self, member_identity, self_path, field,
                                           privileged_value, companion_field, host=""):
        """G14-attributed variant of confirm_mass_assignment.

        Same live Δstate proof, but ALSO stamps a unique nonce into a free-text
        `companion_field` in the SAME write. A finding now requires BOTH:
          * the privileged semantic value stuck (write-side BOPLA), AND
          * our exact nonce present on read-back (proves THIS test's write landed —
            not a pre-existing 'admin', not a shared default, not another tester).
        This removes the residual attribution ambiguity of the string-equality M-4.

        Opt-in: requires a wired nonce_authority + seeker; otherwise abstains (never
        silently downgrades to the weaker check). Zero-harm mutation gate unchanged.
        """
        from .models import HTTPRequest
        from .scope_guard import ScopeVerdict
        from .nonce_provenance import attributed_stick_check, choose_strategy, PlantStrategy

        if self.nonce_authority is None or self.seeker is None:            # A-0
            self.abstained.append((self_path, "attributed mass-assign: no nonce authority — abstain"))
            return None
        member = self.by_identity.get(member_identity)
        if member is None:                                                # M-1
            self.abstained.append((self_path, "attributed mass-assign: member not provisioned"))
            return None
        # The companion must be a genuine free-text field (so the nonce is accepted).
        strat, _ = choose_strategy(field, object_fields={field: privileged_value,
                                                         companion_field: ""})
        if strat is not PlantStrategy.HYBRID_COMPANION:                   # C-1
            self.abstained.append((self_path,
                f"attributed mass-assign: '{companion_field}' is not a usable free-text "
                f"companion — abstain (never plant a nonce into a constrained field)"))
            return None

        nonce = self.nonce_authority.mint(f"mass-assign {field} via {self_path}")
        # HYBRID plant: privileged semantic value + nonce stamped into the free-text sibling.
        body = {field: privileged_value, companion_field: nonce.as_text()}
        patch = HTTPRequest("PATCH", self_path, host=host, body=body)
        if self.confirmer.scope.may_mutate(patch).verdict is ScopeVerdict.HALT:   # M-2
            self.abstained.append((self_path, "attributed mass-assign: write gated by scope — abstain"))
            return None
        wresp = self.confirmer._read(patch, member)
        if wresp is None:                                                 # M-3
            self.abstained.append((self_path, "attributed mass-assign: write blocked/failed"))
            return None
        readback = self.confirmer._read(HTTPRequest("GET", self_path, host=host), member)
        if readback is None or not isinstance(getattr(readback, "body", None), dict):
            self.abstained.append((self_path, "attributed mass-assign: read-back failed"))
            return None

        got = readback.body.get(field)
        semantic_stuck = str(got).strip().lower() == str(privileged_value).strip().lower()
        self.seeker.register_planted(nonce)
        res = attributed_stick_check(seeker=self.seeker, planted=nonce,
                                     readback_body=readback.body,
                                     cross_principal_ok=semantic_stuck)
        if not res.attributed:                                            # M-4 (attributed)
            self.abstained.append((self_path, f"attributed mass-assign: {res.reason}"))
            return None
        return BvAFinding(
            kind="mass_assignment", accessor=member_identity, resource=self_path,
            field=field, owner=str(privileged_value),
            why=(f"member {member_identity} wrote the privilege-bound field '{field}'="
                 f"{privileged_value!r} via {self_path}; the write is provably THIS test's "
                 f"(unique nonce stamped in '{companion_field}' present on read-back) AND the "
                 f"privileged value PERSISTED — mass-assignment / write-side BOPLA, confirmed "
                 f"by live Δstate with cryptographic attribution (G14)."))
