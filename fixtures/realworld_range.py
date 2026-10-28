"""
fixtures.realworld_range — a BLIND, architecture-faithful adversarial range (VERITAS).

The calibration demo PLANTS bugs as flags whose location the author knows, so ONYX
finds them trivially — that cannot predict the real world. This range implements
authorization the way a real backend does — a TRANSITIVE OWNERSHIP TREE, per-operation
checks, RBAC roles, and several real "doors" to the same objects — and the
vulnerabilities EMERGE from realistic architectural mistakes documented in real
disclosures. ONYX gets ONLY what a real engagement gives it (observed traffic + a
contract reconstructed from that traffic). A separate hidden ORACLE scores the run.

EMERGENT BUGS (each maps to a documented real mechanism; none is a flag):
  B1  per-door authz inconsistency: the org canonical (GraphQL) FORBIDS `webhook_secret`,
      but a secondary REST door leaks it — the HackerOne $1,500 field-level GraphQL leak.
  B2  list over-projection (BOPLA / API3:2023): the projects LIST leaks `tax_id` that the
      canonical project detail withholds.
  B3  ownership anomaly from a re-homed parent (RL18 / doc 24 "ownership anomalies from
      schema changes"): resource r3's access still follows its OLD org while its project
      now belongs to another org the principal is forbidden — child didn't follow parent.
  B4  deploy drift (BOPLA over time / RL16): the resource serializer regresses and a later
      read exposes `ssn` that the earlier read filtered.

DECOYS (legitimate by design — must NOT fire):
  D1 lean cards list (detail richer by design);  D2 public status token (public by design).
"""
from __future__ import annotations

from authpath.models import HTTPRequest, HTTPResponse, Principal


class RealWorldRange:
    host = "range.local"

    _PROJECT_ORG = {"p1": "o1", "p2": "o1", "p9": "o9"}
    # r3's project is p9 (re-homed to org o9) — but the resource read below checks the
    # OLD org o1 (the architectural mistake), so U keeps access to the child.
    _RESOURCE_CURRENT_PROJECT = {"r1": "p1", "r2": "p2", "r3": "p9"}
    _RESOURCE_LEGACY_ORG = {"r3": "o1"}          # the stale org the access check still uses
    _ROLES = {"U": {"o1": "member"}, "V": {"o9": "admin"}}

    def __init__(self):
        self._reads = {}

    def _role_in(self, pid, org):
        return self._ROLES.get(pid, {}).get(org)

    def _may_see_org(self, pid, org):
        return self._role_in(pid, org) is not None

    def send(self, req, principal):
        a = principal.pid
        m, p = req.method.upper(), req.path
        q = req.query or {}

        # GraphQL org canonical — FORBIDS webhook_secret (intent-declared canonical) #
        if m == "POST" and p.endswith("/graphql"):
            body = req.body if isinstance(req.body, dict) else {}
            query = str(body.get("query") or "")
            variables = body.get("variables") or {}
            org = str(variables.get("org") or variables.get("id") or "o1")
            if not self._may_see_org(a, org):
                return HTTPResponse(200, {"data": None, "errors": [
                    {"message": "forbidden", "extensions": {"code": "FORBIDDEN"}}]})
            # U1 (declared-unreachable): a DIFFERENT operation name returning the same
            # data leaks the secret the primary withholds — the literal $1,500 case.
            # ONYX unifies identities by (type,id) from the root field, so `orgWebhooks`
            # is NOT unified with `org`; catching this needs an operation-equivalence
            # declaration ONYX does not synthesise. The range exposes it to PROVE the miss.
            if "orgWebhooks" in query:
                return HTTPResponse(200, {"data": {"orgWebhooks": [
                    {"id": "wh1", "secret": "whsec_live_9f3c2a"}]}})
            return HTTPResponse(200, {"data": {"org": {"id": org}},
                "errors": [{"message": "Not authorized to access Org.webhook_secret",
                            "path": ["org", "webhook_secret"],
                            "extensions": {"code": "FORBIDDEN"}}]})

        # REST orgs LIST — B1: secondary door leaks webhook_secret the GraphQL forbids #
        if m == "GET" and p == "/api/orgs":
            org = q.get("org", "o1")
            if not self._may_see_org(a, org):
                return HTTPResponse(403, {"error": "forbidden"})
            return HTTPResponse(200, {"orgs": [
                {"id": org, "name": f"Org {org}", "webhook_secret": "whsec_live_9f3c2a"}]})

        # REST project detail (canonical) — tax_id FILTERED                          #
        if m == "GET" and p.startswith("/api/projects/") and p.count("/") == 3:
            pid = p.rsplit("/", 1)[-1]
            org = self._PROJECT_ORG.get(pid)
            if org is None:
                return HTTPResponse(404, {"error": "not_found"})
            if not self._may_see_org(a, org):
                return HTTPResponse(403, {"error": "forbidden"})
            return HTTPResponse(200, {"id": pid, "name": f"Project {pid}", "org": org})

        # REST projects LIST — B2: over-projects tax_id the detail withholds         #
        if m == "GET" and p == "/api/projects":
            org = q.get("org", "o1")
            if not self._may_see_org(a, org):
                return HTTPResponse(403, {"error": "forbidden"})
            rows = [{"id": pid, "name": f"Project {pid}", "tax_id": f"TX-{pid}-88421"}
                    for pid, porg in self._PROJECT_ORG.items() if porg == org]
            return HTTPResponse(200, {"projects": rows, "next": None})

        # REST resource detail — B3 (stale-org check) + B4 (deploy drift on ssn)     #
        if m == "GET" and p.startswith("/api/resources/") and p.count("/") == 3:
            rid = p.rsplit("/", 1)[-1]
            if rid not in self._RESOURCE_CURRENT_PROJECT:
                return HTTPResponse(404, {"error": "not_found"})
            # the access check uses the LEGACY org for r3 (the B3 mistake), else current
            check_org = self._RESOURCE_LEGACY_ORG.get(
                rid, self._PROJECT_ORG.get(self._RESOURCE_CURRENT_PROJECT[rid]))
            if not self._may_see_org(a, check_org):
                return HTTPResponse(403, {"error": "forbidden"})
            cur_proj = self._RESOURCE_CURRENT_PROJECT[rid]
            self._reads[rid] = self._reads.get(rid, 0) + 1
            # B4 deploy drift is scoped to r1 only; r3's sole defect is the ownership
            # anomaly (B3), so its detection must come from RL18, not a coincidental leak.
            leaked = (rid == "r1" and self._reads[rid] >= 2)
            return HTTPResponse(200, {"id": rid, "project": cur_proj,
                                      "title": f"Resource {rid}",
                                      "ssn": ("404-11-9087" if leaked else None)})

        # DECOYS                                                                      #
        if m == "GET" and p == "/api/cards":
            return HTTPResponse(200, {"cards": [{"id": "c1", "last4": "1234"}]})
        if m == "GET" and p.startswith("/api/cards/") and p.count("/") == 3:
            return HTTPResponse(200, {"id": p.rsplit("/", 1)[-1], "last4": "1234",
                                      "holder_name": "U", "expiry": "12/29"})
        if m == "GET" and p == "/api/status":
            return HTTPResponse(200, {"id": "status", "public": True,
                                      "api_token": "pk_public_demo"})

        return HTTPResponse(404, {"error": "no_route"})


# Hidden ground truth — used ONLY by the scorer, NEVER passed to the engine.
ORACLE = [
    ("B1", "org:o1",      "webhook_secret", "per-door authz inconsistency (HackerOne $1,500 GraphQL field-level leak)"),
    ("B2", "project:p1",  "tax_id",         "list over-projection vs canonical detail (BOPLA / API3:2023)"),
    ("B2", "project:p2",  "tax_id",         "list over-projection vs canonical detail (BOPLA / API3:2023)"),
    ("B3", "resource:r3", None,             "ownership anomaly from re-homed parent (RL18 / ownership inheritance, doc 24)"),
    ("B4", "resource:r1", "ssn",            "deploy-drift field exposure (BOPLA over time / RL16)"),
]
DECOYS = ["cards (lean list — by-design under-fetch)", "status (public token — public by design)"]

# DECLARED BLIND SPOTS — real bug classes ONYX structurally CANNOT reach today. The
# harness PROBES U1 to prove the miss empirically (not assume it); U2 is architectural
# (ONYX is read-only by default — AEGIS gate 2). Reporting these is what makes a 5/5 on
# the reachable set trustworthy instead of false confidence (VERITAS V5/V6).
UNREACHABLE = [
    ("U1", "org:o1", "secret via a DIFFERENT operation name (orgWebhooks) returning the same data",
     "needs an operation-equivalence declaration; ONYX unifies by (type,id) from the root field"),
    ("U2", "—", "BFLA write-privilege escalation (a member succeeds at an admin-only mutation)",
     "needs active multi-principal provisioning + write execution (AEGIS gate 2) — deliberately not built"),
]
