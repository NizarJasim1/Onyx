"""
VERITAS blind range for the OWNERSHIP NERVE (FORGE step 4b).

A target that PLANTS owner-field BOLAs and ADVERSARIAL decoys. The driver never sees
the oracle; it only feeds self/owned/access exchanges to the NerveBridge and reports
findings. The scorer (which alone holds the oracle) checks: every real BOLA caught,
ZERO findings on the decoys — the honest "catches real bugs, never false-positives on
the unseen" test.

PLANTED (hidden):
  B5  /api/notes/{id} — authentication enforced (anon→403) but NO ownership check:
      any authenticated user reads any user's private note (classic BOLA / API1:2023).
ADVERSARIAL DECOYS (must NOT be flagged):
  D3  /api/files/{id} — owned by another user but the body DECLARES shared_with=[me]
      (legitimate share — grant must suppress the candidate).
  D4  /api/bulletins/{id} — public:true, served to anon too (public by design).
  D5  /api/accounts/{id} — owned by another, but the non-owner gets a REDACTED view
      (no substantive private field reproduced — must abstain).
  D6  self-owned note — the accessor reads their OWN note (correct, never a finding).
"""
from authpath.models import HTTPResponse

# ownership ground truth (the scorer's secret; the target uses it to answer)
_NOTE_OWNER = {"n1": "u-1", "n2": "u-2", "n3": "u-3"}
_PROFILE_OWNER = {"ac2": "u-2"}
_SHARED_OWNER = {"f1": "u-2"}
_IDENT = {"A": "u-1", "B": "u-2", "C": "u-3"}


class NerveBlindRange:
    host = "nerve.local"

    def send(self, req, principal):
        p = req.path
        a = principal.pid
        authed = bool(principal.auth) and not principal.is_anonymous

        if p == "/api/me":
            if not authed:
                return HTTPResponse(401, {"error": "login_required"})
            return HTTPResponse(200, {"id": _IDENT.get(a, "?"), "email": f"{a}@nerve.local"})

        # B5: notes — auth gate present, ownership check ABSENT (the bug)
        if p.startswith("/api/notes/") and p.count("/") == 3:
            nid = p.rsplit("/", 1)[-1]
            owner = _NOTE_OWNER.get(nid)
            if owner is None:
                return HTTPResponse(404, {"error": "nf"})
            if not authed:
                return HTTPResponse(403, {"error": "forbidden"})        # anon denied
            return HTTPResponse(200, {"id": nid, "owner_id": owner,
                                      "body": f"private note of {owner}",
                                      "pin": f"PIN-{owner}-7788"})

        # D3: shared — legitimately shared with u-1
        if p.startswith("/api/files/") and p.count("/") == 3:
            sid = p.rsplit("/", 1)[-1]
            owner = _SHARED_OWNER.get(sid)
            if owner is None or not authed:
                return HTTPResponse(403 if authed else 401, {"error": "no"})
            return HTTPResponse(200, {"id": sid, "owner_id": owner,
                                      "shared_with": ["u-1"], "body": "shared doc",
                                      "pin": f"PIN-{owner}-shared"})

        # D4: public — served to anyone, including anon
        if p.startswith("/api/bulletins/") and p.count("/") == 3:
            return HTTPResponse(200, {"id": p.rsplit("/", 1)[-1], "owner_id": "u-2",
                                      "public": True, "body": "public bulletin"})

        # D5: profile — owned by another, but non-owner gets a REDACTED view
        if p.startswith("/api/accounts/") and p.count("/") == 3:
            prid = p.rsplit("/", 1)[-1]
            owner = _PROFILE_OWNER.get(prid)
            if owner is None or not authed:
                return HTTPResponse(403 if authed else 401, {"error": "no"})
            if a != "B":                       # non-owner: redacted
                return HTTPResponse(200, {"id": prid, "owner_id": owner, "pin": "REDACTED"})
            return HTTPResponse(200, {"id": prid, "owner_id": owner, "pin": "PIN-u-2-real"})

        return HTTPResponse(404, {"error": "no_route"})


# Hidden oracle — used ONLY by the scorer, NEVER by the driver.
# A real BOLA finding is the accessor (u-1) reading a note owned by someone else.
ORACLE_FINDINGS = {("note:n2", "u-1"), ("note:n3", "u-1")}
ORACLE_MUST_NOT_FLAG = {"files:f1", "bulletins:b1", "accounts:ac2", "note:n1"}
