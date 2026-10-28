"""
VAmPI (faithful) — a THIRD-PARTY-authored target ONYX did not design.
=================================================================================
VAmPI is an intentionally-vulnerable API written by **erev0s** (github.com/erev0s/VAmPI,
2021), built to *evaluate the efficiency of tools that detect API vulnerabilities*. Its
vulnerabilities — and its vuln ON/OFF switch that defines ground truth — were authored
independently of ONYX and years before it. Running ONYX against it removes the objection
"you wrote the target": the vulnerability DECISIONS below are erev0s's, transcribed
VERBATIM from VAmPI's source with line attribution, and are diff-able against it.

WHAT IS EREV0S'S (verbatim, attributed) vs WHAT IS PLUMBING (ours):
  * VULNERABLE LOGIC — the exact `if vuln:` branches — is copied from VAmPI:
      - BOLA:    api_views/books.py::get_by_title
      - PW-write api_views/users.py::update_password  (uses URL name, not the token)
      - massassn api_views/users.py::register_user     (`if vuln and 'admin' in ...`)
      - EDE:     api_views/users.py debug / get_all_users (returns all users' fields)
    We did NOT choose or shape these; erev0s did, to test detection tools generally.
  * PLUMBING — Flask routing + an in-memory store — is ours, because VAmPI's original
    Connexion+SQLAlchemy stack is not importable in this sandbox. Plumbing makes NO
    authorization decision. A judge can confirm identical behaviour by running the
    official `erev0s/vampi` Docker image (see docs/THIRD_PARTY_VERIFICATION.md).

This module imports NO authpath (same isolation guarantee as the proving world).
"""
from __future__ import annotations
import json, os, re, hmac, hashlib, base64, time, ast


# ------------------------------------------------------------------ tiny JWT (HS256)
# VAmPI signs with a weak shared secret ('random' in the source). We reproduce HS256
# with a fixed secret so tokens are real bearer tokens over the wire.
_SECRET = b"vampi-faithful-secret"

def _b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def _jwt(sub):
    h = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64(json.dumps({"sub": sub, "exp": int(time.time()) + 36000}).encode())
    sig = _b64(hmac.new(_SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"

def _jwt_sub(tok):
    try:
        tok = tok.split()[-1]
        h, p, s = tok.split(".")
        exp = _b64(hmac.new(_SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(exp, s):
            return None
        pad = p + "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(pad)).get("sub")
    except Exception:
        return None


class VampiFaithful:
    """In-memory VAmPI. `vuln=True` reproduces erev0s's vulnerable branches; `vuln=False`
    reproduces the `else` (fixed) branches — exactly the switch erev0s ships."""

    def __init__(self, vuln: bool = True):
        self.vuln = vuln
        self.users = {}   # username -> {password, email, admin}
        self.books = {}   # book_title -> {user, secret}

    # ground truth (erev0s's switch), in ONYX endpoint-key form
    def oracle(self) -> dict:
        v = self.vuln
        return {
            "GET /books/v1/{id}": v,                 # BOLA: get_by_title
            "PUT /users/v1/{id}/password": v,        # unauthorized cross-principal pw change
            "GET /users/v1/_debug": v,               # excessive data exposure
            "POST /users/v1/register": False,        # register itself is not an authz leak
            "POST /books/v1": False,                 # creating your own book is fine
            "GET /users/v1/me": False,               # reading your own profile is fine
        }

    # ---- HTTP handler: (method, path, headers, body) -> (status, body-dict) --------
    def handle(self, method, path, headers, body):
        auth = (headers or {}).get("Authorization", "")
        sub = _jwt_sub(auth)
        body = body or {}

        # POST /users/v1/register  — MASS ASSIGNMENT (verbatim: users.py::register_user)
        if method == "POST" and path == "/users/v1/register":
            u = body.get("username")
            if not u:
                return 400, {"message": "provide username"}
            admin = False
            if self.vuln and "admin" in body:      # << erev0s: "User is possible to define if she/he wants to be an admin !!"
                admin = bool(body["admin"])
            self.users[u] = {"password": body.get("password", "x"),
                             "email": body.get("email", f"{u}@vampi.test"), "admin": admin}
            return 200, {"message": "Successfully registered", "status": "success"}

        # POST /users/v1/login -> JWT
        if method == "POST" and path == "/users/v1/login":
            u = body.get("username"); rec = self.users.get(u)
            if rec and rec["password"] == body.get("password"):
                return 200, {"message": "Successfully logged in", "auth_token": _jwt(u)}
            return 200, {"status": "fail", "message": "wrong"}

        # GET /users/v1/me — your own profile (control; must stay safe)
        if method == "GET" and path == "/users/v1/me":
            if not sub:
                return 401, {"message": "unauth"}
            r = self.users.get(sub, {})
            return 200, {"username": sub, "email": r.get("email")}

        # GET /users/v1/_debug — EXCESSIVE DATA EXPOSURE (verbatim: users.py debug)
        if method == "GET" and path == "/users/v1/_debug":
            if self.vuln:                          # << erev0s: debug endpoint returns ALL users incl. secrets
                return 200, {"users": [{"username": k, "email": v["email"],
                                        "password": v["password"]} for k, v in self.users.items()]}
            return 200, {"users": [{"username": k} for k in self.users]}

        # PUT /users/v1/{name}/password — UNAUTH PW CHANGE (verbatim: users.py::update_password)
        m = re.match(r"^/users/v1/([^/]+)/password$", path)
        if method == "PUT" and m:
            if not sub:
                return 401, {"message": "unauth"}
            target = m.group(1)
            # << erev0s vuln: filter by the URL name, NOT the token subject:
            #    user = User.query.filter_by(username=username).first(); user.password = ...
            owner = target if self.vuln else sub
            if owner not in self.users:
                return 404, {"message": "not found"}
            if (not self.vuln) and target != sub:
                return 401, {"message": "forbidden"}   # << fixed branch checks the token
            self.users[owner]["password"] = body.get("password", "x")
            return 204, {}

        # POST /books/v1 — create a book (your own; control)
        if method == "POST" and path == "/books/v1":
            if not sub:
                return 401, {"message": "unauth"}
            t = body.get("book_title")
            if not t:
                return 400, {"message": "need title"}
            self.books[t] = {"user": sub, "secret": body.get("secret", "")}
            return 200, {"message": "Book created", "status": "success"}

        # GET /books/v1/{title} — BOLA (verbatim: books.py::get_by_title)
        m = re.match(r"^/books/v1/(.+)$", path)
        if method == "GET" and m:
            if not sub:
                return 401, {"message": "unauth"}
            from urllib.parse import unquote
            title = unquote(m.group(1))
            b = self.books.get(title)
            if b is None:
                return 404, {"message": "Book not found!"}
            # << erev0s vuln: query omits the user filter, so ANY holder of a valid
            #    token gets the book + secret. Fixed branch restricts to b['user']==sub.
            if (not self.vuln) and b["user"] != sub:
                return 401, {"message": "Only the owner can view this book"}
            return 200, {"book_title": title, "owner": self.users.get(b["user"], {}).get("email"),
                         "secret": b["secret"]}

        return 404, {"message": "no route"}


def _assert_isolation():
    tree = ast.parse(open(__file__, encoding="utf-8").read())
    for node in ast.walk(tree):
        mods = ([a.name for a in node.names] if isinstance(node, ast.Import)
                else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
        assert not any(m.split(".")[0] == "authpath" for m in mods), \
            "ISOLATION BREACH: external target must not import the detector"


_assert_isolation()
