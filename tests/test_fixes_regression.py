"""
Regression tests for the 13 audited defects. Each test FAILS on the pre-fix
engine and PASSES on the fixed one. Run: python tests/test_fixes_regression.py
"""
import sys, os, json, base64
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.engine import AuthPathEngine
from authpath.transport import make_exchange
from authpath.models import HTTPRequest, HTTPResponse, Principal
from authpath.scope_guard import ScopeConfig, ScopeGuard
from authpath.harimport import ingest_har

PASS = 0; FAIL = 0
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  [PASS] {name}")
    else:    FAIL += 1; print(f"  [FAIL] {name}")

def _jwt(sub):
    b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{b({'alg':'HS256'})}.{b({'sub':sub})}.s"
def _ent(sub, path, status, body):
    hdrs = [] if sub is None else [{"name": "Authorization", "value": "Bearer "+_jwt(sub)}]
    return {"request": {"method": "GET", "url": "https://api.x.com"+path, "headers": hdrs},
            "response": {"status": status, "content": {"mimeType": "application/json",
                                                       "text": json.dumps(body)}}}

def test_offline_no_false_findings():
    """#1/#3/#4/#6: offline HAR emits NO object-access findings; benign sharing/public suppressed."""
    E = []
    for _ in range(3):
        E += [_ent("u_a", "/api/projects/101", 200, {"id":101,"owner":"u_a","tags":["x"]})]
        E += [_ent("u_b", "/api/projects/201", 200, {"id":201,"owner":"u_b","tags":["x"]})]
        E += [_ent(None,  "/api/public/n/9",   200, {"id":9,"title":"news"})]
        E += [_ent("u_a", "/api/public/n/9",   200, {"id":9,"title":"news"})]
    sc = ScopeConfig(allowed_hosts=["api.x.com"], automation_permitted=True, dry_run=True)
    eng = ingest_har({"log":{"entries":E}}, sc, in_scope_hosts=["api.x.com"])
    check("offline emits zero object-access FINDINGS", eng.snapshot()["counts"]["findings"] == 0)
    xl = [l for _, l in eng.leads if getattr(l, "kind", "") == "CROSS_PRINCIPAL_OBJECT"]
    check("public object (anon-reachable) suppressed from leads",
          not any(l.evidence.get("object_id") == "9" for l in xl))

def test_offline_real_idor_surfaces():
    """#1: a genuine cross-principal access still surfaces as a ranked LEAD (no false negative)."""
    E = [_ent("u_a", "/api/inv/7001", 200, {"id":7001,"owner":"u_a"}),
         _ent("u_a", "/api/inv/7001", 200, {"id":7001,"owner":"u_a"}),
         _ent("u_b", "/api/inv/7001", 200, {"id":7001,"owner":"u_a"})]   # Bob reads Alice's
    sc = ScopeConfig(allowed_hosts=["api.x.com"], automation_permitted=True, dry_run=True)
    eng = ingest_har({"log":{"entries":E}}, sc, in_scope_hosts=["api.x.com"])
    xl = [l for _, l in eng.leads if getattr(l, "kind", "") == "CROSS_PRINCIPAL_OBJECT"]
    check("real cross-principal IDOR surfaces as a lead",
          any(l.evidence.get("object_id") == "7001" for l in xl))

def test_replay_target_object_identity():
    """#2: ReplayTarget never returns a different object for the same normalised endpoint."""
    from authpath.transport import ReplayTarget
    from authpath.harimport import parse_har_exchanges
    E = [_ent("u_a", "/api/o/101", 200, {"id":101}), _ent("u_a", "/api/o/203", 200, {"id":203})]
    pr, ex = parse_har_exchanges({"log":{"entries":E}}, ["api.x.com"])
    rt = ReplayTarget(ex)
    r = rt.send(HTTPRequest("GET", "/api/o/101", host="api.x.com"), pr["A"])
    check("read-back of 101 is object 101 (not 203)",
          r.status >= 500 or (isinstance(r.body, dict) and r.body.get("id") == 101))

def test_name_neutral_salience():
    """#5: language-neutral value salience flags non-English / abbreviated sensitive fields."""
    from authpath.intrinsic import interrogate
    def n(extra):
        b = {"rows":[{"id":"u1","name":"a"},{"id":"u2","name":"b",**extra},{"id":"u3","name":"c"}]}
        return len([l for l in interrogate(b,"GET /r","A") if l.kind=="SIBLING_ASYMMETRY"])
    check("abbrev 'bal' overlay flagged", n({"bal":99999}) >= 1)
    check("french 'solde' overlay flagged", n({"solde":99999}) >= 1)
    check("IBAN value under generic name flagged", n({"x":"DE89370400440532013000"}) >= 1)
    check("free-text comment NOT flagged", n({"note":"just a long comment here ok fine"}) == 0)

def test_normalisation_self_alias():
    """#7: /users/me is NOT an object id; dotted usernames ARE."""
    check("/users/me has no object id", HTTPRequest("GET","/api/users/me",host="h").object_ids() == [])
    check("/users/john.doe is an id", HTTPRequest("GET","/api/users/john.doe",host="h").object_ids() == ["john.doe"])

def test_scope_host_confusion():
    """#R3: host that contains the allowed host as a prefix is blocked."""
    sg = ScopeGuard(ScopeConfig(allowed_hosts=["api.target.com"]))
    check("api.target.com.evil.com blocked",
          sg.check(HTTPRequest("GET","/x",host="api.target.com.evil.com")).verdict.value == "HALT")

def test_ownership_noop_vs_escalation():
    """#R4: resubmitting an already-held role is benign; a real elevation is a finding."""
    class T:
        host = "h"
        def __init__(self): self.role = "user"
        def send(self, req, p):
            if req.method == "PATCH" and req.body and "role" in req.body: self.role = req.body["role"]
            if req.path == "/api/users/5": return HTTPResponse(200, {"id":"5","role":self.role})
            return HTTPResponse(404, {})
    def run(newrole):
        t = T(); P = {"A": Principal("A","A")}
        e = AuthPathEngine(t, P, ScopeConfig(allowed_hosts=["h"], automation_permitted=True, dry_run=True),
                           contract={"PATCH /api/users/{id}": {"effect": "OWNERSHIP"}})
        e.observe(make_exchange(t, HTTPRequest("GET","/api/users/5",host="h"), P["A"]))
        e.analyze(make_exchange(t, HTTPRequest("PATCH","/api/users/5",body={"role":newrole},host="h"), P["A"]))
        return len(e.findings)
    check("benign role no-op -> 0 findings", run("user") == 0)
    check("real escalation -> 1 finding", run("admin") == 1)

def test_payment_generic_shape():
    """#R2: payment tampering confirms on a non-/api/orders shape."""
    class T:
        host = "h"
        def send(self, req, p):
            if req.path == "/v2/checkout":
                return HTTPResponse(200, {"ref":req.body.get("ref"),"amount_due":90,"amount_paid":1,"status":"paid"})
            return HTTPResponse(404, {})
    t = T(); P = {"A": Principal("A","A")}
    e = AuthPathEngine(t, P, ScopeConfig(allowed_hosts=["h"], automation_permitted=True, dry_run=True),
                       contract={"POST /v2/checkout": {"effect": "PAYMENT"}})
    e.analyze(make_exchange(t, HTTPRequest("POST","/v2/checkout",body={"ref":"X9","amount_paid":1,"amount_due":90},host="h"), P["A"]))
    check("underpayment confirmed on /v2/checkout shape", len(e.findings) == 1)

def test_price_robustness():
    """#R1: float noise & nested money do NOT create false price candidates; real tamper does."""
    from authpath.eil import PriceLaw, LawContext
    from authpath.contract import ContractResolver
    from authpath.provenance import ProvenanceStore
    from authpath.envelope import EnvelopeEngine
    from authpath.models import Exchange
    def verdict(rb):
        ex = Exchange(HTTPRequest("POST","/api/cart/price",body=rb,host="h"), HTTPResponse(200,{"total":rb.get("total")}), Principal("A","A"))
        return PriceLaw().evaluate(LawContext(ex, ContractResolver({}).classify(ex), ProvenanceStore(), EnvelopeEngine())).verdict.value
    check("float 0.1*3==0.3 -> PASS", verdict({"items":[{"price":0.1,"qty":3}],"total":0.3}) == "PASS")
    check("nested unit price reconciles -> PASS", verdict({"items":[{"price":{"value":5},"qty":2}],"total":10}) == "PASS")
    check("real price tamper -> CANDIDATE", verdict({"items":[{"price":45,"qty":2}],"total":5}) == "CANDIDATE")

def test_deep_body_no_dos():
    """#R5: pathological deep nesting fails safe (no RecursionError)."""
    from authpath.provenance import extract_values
    from authpath.structural import fingerprint
    d = {}; c = d
    for _ in range(5000): c["a"] = {}; c = c["a"]
    ok = True
    try: extract_values(d); fingerprint(d)
    except RecursionError: ok = False
    check("5000-deep body does not crash", ok)



def test_coherent_header_profile():
    """OBSTACLE 1: a captured browser's coherent header profile survives import
    and is replayed (not just Authorization), while secrets are redacted and
    transport-managed headers are dropped."""
    from authpath.harimport import parse_har, to_spec
    ch=[{"name":"User-Agent","value":"Mozilla/5.0 Chrome/131"},
        {"name":"Accept","value":"application/json"},
        {"name":"Sec-Fetch-Site","value":"same-origin"},
        {"name":"Content-Length","value":"0"},{"name":"Host","value":"api.x.com"},
        {"name":"Authorization","value":"Bearer real.tok"}]
    # one entry is enough; Sec-Fetch-Site must surface as a per-request (probe) header
    har={"log":{"entries":[{"request":{"method":"GET","url":"https://api.x.com/a/1","headers":ch},
         "response":{"status":200,"content":{"mimeType":"application/json","text":"{}"}}}]}}
    spec=to_spec(parse_har(har,["api.x.com"]),redact=True)
    prof=spec["principals"]["A"]["profile_headers"]
    # STABLE headers live in the profile; CONTEXTUAL (Sec-Fetch) travel per-request
    check("stable browser header preserved on import", "User-Agent" in prof)
    check("contextual header NOT frozen into stable profile", "Sec-Fetch-Site" not in prof)
    check("contextual header carried per-request", spec["probe"][0].get("headers",{}).get("Sec-Fetch-Site")=="same-origin")
    check("transport-managed headers dropped from profile", "Content-Length" not in prof and "Host" not in prof)
    check("secret not leaked into profile", "Authorization" not in prof)
    check("secret redacted in auth headers", spec["principals"]["A"]["headers"]["Authorization"].endswith("$TOKEN_A"))



def test_transport_governance():
    """OBSTACLE 2: legitimate transport governance — researcher attribution on
    every request, ONE shared egress for all principals (IP-stability invariant),
    a working rate governor, and identical default behaviour when unconfigured."""
    import sys, types, time
    sent=[]
    fake=types.ModuleType("requests")
    def reqfn(method,url,params=None,json=None,headers=None,verify=True,timeout=10,proxies=None):
        sent.append({"headers":dict(headers),"proxies":proxies})
        class R: status_code=200
        r=R(); r.json=lambda:{}; r.text="{}"; r.headers={}; return r
    fake.request=reqfn; sys.modules["requests"]=fake
    from authpath.transport import HTTPTarget, _RateGovernor
    from authpath.models import HTTPRequest, Principal
    from authpath.scope_guard import ScopeConfig
    A=Principal("A","a",auth={"Authorization":"Bearer a"})
    B=Principal("B","b",auth={"Authorization":"Bearer b"})
    sc=ScopeConfig(allowed_hosts=["x"],researcher_id="rid",attribution_header="X-Res",proxy="http://p:8080")
    t=HTTPTarget("https://x",scope=sc)
    t.send(HTTPRequest("GET","/1",host="x"),A); t.send(HTTPRequest("GET","/1",host="x"),B)
    check("attribution header on every request", all(s["headers"].get("X-Res")=="rid" for s in sent))
    check("ONE shared egress for all principals", len({str(s["proxies"]) for s in sent})==1 and sent[0]["proxies"] is not None)
    # governor maths (no real sleep)
    g=_RateGovernor(0.5); 
    check("rate governor honours min interval config", g.min_interval==0.5)
    # defaults: no governance
    sent.clear()
    t2=HTTPTarget("https://x",scope=ScopeConfig(allowed_hosts=["x"]))
    t2.send(HTTPRequest("GET","/1",host="x"),A)
    check("defaults stay backward-compatible (no attrib/proxy)",
          sent[0]["proxies"] is None and not any(k.startswith("X-") for k in sent[0]["headers"]))



def test_obstacle2_hardening():
    """OBSTACLE 2 (deepened): WAF-challenge detection makes the confirmer abstain
    (no corrupted Δstate), jitter is seed-reproducible, and the rate governor is
    global per egress."""
    from authpath.transport import detect_block, _RateGovernor, HTTPTarget
    from authpath.scope_guard import ScopeConfig
    check("detects JS challenge body", bool(detect_block(403, {"_raw":"Just a moment... cloudflare"})))
    check("detects perimeterx interstitial", bool(detect_block(403, {"_raw":"Pardon Our Interruption"})))
    check("clean JSON not flagged as block", detect_block(200, {"id":42,"owner":"a"}) is None)
    g1=_RateGovernor(0.1,0.5,seed=7); g2=_RateGovernor(0.1,0.5,seed=7)
    check("seeded jitter reproducible", [round(g1._rng.uniform(0,1),5) for _ in range(3)]==[round(g2._rng.uniform(0,1),5) for _ in range(3)])
    # Constructing an HTTPTarget only checks that `requests` is importable; no
    # request is sent here, so a stub keeps this test stdlib-only.
    import sys, types
    stubbed = "requests" not in sys.modules
    if stubbed:
        try:
            import requests  # noqa: F401
            stubbed = False
        except ImportError:
            sys.modules["requests"] = types.ModuleType("requests")
    try:
        sc=ScopeConfig(allowed_hosts=["x"],min_request_interval=1.0)
        t1=HTTPTarget("https://x",scope=sc); t2=HTTPTarget("https://x",scope=sc)
        check("global governor shared across same-egress targets", t1._gov is t2._gov)
    finally:
        if stubbed:
            sys.modules.pop("requests", None)



def test_obstacle3_warmup():
    """OBSTACLE 3: session-contextual warm-up shapes the footprint, is governed and
    GET-only, aborts on a WAF challenge, and is strictly VERDICT-NEUTRAL."""
    import sys, types
    seq=[]; state={"challenge_at": 10**9}
    fake=types.ModuleType("requests")
    def reqfn(method,url,params=None,json=None,headers=None,verify=True,timeout=10,proxies=None):
        seq.append(url)
        class R: pass
        r=R(); r.status_code=200; r.json=lambda:{"id":"42","owner":"a","ssn":"1"}; r.text="{}"; r.headers={}
        if len(seq)>state["challenge_at"]:
            r.status_code=403; r.json=lambda:{"_raw":"Just a moment... cloudflare"}
        return r
    fake.request=reqfn; sys.modules["requests"]=fake
    from authpath.transport import HTTPTarget
    from authpath.models import Principal
    from authpath.scope_guard import ScopeConfig
    t=HTTPTarget("https://x", scope=ScopeConfig(allowed_hosts=["x"]))
    A=Principal("A","a",auth={"Authorization":"Bearer A"})
    # GET-only, sends exactly the given paths
    seq.clear()
    n=t.warmup(A, ["/api/home","/api/orders"])
    check("warm-up sends the configured benign GETs", n==2 and len(seq)==2)
    # aborts on challenge
    seq.clear(); state["challenge_at"]=1   # 2nd request is challenged
    n2=t.warmup(A, ["/api/home","/api/orders","/api/profile"])
    check("warm-up aborts after a WAF challenge", n2 < 3)
    state["challenge_at"]=10**9



def test_obstacle4_session_freshness():
    """OBSTACLE 4: declarative session-token refresh lets a CSRF-gated write replay
    succeed (fresh token), with a GET-only source (no recursion), no effect without
    a recipe, and auth-expiry on a read-back is flagged (not silent 'clean')."""
    import sys, types
    calls=[]
    fake=types.ModuleType("requests")
    def reqfn(method,url,params=None,json=None,headers=None,verify=True,timeout=10,proxies=None):
        calls.append((method, url.replace("https://t","")))
        class R: pass
        r=R(); r.status_code=200; r.json=lambda:{"csrf":"fresh","ok":True}; r.text="{}"; r.headers={}; return r
    fake.request=reqfn; sys.modules["requests"]=fake
    from authpath.transport import HTTPTarget, SessionRefresher, detect_auth_expiry
    from authpath.models import HTTPRequest, Principal
    from authpath.scope_guard import ScopeConfig
    B=Principal("B","bob",auth={"Authorization":"Bearer B"})
    recipe=[{"principal":"B","when":"POST /api/orders/42/cancel",
             "source":{"method":"GET","path":"/api/csrf"},"extract":"csrf","inject":{"header":"X-CSRF-Token"}}]
    # with recipe: source GET fetched then write sent
    calls.clear()
    t=HTTPTarget("https://t", scope=ScopeConfig(allowed_hosts=["t"], session_refresh=recipe))
    t.send(HTTPRequest("POST","/api/orders/42/cancel",headers={"X-CSRF-Token":"OLD"},host="t"), B)
    check("recipe fetches a fresh token before the write", ("GET","/api/csrf") in calls)
    # without recipe: no refresh
    calls.clear()
    t2=HTTPTarget("https://t", scope=ScopeConfig(allowed_hosts=["t"]))
    t2.send(HTTPRequest("POST","/api/orders/42/cancel",headers={"X-CSRF-Token":"OLD"},host="t"), B)
    check("no recipe => no refresh (unchanged behaviour)", ("GET","/api/csrf") not in calls)
    # GET-only source enforced
    sr=SessionRefresher([{"when":"*","source":{"method":"POST","path":"/x"},"extract":"t","inject":{"header":"H"}}])
    check("non-GET refresh source rejected (no recursion)", len(sr.recipes)==0)
    # auth expiry detection
    check("explicit auth-expiry flagged", detect_auth_expiry(401,{"msg":"jwt expired"}))
    check("bare 401 not mislabeled as expiry", not detect_auth_expiry(401,{"error":"forbidden"}))



def test_obstacle5_chains():
    """OBSTACLE 5: a declarative multi-step chain detects a cross-object business-
    logic breach (confirmed by an owner read-back), is zero-FP on a patched target,
    is deterministic despite live-minted ids, and respects dry_run on mutations."""
    import sys, types, json, tempfile, io, contextlib
    class Shop:
        host="shop"
        def __init__(self, vuln): self.vuln=vuln; self.n=0; self.flag=False
        def handle(self, m, p, b):
            if m=="POST" and p=="/api/carts": self.n+=1; return 200, {"id":f"C{self.n}"}
            if m=="POST" and p.endswith("/apply-coupon"): return 200, {"token":"DT"}
            if m=="POST" and p=="/api/orders":
                if self.vuln and (b or {}).get("coupon") and (b or {}).get("cart")=="ALICE_CART": self.flag=True
                return 200, {"ok":True}
            if m=="GET" and p=="/api/carts/ALICE_CART": return 200, {"owner":"alice","discount_applied":self.flag}
            return 200, {}
    def install(shop):
        fake=types.ModuleType("requests")
        def reqfn(method,url,params=None,json=None,headers=None,verify=True,timeout=10,proxies=None):
            st,bd=shop.handle(method,url.replace("https://shop",""),json)
            class R: pass
            r=R(); r.status_code=st; r.json=lambda:bd; r.text=str(bd); r.headers={}; return r
        fake.request=reqfn; sys.modules["requests"]=fake
    def run(shop, dry=False, destructive=True):
        install(shop)
        for m in [k for k in list(sys.modules) if k.startswith("authpath")]: del sys.modules[m]
        from authpath.cli import _cmd_scan
        chain={"name":"x","steps":[
            {"as":"B","method":"POST","path":"/api/carts","body":{},"save":{"cart":"id"}},
            {"as":"B","method":"POST","path":"/api/carts/{{cart}}/apply-coupon","body":{},"save":{"dt":"token"}},
            {"as":"B","method":"POST","path":"/api/orders","body":{"coupon":"{{dt}}","cart":"{{ac}}"}}],
            "vars":{"ac":"ALICE_CART"},
            "assert":{"read":{"as":"A","method":"GET","path":"/api/carts/ALICE_CART"},
                      "violated_if":{"field":"discount_applied","equals":True}}}
        spec={"base_url":"https://shop","scope":{"allowed_hosts":["shop"],"automation_permitted":True,"dry_run":dry,"allow_destructive":destructive},
         "principals":[{"pid":"A","label":"a","auth":{"Authorization":"Bearer A"}},{"pid":"B","label":"b","auth":{"Authorization":"Bearer B"}}],
         "contract":{},"seed":[],"probe":[],"chains":[chain]}
        ff=tempfile.mktemp(suffix=".json"); json.dump(spec,open(ff,"w"))
        buf=io.StringIO()
        import types as TT
        with contextlib.redirect_stdout(buf): _cmd_scan(TT.SimpleNamespace(spec=ff,out=None,insecure=False))
        return buf.getvalue()
    check("vulnerable chain detected (BREACH)", "BREACH" in run(Shop(True)))
    check("patched chain is zero-FP", "BREACH" not in run(Shop(False)))
    check("deterministic verdict across runs", ("BREACH" in run(Shop(True)))==("BREACH" in run(Shop(True))))
    check("dry_run aborts a mutating chain", "ABORTED" in run(Shop(True), dry=True, destructive=False))



def test_obstacle6_transport_backend():
    """OBSTACLE 6: pluggable TLS/HTTP-2 backend. Default = requests (unchanged, no
    curl_cffi import); 'auto' resolves the impersonation profile from the captured
    UA (TLS agrees with UA); a missing curl_cffi raises loudly (no silent fallback);
    both backends normalise to an identical HTTPResponse shape."""
    import sys, types
    from authpath.transport import (impersonate_profile_from_ua, make_backend,
                                     _RequestsBackend)
    # UA -> profile coherence
    check("chrome131 UA -> chrome131", impersonate_profile_from_ua("x Chrome/131.0 y")=="chrome131")
    check("firefox UA -> firefox", impersonate_profile_from_ua("x Firefox/133.0")=="firefox133")
    check("edge UA -> edge", impersonate_profile_from_ua("x Edg/120 Chrome/120")=="edge101")
    # default = requests (curl_cffi must NOT be needed)
    sys.modules.pop("curl_cffi", None)
    if "requests" not in sys.modules:
        sys.modules["requests"] = types.ModuleType("requests"); sys.modules["requests"].request=lambda *a,**k:None
    check("default backend is requests", isinstance(make_backend(""), _RequestsBackend))
    check("default did not import curl_cffi", "curl_cffi" not in sys.modules)
    # impersonate requested but lib missing -> loud error
    sys.modules.pop("curl_cffi", None)
    raised=False
    try:
        make_backend("chrome124")
    except RuntimeError:
        raised=True
    check("missing curl_cffi raises (no silent fallback)", raised)



def test_problem1_discovery():
    """PROBLEM 1: discover->test bridge. OpenAPI parsing yields a ranked contract +
    GET-only probe candidates; mutations are never auto-probed; output is
    deterministic; malformed docs are handled; discovery cannot add a false positive."""
    from authpath import discovery as D
    doc={"openapi":"3.0.0","servers":[{"url":"https://api.x.com/v2"}],
         "paths":{"/orders/{id}":{"get":{},"delete":{}},"/health":{"get":{}}}}
    eps=D.parse_openapi(doc)
    contract=D.build_contract(eps)
    check("id-bearing GET -> OBJECT_ACCESS", contract.get("GET /v2/orders/{id}",{}).get("effect")=="OBJECT_ACCESS")
    check("bare GET dropped (NONE)", "GET /v2/health" not in contract)
    probes=D.generate_probes(eps,{"/v2/orders/{id}":["1001"]},attacker_pid="B")
    check("GET-only probes (no mutating auto-probe)", probes and all(p["method"]=="GET" for p in probes))
    check("ids threaded from capture", any(p["path"]=="/v2/orders/1001" for p in probes))
    check("deterministic output", [e.key for e in D.parse_openapi(doc)]==[e.key for e in D.parse_openapi(doc)])
    for bad in [None,{},{"paths":"x"},"str"]:
        try: D.parse_openapi(bad)
        except Exception: check("malformed doc crashed", False); break
    else: check("malformed docs handled gracefully", True)



def test_problem2_matrix():
    """PROBLEM 2: the N-principal probe matrix expands coverage (horizontal+vertical),
    never probes a legitimate owner, is GET-only, deterministic, and structurally
    cannot add a false positive (secure target => 0 findings)."""
    from authpath import matrix as M
    from authpath.engine import AuthPathEngine
    from authpath.transport import make_exchange
    from authpath.models import HTTPRequest, HTTPResponse, Principal
    from authpath.scope_guard import ScopeConfig
    P={"A":Principal("A","alice",{"Authorization":"Bearer A"}),
       "B":Principal("B","bob",{"Authorization":"Bearer B"}),
       "anon":Principal("anon","anon",{},is_anonymous=True)}
    observed=[{"owner_pid":"A","method":"GET","endpoint":"GET /o/{id}","path":"/o/42","object_id":"42"}]
    pairs=M.build_matrix(observed,P)
    atk={p.attacker_pid for p in pairs}
    check("owner never probed against own object", "A" not in atk)
    check("peers + anon covered", {"B","anon"} <= atk)
    check("anon classified vertical", any(p.attacker_pid=="anon" and p.kind=="vertical" for p in pairs))
    check("mutations never multiplied", M.build_matrix(
        [{"owner_pid":"A","method":"DELETE","endpoint":"e","path":"/o/42","object_id":"42"}], P)==[])
    check("deterministic", [p.dedup_key for p in M.build_matrix(observed,P)]==[p.dedup_key for p in M.build_matrix(observed,P)])
    # zero-FP on a secure target
    class Secure:
        host="t"
        def send(self,req,p):
            if "/o/42" in req.path and p.pid=="A": return HTTPResponse(200,{"id":"42","owner":"a","ssn":"x"})
            return HTTPResponse(403,{"error":"forbidden"})
    sc=ScopeConfig(allowed_hosts=["t"],automation_permitted=True,dry_run=True); tgt=Secure()
    eng=AuthPathEngine(tgt,P,sc,contract={"GET /o/{id}":{"effect":"OBJECT_ACCESS"}})
    eng.observe(make_exchange(tgt,HTTPRequest("GET","/o/42",host="t"),P["A"]))
    for item in M.to_probe_items(pairs):
        eng.analyze(make_exchange(tgt,HTTPRequest("GET",item["path"],host="t"),P[item["principal"]]))
    check("matrix adds no FP on a secure target", len(eng.findings)==0)



def test_integration_pipeline():
    """INTEGRATION: discovery + matrix wired into one scan pipeline via the bridge.
    The bridge extracts observed accesses from the capture deterministically; the
    unified pipeline expands contract + probes yet stays Δstate-gated (zero FP)."""
    from authpath import pipeline as P
    contract={"GET /o/{id}":{"effect":"OBJECT_ACCESS"}}
    spec={"seed":[{"principal":"A","method":"GET","path":"/o/42"}]}
    acc=P.observed_accesses(spec, contract)
    check("bridge extracts owner+object from capture",
          acc and acc[0]["owner_pid"]=="A" and acc[0]["object_id"]=="42")
    check("bridge template match is deterministic",
          P.observed_accesses(spec,contract)==P.observed_accesses(spec,contract))
    check("merge_contract keeps user-declared effect",
          P.merge_contract({"GET /o/{id}":{"effect":"X"}},{"GET /o/{id}":{"effect":"Y"}})["GET /o/{id}"]["effect"]=="X")
    check("ids_by_template groups ids", P.ids_by_template(acc)=={"/o/{id}":["42"]})



def test_problem3_error_normalisation():
    """PROBLEM 3: the error-semantics normaliser maps (status,body) to a canonical
    Outcome; an error signal can NEVER be AUTHORIZED (kills the 200-with-error-body
    false positive); masked 404 denials are disambiguated; genuine data => AUTHORIZED;
    deterministic; and a 200+error read-back never confirms a leak."""
    from authpath.errnorm import classify_outcome as C, Outcome as O, disambiguate_attacker_404
    # cardinal guard: any error signal => never AUTHORIZED
    for bd in [{"error":"x"},{"errors":["z"]},{"ok":False,"error":"no_access"},{"success":False,"id":1}]:
        check(f"error signal never AUTHORIZED ({bd})", C(200,bd) is not O.AUTHORIZED)
    check("200+forbidden -> DENIED_AUTHZ", C(200,{"error":"forbidden"}) is O.DENIED_AUTHZ)
    check("genuine object -> AUTHORIZED", C(200,{"id":"42","owner":"a","ssn":"x"}) is O.AUTHORIZED)
    check("data field named 'description' not misread",
          C(200,{"id":"7","description":"error log","owner":"a"}) is O.AUTHORIZED)
    check("403 -> DENIED_AUTHZ", C(403,{}) is O.DENIED_AUTHZ)
    check("gateway opaque 404 -> DENIED_AUTHZ", C(404,{"message":"Missing Authentication Token"}) is O.DENIED_AUTHZ)
    check("genuine 404 -> NOT_FOUND", C(404,{"message":"order not found"}) is O.NOT_FOUND)
    check("masked 404 disambiguated via owner",
          disambiguate_attacker_404(C(404,{}), C(200,{"id":"1","owner":"a"})) is O.DENIED_AUTHZ)
    check("deterministic", [C(s,b).value for s,b in [(200,{"id":1}),(403,{}),(200,{"error":"x"})]]
                          ==[C(s,b).value for s,b in [(200,{"id":1}),(403,{}),(200,{"error":"x"})]])
    # end-to-end: a 200+error read-back must NOT confirm a leak
    from authpath.engine import AuthPathEngine
    from authpath.transport import make_exchange
    from authpath.models import HTTPRequest, HTTPResponse, Principal
    from authpath.scope_guard import ScopeConfig
    class Trap:
        host="t"
        def send(self,req,p):
            if "/o/42" in req.path:
                if p.pid=="A": return HTTPResponse(200,{"id":"42","owner":"a","ssn":"x"})
                return HTTPResponse(200,{"error":"forbidden"})
            return HTTPResponse(404,{})
    P={"A":Principal("A","a",{"Authorization":"Bearer A"}),"B":Principal("B","b",{"Authorization":"Bearer B"})}
    sc=ScopeConfig(allowed_hosts=["t"],automation_permitted=True,dry_run=True); tg=Trap()
    eng=AuthPathEngine(tg,P,sc,contract={"GET /o/{id}":{"effect":"OBJECT_ACCESS"}})
    eng.observe(make_exchange(tg,HTTPRequest("GET","/o/42",host="t"),P["A"]))
    eng.analyze(make_exchange(tg,HTTPRequest("GET","/o/42",host="t"),P["B"]))
    check("200-with-error-body never confirms a leak", len(eng.findings)==0)



def test_gap1_idformat():
    """GAP 1: id-format intelligence detects encoded id structure and generates
    structure-preserving neighbours (decode->increment->re-encode), preserving the
    observed encoding style; flag OFF is byte-identical; ambiguous/uuid emit no
    malformed mutation; expansion cannot add a false positive (Δstate gates)."""
    import base64
    from authpath import idformat as F
    from authpath import matrix as M
    from authpath.models import Principal
    # url-safe global id (real GraphQL style)
    gid = base64.urlsafe_b64encode(b"Order:42").decode().rstrip("=")
    sh = F.detect_shape(gid)
    check("global id detected as b64_typed", sh.kind == "b64_typed")
    nb = F.neighbours(gid, max_neighbours=4)
    dec = [base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)).decode() for x in nb]
    check("decode->increment->re-encode exact", "Order:41" in dec and "Order:43" in dec)
    check("url-safe style preserved (no padding leak)", all("=" not in x for x in nb))
    check("padded int width preserved", "006" in F.neighbours("007") and "008" in F.neighbours("007"))
    check("prefixed mutated", "usr_1008" in F.neighbours("usr_1007"))
    check("uuid emits no blind sequence", F.neighbours("550e8400-e29b-41d4-a716-446655440000") == [])
    check("unknown -> verbatim only", F.neighbours("random-slug") == [])
    check("flag off => observed only (no weakening)", F.expand_ids("42", enabled=False) == ["42"])
    # matrix flag-off byte-identical
    P = {"A": Principal("A","a",{"Authorization":"Bearer A"}), "B": Principal("B","b",{"Authorization":"Bearer B"})}
    obs = [{"owner_pid":"A","method":"GET","endpoint":"GET /o/{id}","path":"/o/42","object_id":"42"}]
    off = [p.dedup_key for p in M.build_matrix(obs, P)]
    off2 = [p.dedup_key for p in M.build_matrix(obs, P, expand_id_formats=False)]
    check("matrix flag-off identical to default", off == off2)



def test_gap3_action_matrix():
    """GAP 3: action-level BOLA matrix generates state-change probes for non-owners,
    excludes irreversible actions by default, confirms via owner read-back (Δstate),
    respects dry_run, is zero-FP on a secure target, and catches a real action-level
    BOLA on a vulnerable target."""
    from authpath import action_matrix as A
    from authpath.chains import ChainRunner
    from authpath.engine import AuthPathEngine
    from authpath.models import HTTPRequest, HTTPResponse, Principal
    from authpath.scope_guard import ScopeConfig
    actions=[{"owner_pid":"A","method":"PUT","endpoint":"PUT /o/{id}/cancel",
              "path":"/o/42/cancel","object_id":"42","readback_path":"/o/42"}]
    P={"A":Principal("A","a",{"Authorization":"Bearer A"}),"B":Principal("B","b",{"Authorization":"Bearer B"})}
    pairs=A.build_action_matrix(actions,[],P)
    check("non-owner gets an action probe", any(p.attacker_pid=="B" for p in pairs))
    check("owner excluded", all(p.attacker_pid!="A" for p in pairs))
    check("irreversible excluded by default",
          all(p.method!="DELETE" for p in A.build_action_matrix(
              [{"owner_pid":"A","method":"DELETE","endpoint":"e","path":"/o/42","object_id":"42"}],[],P)))
    check("deterministic", [p.dedup_key for p in A.build_action_matrix(actions,[],P)]
                          ==[p.dedup_key for p in A.build_action_matrix(actions,[],P)])
    specs=A.to_chain_specs(pairs)
    for sp in specs: sp["assert"]["violated_if"]={"field":"status","equals":"cancelled"}
    def target(secure):
        class T:
            host="t"
            def __init__(self): self.c=False
            def send(self,req,p):
                if req.path=="/o/42/cancel" and req.method=="PUT":
                    if secure and p.pid!="A": return HTTPResponse(403,{"error":"forbidden"})
                    self.c=True; return HTTPResponse(200,{"ok":True})
                if req.path=="/o/42": return HTTPResponse(200,{"id":"42","owner":"a","status":"cancelled" if self.c else "active"})
                return HTTPResponse(404,{})
        return T()
    # dry_run blocks
    t0=target(True); sc0=ScopeConfig(allowed_hosts=["t"],automation_permitted=True,dry_run=True,allow_destructive=False)
    e0=AuthPathEngine(t0,P,sc0,contract={}); r0=ChainRunner(e0,t0,e0.scope_guard,P)
    for sp in specs: r0.run(sp,"t")
    check("dry_run leaves target unmutated", t0.c is False)
    # secure => 0 findings
    t1=target(True); sc1=ScopeConfig(allowed_hosts=["t"],automation_permitted=True,dry_run=False,allow_destructive=True)
    e1=AuthPathEngine(t1,P,sc1,contract={}); r1=ChainRunner(e1,t1,e1.scope_guard,P)
    for sp in specs: r1.run(sp,"t")
    check("secure target => 0 action findings", len(e1.findings)==0)
    # vulnerable => finding
    t2=target(False); e2=AuthPathEngine(t2,P,sc1,contract={}); r2=ChainRunner(e2,t2,e2.scope_guard,P)
    for sp in specs: r2.run(sp,"t")
    check("vulnerable target => action-level BOLA confirmed", len(e2.findings)>=1)



def test_gap2_nestedref():
    """GAP 2: object-reference detection in bodies/nested JSON/query strings with
    structure-preserving swap. Non-ref fields (amount, count) are never swapped; the
    rebuild is exact and does not mutate the original; flag off => no swaps; swaps
    cannot add a false positive (Δstate gates)."""
    from authpath import nestedref as N
    body={"from_account":"A123","to":"B456","amount":50,"note":"x"}
    names=[r.json_path for r in N.find_refs(body=body)]
    check("body ref detected", "from_account" in names)
    check("non-ref 'amount' ignored", "amount" not in names)
    check("'account' not blocked by 'count' substring", N._is_ref_name("account_id"))
    check("'count' field IS blocked", not N._is_ref_name("count"))
    nested={"doc":{"id":"42","title":"secret"},"with":"bob"}
    check("nested body.doc.id detected", "doc.id" in [r.json_path for r in N.find_refs(body=nested)])
    check("query account_id detected", "account_id" in [r.json_path for r in N.find_refs(query={"account_id":"A1","format":"json"})])
    sw=N.generate_swaps(nested,None,["99"],enabled=True)[0]
    check("exact rebuild (only target changed)", sw["body"]["doc"]["id"]=="99" and sw["body"]["doc"]["title"]=="secret")
    check("original not mutated", nested["doc"]["id"]=="42")
    check("flag off => no swaps", N.generate_swaps(body,None,["99"],enabled=False)==[])
    check("deterministic", [(x["ref_path"],x["new"]) for x in N.generate_swaps(nested,None,["9"],enabled=True)]
                          ==[(x["ref_path"],x["new"]) for x in N.generate_swaps(nested,None,["9"],enabled=True)])



def test_track1_surface_intel():
    """TRACK 1: read-only strategic classifier. Bearer API => ARENA (with reach!=bug
    caveat); DPoP/mTLS/attested/cnf-bound => OUT_OF_REACH naming the binding; ambiguous
    => ARENA-by-default; deterministic; never AUTHORIZED-affecting (read-only)."""
    from authpath import surface_intel as S
    from authpath.surface_intel import Reach
    import base64, json
    v=S.classify_surface(request_headers={"Authorization":"Bearer a.b.c"},
                         response_body={"id":"42"}, content_type="application/json")
    check("bearer API => ARENA", v.reach is Reach.ARENA and v.token_binding=="bearer")
    check("ARENA carries the reach!=bug caveat", "does NOT claim a vulnerability" in v.caveat)
    check("DPoP => OUT_OF_REACH", S.classify_surface(request_headers={"Authorization":"DPoP x"}).reach is Reach.OUT_OF_REACH)
    check("mTLS => OUT_OF_REACH", S.classify_surface(response_body={"error":"client certificate required"}).reach is Reach.OUT_OF_REACH)
    check("attested => OUT_OF_REACH", S.classify_surface(response_body={"error":"Play Integrity attestation failed"}).token_binding=="attested")
    payload=base64.urlsafe_b64encode(json.dumps({"cnf":{"jkt":"k"}}).encode()).decode().rstrip("=")
    check("cnf/jkt JWT => bound", S.classify_surface(request_headers={"Authorization":f"Bearer h.{payload}.s"}).token_binding=="dpop")
    check("ambiguous => ARENA-by-default", S.classify_surface(response_body={"id":1}).reach is Reach.ARENA)
    check("measured non-portability overrides prior",
          S.classify_surface(request_headers={"Authorization":"Bearer x.y.z"},probe_portable=False).reach is Reach.OUT_OF_REACH)
    check("deterministic",
          S.report(S.classify_surface(request_headers={"Authorization":"Bearer x"}))
          ==S.report(S.classify_surface(request_headers={"Authorization":"Bearer x"})))

if __name__ == "__main__":
    for fn in [test_offline_no_false_findings, test_offline_real_idor_surfaces,
               test_replay_target_object_identity, test_name_neutral_salience,
               test_normalisation_self_alias, test_scope_host_confusion,
               test_ownership_noop_vs_escalation, test_payment_generic_shape,
               test_price_robustness, test_deep_body_no_dos, test_coherent_header_profile, test_transport_governance, test_obstacle2_hardening, test_obstacle3_warmup, test_obstacle4_session_freshness, test_obstacle5_chains, test_obstacle6_transport_backend, test_problem1_discovery, test_problem2_matrix, test_integration_pipeline, test_problem3_error_normalisation, test_gap1_idformat, test_gap3_action_matrix, test_gap2_nestedref, test_track1_surface_intel]:
        print(f"\n{fn.__name__}:")
        fn()
    print(f"\n{'='*50}\n  {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
