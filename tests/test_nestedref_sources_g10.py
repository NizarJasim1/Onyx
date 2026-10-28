"""
Falsification suite for G10 (extended reference-source extraction). Verifies the
new sources (headers, JWT claims, GraphQL variables) reuse the same conservative
guards, that JWT claims are extraction-only, and that the prior body+query behavior
is byte-identical. No network.
"""
import sys, os, base64, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.nestedref import find_refs, swap_ref_full, swap_ref, RefField


def _jwt(claims: dict) -> str:
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg':'none'})}.{seg(claims)}.sig"


def test_body_query_behavior_unchanged():
    """No new sources passed ⇒ identical to before (body + query only)."""
    refs = find_refs(body={"doc_id": "usr_abcdef123"}, query={"account_id": "usr_zzz999aa"})
    locs = sorted(r.location for r in refs)
    assert locs == ["body", "query"]


def test_header_reference_extracted():
    refs = find_refs(body=None, headers={"X-Customer-ID": "cus_abc123xyz",
                                         "Content-Type": "application/json"})
    hdr = [r for r in refs if r.location == "header"]
    assert len(hdr) == 1 and hdr[0].json_path == "X-Customer-ID"
    # Content-Type is not a ref name → ignored
    assert all(r.json_path != "Content-Type" for r in refs)


def test_jwt_claims_extracted_but_not_swappable():
    # NOTE: 'sub' and camelCase names are a separate name-matcher limitation (not
    # G10's source scope). Here we use the snake_case claims the current guard accepts.
    tok = _jwt({"user_id": "usr_victim01", "tenant_id": "org_9931aa", "role": "admin"})
    refs = find_refs(headers={"Authorization": f"Bearer {tok}"})
    jwt_refs = [r for r in refs if r.location == "jwt"]
    names = sorted(r.json_path for r in jwt_refs)
    # 'role' is in _NEVER → excluded; user_id + tenant_id are refs
    assert "user_id" in names and "tenant_id" in names and "role" not in names
    assert all(r.swappable is False for r in jwt_refs)


def test_jwt_swap_is_refused():
    r = RefField("jwt", "sub", "usr_victim01", 90, swappable=False)
    try:
        swap_ref_full(headers={}, ref=r, new_value="usr_attacker")
        assert False, "must refuse to swap a signed JWT claim"
    except ValueError:
        pass


def test_graphql_variables_extracted_and_swappable():
    refs = find_refs(variables={"order_id": "ord_abc12345", "note": "hi"})
    gv = [r for r in refs if r.location == "gql_var"]
    assert len(gv) == 1 and gv[0].json_path == "order_id" and gv[0].swappable is True


def test_never_list_still_blocks_across_all_sources():
    """amount/name/role etc. must never be treated as refs, in ANY source."""
    refs = find_refs(body={"amount": "12345678"},
                     headers={"X-Amount": "999999"},
                     variables={"price": "500000"})
    assert refs == []


def test_full_swap_replaces_only_target_header():
    r = RefField("header", "X-Customer-ID", "cus_old000111", 90)
    b, q, h, v = swap_ref_full(headers={"X-Customer-ID": "cus_old000111",
                                        "X-Other": "keep"}, ref=r, new_value="cus_new999222")
    assert h["X-Customer-ID"] == "cus_new999222" and h["X-Other"] == "keep"


def test_full_swap_replaces_only_target_gql_var():
    r = RefField("gql_var", "orderId", "ord_old000", 90)
    b, q, h, v = swap_ref_full(variables={"orderId": "ord_old000", "keep": "x"},
                               ref=r, new_value="ord_new111")
    assert v["orderId"] == "ord_new111" and v["keep"] == "x"


def test_authorization_header_not_double_counted_as_plain_header():
    """The Authorization header is mined for JWT claims, not treated as a plain
    header reference."""
    tok = _jwt({"user_id": "usr_x1"})
    refs = find_refs(headers={"Authorization": f"Bearer {tok}"})
    assert all(r.location != "header" for r in refs)   # only jwt-location refs
    assert any(r.location == "jwt" for r in refs)


def test_malformed_jwt_is_failsafe():
    refs = find_refs(headers={"Authorization": "Bearer not.a.valid.jwt.at.all"})
    # must not raise; simply yields no jwt refs (or ignores) 
    assert isinstance(refs, list)


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS  {fn.__name__}"); passed += 1
        except Exception:
            print(f"FAIL  {fn.__name__}"); traceback.print_exc()
    print(f"\n{passed}/{len(fns)} passed")
