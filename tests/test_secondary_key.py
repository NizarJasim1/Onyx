"""
Secondary-key resource identity regression — CRUCIBLE problem #6 (GT3 generalization).

An object addressed by a single non-pagination query key (?invoice=, ?email=) is a distinct
resource, so secondary-key BOLA is visible. Pagination / projection / filter params
(?page, ?sort, ?expand, ?limit) must NEVER be promoted to objects — identity is the spine
every detector keys on, so this guard protects precision across the whole tool.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authpath.surface_map import identify
from authpath.models import HTTPRequest


def _id(path):
    return identify(HTTPRequest("GET", path, host="t.local"))


def test_single_secondary_key_is_an_object():
    assert str(_id("/api/orders?invoice=INV-DDD")) == "order:invoice=inv-ddd"
    assert str(_id("/api/users?email=a@b.com")) == "user:email=a@b.com"


def test_pagination_and_projection_are_never_objects():
    for path in ("/api/orders?page=2", "/api/orders?sort=date", "/api/orders?limit=10",
                 "/api/orders?offset=5", "/api/accounts?expand=full", "/api/orders?q=foo",
                 "/api/orders?cursor=abc", "/api/items?fields=id,name"):
        assert _id(path) is None, f"{path} was wrongly promoted to an object"


def test_bare_collection_is_not_an_object():
    assert _id("/api/orders") is None


def test_pagination_plus_one_key_resolves_to_the_meaningful_key():
    # page is filtered out; invoice is the single meaningful key
    assert str(_id("/api/orders?page=2&invoice=X")) == "order:invoice=x"


def test_multiple_meaningful_keys_is_not_a_single_object():
    # two non-pagination keys → ambiguous, not one object → abstain (None)
    assert _id("/api/orders?invoice=X&account=Y") is None


def test_path_id_still_takes_precedence():
    # a real path id must still win and not be shadowed by the secondary-key path
    assert str(_id("/api/docs/4")) == "doc:4"
