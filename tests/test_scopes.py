"""权限范围：越权 403 与未认证 401 必须可区分；公开接口行为不变。"""

from __future__ import annotations


def test_unauthenticated_is_401(client, helpers):
    resp = client.get("/items")
    assert resp.status_code == 401
    assert resp.json()["error"]["reason"] == "missing_api_key"


def test_authenticated_but_missing_scope_is_403(client, admin_headers, helpers):
    issued = helpers.issue(client, admin_headers, "alice", ["items:read"])
    h = helpers.bearer(issued["api_key"])

    # read 范围可以读
    assert client.get("/items", headers=h).status_code == 200
    # read 范围不能写 -> 403（已认证但越权）
    resp = client.post("/items", json={"name": "x"}, headers=h)
    assert resp.status_code == 403
    err = resp.json()["error"]
    assert err["reason"] == "insufficient_scope"
    assert "items:write" in err["message"]
    assert err["key_id"] == issued["key_id"]


def test_403_distinct_from_401(client, admin_headers, helpers):
    issued = helpers.issue(client, admin_headers, "bob", [])
    resp = client.post("/items", json={"name": "x"}, headers=helpers.bearer(issued["api_key"]))
    assert resp.status_code == 403
    assert resp.json()["error"]["reason"] == "insufficient_scope"

    no_cred = client.post("/items", json={"name": "x"})
    assert no_cred.status_code == 401


def test_write_scope_can_post(client, admin_headers, helpers):
    issued = helpers.issue(client, admin_headers, "carol", ["items:write"])
    h = helpers.bearer(issued["api_key"])
    resp = client.post("/items", json={"name": "widget"}, headers=h)
    assert resp.status_code == 200
    assert resp.json()["owner"] == "carol"
    # 只有 write 没有 read
    assert client.get("/items", headers=h).status_code == 403


def test_business_scope_cannot_access_admin(client, admin_headers, helpers):
    issued = helpers.issue(client, admin_headers, "dave", ["items:read", "items:write"])
    resp = client.get("/admin/callers", headers=helpers.bearer(issued["api_key"]))
    assert resp.status_code == 403
    assert resp.json()["error"]["reason"] == "insufficient_scope"


def test_admin_scope_cannot_access_business_endpoint(client, admin_headers, helpers):
    # 引导 admin 只有 admin 范围，访问业务接口应越权（而非放行）
    assert client.get("/items", headers=admin_headers).status_code == 403


def test_public_endpoint_remains_open_with_auth_enabled(client, helpers):
    # 不带凭证、带无效凭证时，公开接口都照常返回且响应契约不变
    assert client.get("/").json() == {"Hello": "World"}
    assert client.get("/", headers=helpers.bearer("ak_garbage")).json() == {"Hello": "World"}
