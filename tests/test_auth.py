"""凭证生命周期：缺失、无效、吊销、过期、轮换的失败原因可区分。"""

from __future__ import annotations


def test_missing_api_key_is_rejected(client, helpers):
    resp = client.get("/items")
    assert resp.status_code == 401
    err = resp.json()["error"]
    assert err["reason"] == "missing_api_key"
    assert "WWW-Authenticate" in resp.headers


def test_non_bearer_scheme_is_missing(client, helpers):
    resp = client.get("/items", headers={"Authorization": "Basic abc"})
    assert resp.status_code == 401
    assert resp.json()["error"]["reason"] == "missing_api_key"


def test_unknown_api_key_is_invalid(client, admin_headers, helpers):
    resp = client.get("/items", headers=helpers.bearer("ak_does_not_exist"))
    assert resp.status_code == 401
    assert resp.json()["error"]["reason"] == "invalid_api_key"
    # 与 missing 区分
    assert resp.json()["error"]["reason"] != "missing_api_key"


def test_valid_key_passes_and_public_endpoint_unaffected(client, admin_headers, helpers):
    issued = helpers.issue(client, admin_headers, "alice", ["items:read"])
    resp = client.get("/items", headers=helpers.bearer(issued["api_key"]))
    assert resp.status_code == 200, resp.text

    # 公开接口无需鉴权，响应契约不变
    assert client.get("/").json() == {"Hello": "World"}
    assert client.get("/").status_code == 200


def test_revoked_key_is_rejected_with_distinct_reason(client, admin_headers, helpers):
    issued = helpers.issue(client, admin_headers, "bob", ["items:read"])
    ok = client.get("/items", headers=helpers.bearer(issued["api_key"]))
    assert ok.status_code == 200

    revoked = client.post(
        "/admin/keys/revoke",
        json={"caller_id": "bob", "key_id": issued["key_id"]},
        headers=admin_headers,
    )
    assert revoked.status_code == 200 and revoked.json()["changed"] is True

    resp = client.get("/items", headers=helpers.bearer(issued["api_key"]))
    assert resp.status_code == 401
    err = resp.json()["error"]
    assert err["reason"] == "revoked_api_key"
    assert err["key_id"] == issued["key_id"]


def test_revoke_unknown_key_is_idempotent(client, admin_headers, helpers):
    resp = client.post(
        "/admin/keys/revoke",
        json={"caller_id": "ghost", "key_id": "kid_ghost"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["changed"] is False


def test_expired_key_is_rejected_with_distinct_reason(client, admin_headers, clock, helpers):
    issued = helpers.issue(
        client, admin_headers, "carol", ["items:read"], expires_in_seconds=10
    )
    # 未过期：合法请求不得误拒
    assert client.get("/items", headers=helpers.bearer(issued["api_key"])).status_code == 200

    clock.advance(11)
    resp = client.get("/items", headers=helpers.bearer(issued["api_key"]))
    assert resp.status_code == 401
    err = resp.json()["error"]
    assert err["reason"] == "expired_api_key"
    assert err["reason"] not in {"revoked_api_key", "invalid_api_key"}


def test_rotation_old_revoked_new_works_quota_preserved(client, admin_headers, helpers):
    issued = helpers.issue(
        client, admin_headers, "dave", ["items:read"],
        quota_limit=5, quota_window_seconds=3600,
    )
    h = helpers.bearer(issued["api_key"])
    client.get("/items", headers=h)
    client.get("/items", headers=h)

    rotated = client.post(
        "/admin/keys/rotate",
        json={"caller_id": "dave", "key_id": issued["key_id"]},
        headers=admin_headers,
    ).json()
    assert rotated["rotated_from"] == issued["key_id"]

    # 旧密钥立即失效且原因为已吊销
    old_resp = client.get("/items", headers=h)
    assert old_resp.status_code == 401
    assert old_resp.json()["error"]["reason"] == "revoked_api_key"

    # 新密钥可用，范围继承
    new_resp = client.get("/items", headers=helpers.bearer(rotated["api_key"]))
    assert new_resp.status_code == 200

    # 配额计数在轮换后延续（已用 3 / 5）
    usage = client.get("/admin/callers", headers=admin_headers).json()
    dave = next(c for c in usage["callers"] if c["caller_id"] == "dave")
    assert dave["quota"]["used"] == 3


def test_rotate_unknown_key_returns_invalid(client, admin_headers, helpers):
    resp = client.post(
        "/admin/keys/rotate",
        json={"caller_id": "nope", "key_id": "kid_nope"},
        headers=admin_headers,
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["reason"] == "invalid_api_key"


def test_unknown_scope_rejected_at_issue(client, admin_headers, helpers):
    resp = client.post(
        "/admin/keys",
        json={"caller_id": "eve", "scopes": ["not:a:scope"]},
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["reason"] == "bad_request"
