"""权限范围模型：已认证但越权 -> 403，与未认证 401 可区分。"""

from __future__ import annotations

from fastapi.testclient import TestClient


def _issue(client: TestClient, admin_headers, caller_id: str, scopes: list[str]) -> str:
    r = client.post(
        "/admin/keys",
        headers=admin_headers,
        json={"caller_id": caller_id, "scopes": scopes, "quota_limit": 100},
    )
    assert r.status_code == 200, r.text
    return r.json()["secret"]


def test_missing_credentials_is_401_not_403(client: TestClient) -> None:
    r = client.get("/data/read")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "missing_key"


def test_read_scope_allows_read(client: TestClient, admin_headers) -> None:
    secret = _issue(client, admin_headers, "reader", ["data:read"])
    r = client.get(
        "/data/read", headers={"Authorization": f"Bearer {secret}"}
    )
    assert r.status_code == 200
    assert r.json()["caller_id"] == "reader"


def test_read_scope_cannot_write(client: TestClient, admin_headers) -> None:
    secret = _issue(client, admin_headers, "reader", ["data:read"])
    r = client.post(
        "/data/write", headers={"Authorization": f"Bearer {secret}"}
    )
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail["reason"] == "insufficient_scope"
    assert "data:write" in detail["message"]
    assert 'error="insufficient_scope"' in r.headers["www-authenticate"]


def test_no_scope_key_can_reach_me_but_not_protected(
    client: TestClient, admin_headers
) -> None:
    secret = _issue(client, admin_headers, "scopeless", [])
    headers = {"Authorization": f"Bearer {secret}"}
    # /me 只要求有效凭证
    assert client.get("/me", headers=headers).status_code == 200
    # 业务 scope 缺失 -> 403（不是 401：凭证是合法的）
    assert client.get("/data/read", headers=headers).status_code == 403


def test_write_scope_allows_write(client: TestClient, admin_headers) -> None:
    secret = _issue(client, admin_headers, "writer", ["data:write"])
    r = client.post(
        "/data/write", headers={"Authorization": f"Bearer {secret}"}
    )
    assert r.status_code == 200
    assert r.json()["written"] is True


def test_scopes_are_isolated_between_callers(
    client: TestClient, admin_headers
) -> None:
    reader = _issue(client, admin_headers, "a", ["data:read"])
    writer = _issue(client, admin_headers, "b", ["data:write"])
    assert client.get(
        "/data/read", headers={"Authorization": f"Bearer {reader}"}
    ).status_code == 200
    assert client.get(
        "/data/read", headers={"Authorization": f"Bearer {writer}"}
    ).status_code == 403
