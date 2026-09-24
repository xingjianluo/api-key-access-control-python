"""凭证生命周期：签发 / 哈希存储 / 轮换 / 吊销 / 过期 / 失败原因可区分。"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.service import utc_now


def _issue(client: TestClient, admin_headers, **body) -> dict:
    r = client.post("/admin/keys", headers=admin_headers, json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_secret_never_stored_in_plaintext(
    client: TestClient, settings, admin_headers
) -> None:
    issued = _issue(
        client, admin_headers, caller_id="alice", scopes=["data:read"]
    )
    secret = issued["secret"]
    creds_file = settings.data_dir / "credentials.json"
    raw = creds_file.read_text(encoding="utf-8")
    # 明文密钥绝不出现在持久化文件中
    assert secret not in raw
    payload = json.loads(raw)
    record = payload[issued["key_id"]]
    assert "secret" not in record
    assert len(record["key_hash"]) == 64  # sha256 hex
    assert record["caller_id"] == "alice"


def test_missing_key_rejected(client: TestClient) -> None:
    r = client.get("/me")
    assert r.status_code == 401
    body = r.json()["detail"]
    assert body["reason"] == "missing_key"
    assert 'error="missing_key"' in r.headers["www-authenticate"]


def test_malformed_authorization_rejected_as_missing(client: TestClient) -> None:
    r = client.get("/me", headers={"Authorization": "Token abc"})
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "missing_key"


def test_invalid_key_distinguishable(client: TestClient) -> None:
    r = client.get("/me", headers={"Authorization": "Bearer ak_unknown"})
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "invalid_key"


def test_valid_key_accepted(client: TestClient, admin_headers) -> None:
    issued = _issue(client, admin_headers, caller_id="bob", scopes=[])
    r = client.get(
        "/me", headers={"Authorization": f"Bearer {issued['secret']}"}
    )
    assert r.status_code == 200
    assert r.json()["caller_id"] == "bob"
    assert r.json()["key_id"] == issued["key_id"]


def test_rotation_invalidates_old_secret(
    client: TestClient, admin_headers
) -> None:
    issued = _issue(client, admin_headers, caller_id="carol", scopes=[])
    old_secret = issued["secret"]
    key_id = issued["key_id"]

    r = client.post(
        f"/admin/keys/{key_id}/rotate", headers=admin_headers, json={}
    )
    assert r.status_code == 200, r.text
    new_secret = r.json()["secret"]
    assert new_secret != old_secret

    # 旧密钥立即失效
    r = client.get("/me", headers={"Authorization": f"Bearer {old_secret}"})
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "invalid_key"

    # 新密钥可用，且 key_id / caller_id 不变
    r = client.get("/me", headers={"Authorization": f"Bearer {new_secret}"})
    assert r.status_code == 200
    assert r.json()["key_id"] == key_id
    assert r.json()["caller_id"] == "carol"

    # 旧明文也不应留在磁盘
    raw = (client.app.state.settings.data_dir / "credentials.json").read_text()
    assert old_secret not in raw and new_secret not in raw


def test_revoked_key_rejected_with_distinct_reason(
    client: TestClient, admin_headers
) -> None:
    issued = _issue(client, admin_headers, caller_id="dave", scopes=["data:read"])
    headers = {"Authorization": f"Bearer {issued['secret']}"}

    r = client.post(f"/admin/keys/{issued['key_id']}/revoke", headers=admin_headers)
    assert r.status_code == 200

    r = client.get("/data/read", headers=headers)
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "revoked_key"


def test_expired_key_rejected_with_distinct_reason(
    client: TestClient, admin_headers, auth_service
) -> None:
    issued = _issue(
        client, admin_headers, caller_id="erin", scopes=["data:read"],
        ttl_seconds=60,
    )
    headers = {"Authorization": f"Bearer {issued['secret']}"}

    # 未过期时可用
    assert client.get("/data/read", headers=headers).status_code == 200

    # 让时钟越过过期时刻
    real_now = auth_service._clock()
    auth_service._clock = lambda: real_now + timedelta(seconds=61)

    r = client.get("/data/read", headers=headers)
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "expired_key"


def test_admin_endpoints_require_admin_scope(
    client: TestClient, admin_headers
) -> None:
    # 普通调用方（无 admin scope）不能管理凭证
    issued = _issue(client, admin_headers, caller_id="mallory", scopes=[])
    user_headers = {"Authorization": f"Bearer {issued['secret']}"}

    r = client.get("/admin/keys", headers=user_headers)
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "insufficient_scope"


def test_rotate_unknown_key_returns_404(client: TestClient, admin_headers) -> None:
    r = client.post("/admin/keys/key_doesnotexist/rotate",
                    headers=admin_headers, json={})
    assert r.status_code == 404
    assert r.json()["reason"] == "unknown_key_id"
