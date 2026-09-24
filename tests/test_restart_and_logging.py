"""重启后状态延续（吊销/轮换）与可解释日志。"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient


def test_revocation_persists_across_restart(settings) -> None:
    from main import create_app

    with TestClient(create_app(settings)) as first:
        data_dir = settings.data_dir
        admin_secret = (
            data_dir / settings.admin_secret_file
        ).read_text().strip()
        admin_h = {"Authorization": f"Bearer {admin_secret}"}
        r = first.post(
            "/admin/keys",
            headers=admin_h,
            json={"caller_id": "ghost", "scopes": ["data:read"]},
        )
        issued = r.json()
        key_id, secret = issued["key_id"], issued["secret"]
        assert first.post(
            f"/admin/keys/{key_id}/revoke", headers=admin_h
        ).status_code == 200

    # 重启后吊销结论保持
    with TestClient(create_app(settings)) as second:
        r = second.get(
            "/data/read", headers={"Authorization": f"Bearer {secret}"}
        )
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "revoked_key"


def test_rotation_persists_across_restart(settings) -> None:
    from main import create_app

    with TestClient(create_app(settings)) as first:
        data_dir = settings.data_dir
        admin_secret = (
            data_dir / settings.admin_secret_file
        ).read_text().strip()
        admin_h = {"Authorization": f"Bearer {admin_secret}"}
        r = first.post(
            "/admin/keys", headers=admin_h,
            json={"caller_id": "rotator", "scopes": []},
        )
        issued = r.json()
        old_secret = issued["secret"]
        r = first.post(
            f"/admin/keys/{issued['key_id']}/rotate",
            headers=admin_h, json={},
        )
        new_secret = r.json()["secret"]

    with TestClient(create_app(settings)) as second:
        assert second.get(
            "/me", headers={"Authorization": f"Bearer {old_secret}"}
        ).status_code == 401
        assert second.get(
            "/me", headers={"Authorization": f"Bearer {new_secret}"}
        ).status_code == 200


def test_logs_contain_key_id_reason_and_quota_count(
    client: TestClient, admin_headers, caplog
) -> None:
    """单测日志中必须打印凭证标识、判定依据与配额计数。"""
    r = client.post(
        "/admin/keys",
        headers=admin_headers,
        json={"caller_id": "logged", "scopes": ["data:read"], "quota_limit": 1},
    )
    key_id = r.json()["key_id"]
    secret = r.json()["secret"]
    headers = {"Authorization": f"Bearer {secret}"}

    with caplog.at_level(logging.INFO, logger="auth"):
        # 成功：应打印 key_id、caller、配额 1/1
        assert client.get("/data/read", headers=headers).status_code == 200
        # 超额：应打印 reason=quota_exceeded 与 quota=1/1
        assert client.get("/data/read", headers=headers).status_code == 429
        # 越权：应打印 key_id 与 insufficient_scope
        assert client.post("/data/write", headers=headers).status_code == 403
        # 无效：应打印 invalid_key
        assert client.get(
            "/data/read", headers={"Authorization": "Bearer ak_bogus"}
        ).status_code == 401

    text = caplog.text
    assert key_id in text
    assert "auth allow" in text
    assert "quota=1/1" in text
    assert "reason=quota_exceeded" in text
    assert "reason=insufficient_scope" in text
    assert "reason=invalid_key" in text
