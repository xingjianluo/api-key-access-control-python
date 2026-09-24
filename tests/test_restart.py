"""重启场景：状态文件持久化使配额消耗与吊销状态在新进程实例后延续。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.security import hash_key
from app.server import create_app
from tests.conftest import ADMIN_KEY


def _new_client(state_file, clock):
    return TestClient(create_app(state_path=state_file, admin_key=ADMIN_KEY, clock=clock))


def test_quota_usage_survives_restart(client, state_file, clock, admin_headers, helpers):
    issued = helpers.issue(
        client, admin_headers, "restart-user", ["items:read"],
        quota_limit=5, quota_window_seconds=3600,
    )
    h = helpers.bearer(issued["api_key"])
    for _ in range(5):
        assert client.get("/items", headers=h).status_code == 200
    assert client.get("/items", headers=h).status_code == 429

    # 模拟服务重启：新应用实例从同一状态文件加载，时钟不变
    restarted = _new_client(state_file, clock)
    resp = restarted.get("/items", headers=h)
    assert resp.status_code == 429
    assert resp.json()["error"]["reason"] == "quota_exceeded"

    # 配额计数在管理视图中仍为 5，未被静默重置
    view = restarted.get("/admin/callers", headers=admin_headers).json()
    user = next(c for c in view["callers"] if c["caller_id"] == "restart-user")
    assert user["quota"]["used"] == 5
    assert user["quota"]["limit"] == 5


def test_quota_resets_only_after_window_not_restart(client, state_file, clock, admin_headers, helpers):
    issued = helpers.issue(
        client, admin_headers, "window-user", ["items:read"],
        quota_limit=3, quota_window_seconds=60,
    )
    h = helpers.bearer(issued["api_key"])
    for _ in range(3):
        client.get("/items", headers=h)

    # 重启但窗口未结束：仍然超额
    assert _new_client(state_file, clock).get("/items", headers=h).status_code == 429
    # 窗口过期后即使"重启"也恢复
    clock.advance(61)
    assert _new_client(state_file, clock).get("/items", headers=h).status_code == 200


def test_revocation_survives_restart(client, state_file, clock, admin_headers, helpers):
    issued = helpers.issue(client, admin_headers, "revive-me", ["items:read"])
    client.post(
        "/admin/keys/revoke",
        json={"caller_id": "revive-me", "key_id": issued["key_id"]},
        headers=admin_headers,
    )
    restarted = _new_client(state_file, clock)
    resp = restarted.get("/items", headers=helpers.bearer(issued["api_key"]))
    assert resp.status_code == 401
    assert resp.json()["error"]["reason"] == "revoked_api_key"


def test_bootstrap_admin_seeding_is_idempotent_across_restarts(client, state_file, clock):
    # 多次重启不应产生重复的引导凭证
    for _ in range(3):
        c = _new_client(state_file, clock)
        view = c.get("/admin/callers", headers={"Authorization": f"Bearer {ADMIN_KEY}"}).json()
    admin = next(x for x in view["callers"] if x["caller_id"] == "__bootstrap_admin__")
    assert len(admin["credentials"]) == 1


def test_state_file_contains_no_plaintext_keys(client, state_file, admin_headers, helpers):
    issued = helpers.issue(client, admin_headers, "secret-user", ["items:read"])
    client.get("/items", headers=helpers.bearer(issued["api_key"]))

    raw = state_file.read_text(encoding="utf-8")
    assert issued["api_key"] not in raw                 # 明文不落盘
    assert hash_key(issued["api_key"]) in raw          # 只保存哈希
    assert ADMIN_KEY not in raw
