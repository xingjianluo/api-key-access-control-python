"""调用方自助查询配额：凭自己的凭证即可查，不消耗业务配额。"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi.testclient import TestClient


def _issue(client: TestClient, admin_headers, caller_id: str, limit: int,
           scopes: list[str] | None = None) -> str:
    r = client.post(
        "/admin/keys",
        headers=admin_headers,
        json={
            "caller_id": caller_id,
            "scopes": scopes if scopes is not None else ["data:read"],
            "quota_limit": limit,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["secret"]


def test_caller_can_query_own_quota(client: TestClient, admin_headers) -> None:
    secret = _issue(client, admin_headers, "alice", 3)
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/data/read", headers=headers).status_code == 200

    r = client.get("/me/quota", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["caller_id"] == "alice"
    assert body["limit"] == 3
    assert body["used"] == 1
    assert body["remaining"] == 2
    # 窗口重开时刻 = 窗口起点 + 窗口长度
    window_start = datetime.fromisoformat(body["window_start"])
    window_reset_at = datetime.fromisoformat(body["window_reset_at"])
    assert window_reset_at - window_start == timedelta(seconds=3600)


def test_self_query_does_not_consume_quota(
    client: TestClient, admin_headers
) -> None:
    secret = _issue(client, admin_headers, "alice", 2)
    headers = {"Authorization": f"Bearer {secret}"}
    # 反复自助查询，不计数
    for _ in range(10):
        r = client.get("/me/quota", headers=headers)
        assert r.status_code == 200
        assert r.json()["used"] == 0
    # 业务配额完好：2 个放行，第 3 个 429
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 429
    # 超额后自助查询仍可用（查询本身不受配额限制）
    r = client.get("/me/quota", headers=headers)
    assert r.status_code == 200
    assert r.json()["used"] == 2 and r.json()["remaining"] == 0


def test_self_query_requires_valid_credential(client: TestClient) -> None:
    assert client.get("/me/quota").status_code == 401
    r = client.get("/me/quota", headers={"Authorization": "Bearer ak_bad"})
    assert r.status_code == 401


def test_self_query_reflects_adjusted_limit(
    client: TestClient, admin_headers
) -> None:
    """在线调额后，自助查询立即看到新上限。"""
    secret = _issue(client, admin_headers, "alice", 2)
    headers = {"Authorization": f"Bearer {secret}"}
    r = client.put(
        "/admin/keys/quotas/alice", headers=admin_headers, json={"limit": 9}
    )
    assert r.status_code == 200
    body = client.get("/me/quota", headers=headers).json()
    assert body["limit"] == 9 and body["remaining"] == 9


def test_self_query_shows_reset_time_in_window(
    client: TestClient, admin_headers, auth_service
) -> None:
    """窗口重开时刻是未来的明确时间点；窗口过期后按已重开展示。"""
    secret = _issue(client, admin_headers, "alice", 1)
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/data/read", headers=headers).status_code == 200

    body = client.get("/me/quota", headers=headers).json()
    now = auth_service._clock()
    reset_at = datetime.fromisoformat(body["window_reset_at"])
    assert reset_at > now  # 重开时刻在未来，可作为重试依据

    # 推进时间超过窗口：自助查询按有效状态展示（已重开、可用量恢复）
    real_now = auth_service._clock()
    auth_service._clock = lambda: real_now + timedelta(seconds=3601)
    body = client.get("/me/quota", headers=headers).json()
    assert body["used"] == 0
    assert body["remaining"] == body["limit"] == 1


def test_admin_can_query_any_caller(client: TestClient, admin_headers) -> None:
    """管理员走管理接口可查任意调用方（既有行为回归）。"""
    secret = _issue(client, admin_headers, "alice", 2)
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/data/read", headers=headers).status_code == 200
    r = client.get("/admin/keys/quotas/alice", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["used"] == 1 and body["limit"] == 2
