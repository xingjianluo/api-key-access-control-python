"""访问配额：按调用方计量、并发不超限、429 带 Retry-After、窗口重置。"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

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


def _quota_view(client: TestClient, admin_headers, caller_id: str) -> dict:
    r = client.get(f"/admin/keys/quotas/{caller_id}", headers=admin_headers)
    assert r.status_code == 200, r.text
    return r.json()


def test_requests_within_quota_pass(client: TestClient, admin_headers) -> None:
    secret = _issue(client, admin_headers, "alice", 3)
    headers = {"Authorization": f"Bearer {secret}"}
    for i in range(3):
        r = client.get("/data/read", headers=headers)
        assert r.status_code == 200, f"request {i} should pass: {r.text}"
    view = _quota_view(client, admin_headers, "alice")
    assert view["used"] == 3 and view["remaining"] == 0


def test_over_quota_rejected_with_retry_after(
    client: TestClient, admin_headers
) -> None:
    secret = _issue(client, admin_headers, "alice", 2)
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 200

    r = client.get("/data/read", headers=headers)
    assert r.status_code == 429
    detail = r.json()["detail"]
    assert detail["reason"] == "quota_exceeded"
    assert detail["message"] == "访问配额已用尽: 2/2"
    retry_after = int(r.headers["Retry-After"])
    assert 0 < retry_after <= 3600


def test_concurrent_requests_near_limit_never_exceed(
    client: TestClient, admin_headers
) -> None:
    """并发接近限额：恰好 limit 个成功，其余 429，计数绝不突破限额。"""
    limit = 20
    secret = _issue(client, admin_headers, "racer", limit)
    headers = {"Authorization": f"Bearer {secret}"}

    statuses: list[int] = []
    lock = threading.Lock()

    def call() -> None:
        r = client.get("/data/read", headers=headers)
        with lock:
            statuses.append(r.status_code)

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(lambda _: call(), range(50)))

    allowed = [s for s in statuses if s == 200]
    rejected = [s for s in statuses if s == 429]
    assert len(allowed) == limit, f"expected {limit} allowed, got {len(allowed)}"
    assert len(rejected) == 50 - limit
    view = _quota_view(client, admin_headers, "racer")
    assert view["used"] == limit, view


def test_quota_is_isolated_per_caller(
    client: TestClient, admin_headers
) -> None:
    s1 = _issue(client, admin_headers, "tenant-a", 1)
    s2 = _issue(client, admin_headers, "tenant-b", 1)
    h1 = {"Authorization": f"Bearer {s1}"}
    h2 = {"Authorization": f"Bearer {s2}"}
    assert client.get("/data/read", headers=h1).status_code == 200
    assert client.get("/data/read", headers=h1).status_code == 429
    # 另一个调用方不受影响
    assert client.get("/data/read", headers=h2).status_code == 200


def test_denied_requests_do_not_consume_quota(
    client: TestClient, admin_headers
) -> None:
    # read-only 密钥：越权请求不应吃掉配额
    secret = _issue(client, admin_headers, "alice", 2)
    headers = {"Authorization": f"Bearer {secret}"}
    for _ in range(5):
        r = client.post("/data/write", headers=headers)
        assert r.status_code == 403
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 429


def test_admin_calls_do_not_consume_business_quota(
    client: TestClient, admin_headers
) -> None:
    secret = _issue(client, admin_headers, "alice", 1)
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 429
    # 管理员大量查询/操作不影响 alice 的配额状态
    for _ in range(10):
        assert client.get(
            "/admin/keys/quotas/alice", headers=admin_headers
        ).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 429


def test_quota_window_resets_after_window_length(
    client: TestClient, admin_headers, auth_service
) -> None:
    secret = _issue(client, admin_headers, "alice", 1)
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 429

    # 推进时间超过一个窗口
    from datetime import timedelta
    real_now = auth_service._clock()
    auth_service._clock = lambda: real_now + timedelta(seconds=3601)

    r = client.get("/data/read", headers=headers)
    assert r.status_code == 200, r.text
    view = _quota_view(client, admin_headers, "alice")
    assert view["used"] == 1  # 新窗口重新计数


def test_quota_persists_across_restart(
    tmp_path, admin_headers, settings
) -> None:
    """重启延续：耗尽配额后重建 app（重新加载文件），结论必须一致。"""
    from main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app(settings)) as first:
        data_dir = settings.data_dir
        admin_secret = (
            data_dir / settings.admin_secret_file
        ).read_text().strip()
        admin_h = {"Authorization": f"Bearer {admin_secret}"}
        r = first.post(
            "/admin/keys",
            headers=admin_h,
            json={"caller_id": "survivor", "scopes": ["data:read"],
                  "quota_limit": 2},
        )
        secret = r.json()["secret"]
        headers = {"Authorization": f"Bearer {secret}"}
        assert first.get("/data/read", headers=headers).status_code == 200
        assert first.get("/data/read", headers=headers).status_code == 200
        assert first.get("/data/read", headers=headers).status_code == 429

    # 模拟服务重启：同一 data_dir，全新进程式地重新构造应用
    with TestClient(create_app(settings)) as second:
        r = second.get("/data/read", headers=headers)
        assert r.status_code == 429
        assert r.json()["detail"]["reason"] == "quota_exceeded"
        # 管理员引导不重复创建
        r2 = second.get(
            "/admin/keys/quotas/survivor",
            headers={"Authorization": f"Bearer {admin_secret}"},
        )
        assert r2.json()["used"] == 2
