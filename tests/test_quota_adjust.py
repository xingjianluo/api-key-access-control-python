"""在线调额：调高/调低立即生效、已用量保留、并发不超发不丢计数。"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient


def _issue(client: TestClient, admin_headers, caller_id: str, limit: int) -> str:
    r = client.post(
        "/admin/keys",
        headers=admin_headers,
        json={
            "caller_id": caller_id,
            "scopes": ["data:read"],
            "quota_limit": limit,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["secret"]


def _adjust(client: TestClient, admin_headers, caller_id: str, limit: int):
    return client.put(
        f"/admin/keys/quotas/{caller_id}",
        headers=admin_headers,
        json={"limit": limit},
    )


def _quota_view(client: TestClient, admin_headers, caller_id: str) -> dict:
    r = client.get(f"/admin/keys/quotas/{caller_id}", headers=admin_headers)
    assert r.status_code == 200, r.text
    return r.json()


def test_adjust_limit_up_takes_effect_immediately(
    client: TestClient, admin_headers
) -> None:
    """调高：耗尽后调大上限，无需重启即可继续放行，已用量保留。"""
    secret = _issue(client, admin_headers, "alice", 2)
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 429

    r = _adjust(client, admin_headers, "alice", 4)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["limit"] == 4
    assert body["used"] == 2  # 已用量保留，不被清零

    # 立即生效：还能再走 2 个（4 - 2），随后继续 429
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 429
    view = _quota_view(client, admin_headers, "alice")
    assert view["used"] == 4 and view["limit"] == 4


def test_adjust_limit_down_below_used_keeps_rejecting(
    client: TestClient, admin_headers
) -> None:
    """调低到已用量之下：继续按超额拒绝并给出 Retry-After，已用量不清零。"""
    secret = _issue(client, admin_headers, "alice", 5)
    headers = {"Authorization": f"Bearer {secret}"}
    for _ in range(3):
        assert client.get("/data/read", headers=headers).status_code == 200

    r = _adjust(client, admin_headers, "alice", 2)
    assert r.status_code == 200, r.text
    assert r.json()["used"] == 3  # 已用量保留

    r = client.get("/data/read", headers=headers)
    assert r.status_code == 429
    assert r.json()["detail"]["reason"] == "quota_exceeded"
    retry_after = int(r.headers["Retry-After"])
    assert 0 < retry_after <= 3600  # 明确的重试时间依据：当前窗口剩余秒数

    # 计数没有被调额清零
    view = _quota_view(client, admin_headers, "alice")
    assert view["used"] == 3 and view["limit"] == 2


def test_adjust_limit_down_above_used_allows_remainder(
    client: TestClient, admin_headers
) -> None:
    """调低但仍高于已用量：剩余额度立即按新上限计算。"""
    secret = _issue(client, admin_headers, "alice", 5)
    headers = {"Authorization": f"Bearer {secret}"}
    for _ in range(3):
        assert client.get("/data/read", headers=headers).status_code == 200

    assert _adjust(client, admin_headers, "alice", 4).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 200  # 第 4 个
    assert client.get("/data/read", headers=headers).status_code == 429


def test_adjust_limit_persists_across_restart(tmp_path, settings) -> None:
    """调额结果落盘，重启后新上限与已用量都延续。"""
    from main import create_app

    with TestClient(create_app(settings)) as first:
        admin_secret = (
            settings.data_dir / settings.admin_secret_file
        ).read_text().strip()
        admin_h = {"Authorization": f"Bearer {admin_secret}"}
        secret = _issue(first, admin_h, "survivor", 2)
        headers = {"Authorization": f"Bearer {secret}"}
        assert first.get("/data/read", headers=headers).status_code == 200
        assert _adjust(first, admin_h, "survivor", 3).status_code == 200

    with TestClient(create_app(settings)) as second:
        headers_view = _quota_view(second, admin_h, "survivor")
        assert headers_view["limit"] == 3
        assert headers_view["used"] == 1
        # 新上限下还能走 2 个
        assert second.get("/data/read", headers=headers).status_code == 200
        assert second.get("/data/read", headers=headers).status_code == 200
        assert second.get("/data/read", headers=headers).status_code == 429


def test_adjust_unknown_caller_returns_404(
    client: TestClient, admin_headers
) -> None:
    r = _adjust(client, admin_headers, "nobody", 10)
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "unknown_caller_id"


def test_adjust_requires_admin_scope(client: TestClient, admin_headers) -> None:
    secret = _issue(client, admin_headers, "alice", 2)
    r = client.put(
        "/admin/keys/quotas/alice",
        headers={"Authorization": f"Bearer {secret}"},
        json={"limit": 9},
    )
    assert r.status_code == 403
    r = client.put("/admin/keys/quotas/alice", json={"limit": 9})
    assert r.status_code == 401


def test_adjust_rejects_invalid_limit(client: TestClient, admin_headers) -> None:
    _issue(client, admin_headers, "alice", 2)
    r = _adjust(client, admin_headers, "alice", 0)
    assert r.status_code == 422


def test_adjust_concurrent_with_traffic_no_overissue_no_loss(
    client: TestClient, admin_headers
) -> None:
    """调额与业务请求并发：不超发、不丢计数。

    初始上限 5，并发 30 个业务请求 + 1 次调高到 15：
    无论调额落在哪个时点，放行总数都不超过最终上限 15，
    且最终持久化计数恰好等于放行总数（一个都不丢）。
    """
    secret = _issue(client, admin_headers, "racer", 5)
    headers = {"Authorization": f"Bearer {secret}"}

    statuses: list[int] = []
    lock = threading.Lock()

    def call() -> None:
        r = client.get("/data/read", headers=headers)
        with lock:
            statuses.append(r.status_code)

    def adjust() -> None:
        r = _adjust(client, admin_headers, "racer", 15)
        assert r.status_code == 200, r.text

    with ThreadPoolExecutor(max_workers=11) as pool:
        futures = [pool.submit(call) for _ in range(30)]
        futures.append(pool.submit(adjust))
        for f in futures:
            f.result()

    allowed = len([s for s in statuses if s == 200])
    rejected = len([s for s in statuses if s == 429])
    assert allowed + rejected == 30
    assert allowed <= 15, f"over-issued: {allowed} > final limit 15"
    view = _quota_view(client, admin_headers, "racer")
    assert view["limit"] == 15
    assert view["used"] == allowed, (
        f"lost counts: persisted used={view['used']} != allowed={allowed}"
    )


def test_concurrent_adjusts_keep_count_and_converge(
    client: TestClient, admin_headers
) -> None:
    """多个调额并发：最终上限收敛为其中之一，已用量不丢不变。"""
    secret = _issue(client, admin_headers, "racer", 5)
    headers = {"Authorization": f"Bearer {secret}"}
    for _ in range(3):
        assert client.get("/data/read", headers=headers).status_code == 200

    candidates = [10, 20, 30]

    def adjust(limit: int) -> None:
        r = _adjust(client, admin_headers, "racer", limit)
        assert r.status_code == 200, r.text

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(adjust, candidates))

    view = _quota_view(client, admin_headers, "racer")
    assert view["limit"] in candidates
    assert view["used"] == 3  # 已用量不受调额影响
