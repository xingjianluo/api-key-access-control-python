"""固定窗口边界：清零与起点更新一起生效，并发请求恰好落入一个窗口。"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

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


def _quota_view(client: TestClient, admin_headers, caller_id: str) -> dict:
    r = client.get(f"/admin/keys/quotas/{caller_id}", headers=admin_headers)
    assert r.status_code == 200, r.text
    return r.json()


def _fire_concurrently(client: TestClient, headers: dict, n: int) -> list[int]:
    statuses: list[int] = []
    lock = threading.Lock()

    def call() -> None:
        r = client.get("/data/read", headers=headers)
        with lock:
            statuses.append(r.status_code)

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(lambda _: call(), range(n)))
    return statuses


def test_concurrent_requests_just_before_boundary_stay_in_old_window(
    client: TestClient, admin_headers, auth_service
) -> None:
    """边界前并发：全部落入旧窗口，放行数恰好等于剩余额度。"""
    secret = _issue(client, admin_headers, "alice", 5)
    headers = {"Authorization": f"Bearer {secret}"}
    for _ in range(3):
        assert client.get("/data/read", headers=headers).status_code == 200

    # 冻结时间在窗口结束前 1 秒
    t0 = auth_service._clock()
    auth_service._clock = lambda: t0 + timedelta(seconds=3599)

    statuses = _fire_concurrently(client, headers, 10)
    assert len([s for s in statuses if s == 200]) == 2  # 剩余额度 5-3=2
    assert len([s for s in statuses if s == 429]) == 8
    view = _quota_view(client, admin_headers, "alice")
    assert view["used"] == 5
    assert datetime.fromisoformat(view["window_start"]) <= t0


def test_concurrent_requests_at_boundary_land_in_new_window(
    client: TestClient, admin_headers, auth_service
) -> None:
    """边界上并发：恰好触发一次重开，全部落入新窗口，放行数等于上限。"""
    secret = _issue(client, admin_headers, "alice", 5)
    headers = {"Authorization": f"Bearer {secret}"}
    for _ in range(5):
        assert client.get("/data/read", headers=headers).status_code == 200

    t0 = auth_service._clock()
    boundary = t0 + timedelta(seconds=3600)
    auth_service._clock = lambda: boundary

    statuses = _fire_concurrently(client, headers, 20)
    assert len([s for s in statuses if s == 200]) == 5
    assert len([s for s in statuses if s == 429]) == 15
    view = _quota_view(client, admin_headers, "alice")
    # 清零与起点更新一起生效：新起点 + 新计数，无撕裂状态
    assert datetime.fromisoformat(view["window_start"]) == boundary
    assert view["used"] == 5


def test_concurrent_requests_straddling_boundary_counted_exactly_once(
    client: TestClient, admin_headers, auth_service, settings
) -> None:
    """边界前后混合并发：每个请求落入恰好一个窗口，不漏记不重复计。

    用可替换时钟给 20 个并发请求分配确定的时间戳序列：
    前 5 个落在旧窗口最后 1 秒（剩余额度 2），后 15 个落在新窗口
    （上限 5）。无论线程调度顺序如何，结果必须确定：
    旧窗口再放行 2 个，新窗口放行 5 个，其余 429。
    """
    secret = _issue(client, admin_headers, "alice", 5)
    headers = {"Authorization": f"Bearer {secret}"}
    for _ in range(3):
        assert client.get("/data/read", headers=headers).status_code == 200

    t0 = auth_service._clock()
    before = t0 + timedelta(seconds=3599)
    after = t0 + timedelta(seconds=3600)
    timeline = [before] * 5 + [after] * 15
    pop_lock = threading.Lock()
    index = {"i": 0}

    def fake_clock() -> datetime:
        with pop_lock:
            i = min(index["i"], len(timeline) - 1)
            index["i"] += 1
        return timeline[i]

    auth_service._clock = fake_clock

    statuses = _fire_concurrently(client, headers, 20)
    assert len([s for s in statuses if s == 200]) == 2 + 5
    assert len([s for s in statuses if s == 429]) == 3 + 10

    # 每个请求恰好计入一个窗口：旧窗口 3+2=5，新窗口 5，无人漏记/重复
    view = _quota_view(client, admin_headers, "alice")
    assert datetime.fromisoformat(view["window_start"]) == after
    assert view["used"] == 5

    # 落盘状态同样无撕裂：起点与计数同属新窗口
    raw = json.loads((settings.data_dir / "quotas.json").read_text())
    persisted = raw["alice"]
    assert datetime.fromisoformat(persisted["window_start"]) == after
    assert persisted["count"] == 5


def test_retry_after_points_to_window_reset_at_boundary(
    client: TestClient, admin_headers, auth_service
) -> None:
    """边界前最后一秒超额：Retry-After 指向窗口重开时刻。"""
    secret = _issue(client, admin_headers, "alice", 1)
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/data/read", headers=headers).status_code == 200

    t0 = auth_service._clock()
    auth_service._clock = lambda: t0 + timedelta(seconds=3599)
    r = client.get("/data/read", headers=headers)
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) == 1
