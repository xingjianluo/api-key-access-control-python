"""在线调额、调用方自助查询、窗口边界并发语义的测试。"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

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


def _adjust(client: TestClient, admin_headers, caller_id: str, limit: int) -> dict:
    r = client.put(
        f"/admin/keys/quotas/{caller_id}",
        headers=admin_headers,
        json={"limit": limit},
    )
    assert r.status_code == 200, r.text
    return r.json()


def _quota_view(client: TestClient, admin_headers, caller_id: str) -> dict:
    r = client.get(f"/admin/keys/quotas/{caller_id}", headers=admin_headers)
    assert r.status_code == 200, r.text
    return r.json()


# ---------- 在线调额 ----------

def test_adjust_limit_up_takes_effect_immediately(
    client: TestClient, admin_headers
) -> None:
    """调高立即生效，已用量保留，不清零。"""
    secret = _issue(client, admin_headers, "alice", 2)
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 429

    view = _adjust(client, admin_headers, "alice", 4)
    assert view["limit"] == 4
    assert view["used"] == 2  # 已用量保留
    assert view["remaining"] == 2

    # 新上限立即生效：还能再放行恰好 2 个
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 429
    assert _quota_view(client, admin_headers, "alice")["used"] == 4


def test_adjust_limit_down_below_used_rejects_with_retry_after(
    client: TestClient, admin_headers
) -> None:
    """调低到低于已用量：后续请求继续按超额拒绝，并给出重试时间依据。"""
    secret = _issue(client, admin_headers, "alice", 5)
    headers = {"Authorization": f"Bearer {secret}"}
    for _ in range(4):
        assert client.get("/data/read", headers=headers).status_code == 200

    view = _adjust(client, admin_headers, "alice", 2)
    assert view["limit"] == 2
    assert view["used"] == 4  # 已消耗量不因调额被清零
    assert view["remaining"] == 0

    r = client.get("/data/read", headers=headers)
    assert r.status_code == 429
    assert r.json()["detail"]["reason"] == "quota_exceeded"
    retry_after = int(r.headers["Retry-After"])
    assert 0 < retry_after <= 3600


def test_adjust_unknown_caller_is_404(client: TestClient, admin_headers) -> None:
    r = client.put(
        "/admin/keys/quotas/ghost", headers=admin_headers, json={"limit": 5}
    )
    assert r.status_code == 404


def test_adjust_requires_admin_scope(client: TestClient, admin_headers) -> None:
    secret = _issue(client, admin_headers, "alice", 5)
    user_headers = {"Authorization": f"Bearer {secret}"}
    # 无凭证 -> 401；普通调用方 -> 403，均不能调额
    assert client.put(
        "/admin/keys/quotas/alice", json={"limit": 9}
    ).status_code == 401
    assert client.put(
        "/admin/keys/quotas/alice", headers=user_headers, json={"limit": 9}
    ).status_code == 403
    assert _quota_view(client, admin_headers, "alice")["limit"] == 5


def test_concurrent_adjust_and_traffic_no_overissue_no_lost_count(
    client: TestClient, admin_headers
) -> None:
    """调额与业务请求并发：不超发、不丢计数，最终计数与放行数严格相等。"""
    secret = _issue(client, admin_headers, "racer", 5)
    headers = {"Authorization": f"Bearer {secret}"}

    statuses: list[int] = []
    lock = threading.Lock()

    def call() -> None:
        r = client.get("/data/read", headers=headers)
        with lock:
            statuses.append(r.status_code)

    def adjust() -> None:
        for limit in (10, 20, 40):
            _adjust(client, admin_headers, "racer", limit)

    with ThreadPoolExecutor(max_workers=9) as pool:
        futures = [pool.submit(call) for _ in range(40)]
        futures.append(pool.submit(adjust))
        for f in futures:
            f.result()

    allowed = statuses.count(200)
    rejected = statuses.count(429)
    assert allowed + rejected == 40
    assert allowed >= 5  # 至少按初始上限放行
    assert allowed <= 40  # 绝不突破最终上限
    view = _quota_view(client, admin_headers, "racer")
    assert view["limit"] == 40
    assert view["used"] == allowed  # 每个 200 恰好计数一次，不丢不重


def test_concurrent_adjusts_are_serialized(
    client: TestClient, admin_headers
) -> None:
    """多个调额并发：结果必为其中之一，已用量不受影响。"""
    _issue(client, admin_headers, "multi", 5)
    limits = [10, 20, 30, 40, 50]
    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(
            lambda limit: _adjust(client, admin_headers, "multi", limit), limits
        ))
    view = _quota_view(client, admin_headers, "multi")
    assert view["limit"] in limits
    assert view["used"] == 0


# ---------- 调用方自助查询 ----------

def test_self_quota_query_without_admin_scope(
    client: TestClient, admin_headers
) -> None:
    """普通调用方凭自己的凭证即可查询，且查询不消耗业务配额。"""
    secret = _issue(client, admin_headers, "selfie", 2)
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/data/read", headers=headers).status_code == 200

    r = client.get("/me/quota", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["caller_id"] == "selfie"
    assert body["limit"] == 2
    assert body["used"] == 1
    assert body["remaining"] == 1
    reset_at = datetime.fromisoformat(body["window_reset_at"])
    window_start = datetime.fromisoformat(body["window_start"])
    assert reset_at == window_start + timedelta(seconds=3600)
    assert 0 < body["retry_after_seconds"] <= 3600

    # 反复查询不占用配额：剩余 1 次业务请求仍放行
    for _ in range(5):
        assert client.get("/me/quota", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 429
    # 超额后自助查询依然可用（查询本身不受限额影响）
    r = client.get("/me/quota", headers=headers)
    assert r.status_code == 200
    assert r.json()["used"] == 2


def test_self_quota_query_requires_valid_credential(client: TestClient) -> None:
    assert client.get("/me/quota").status_code == 401
    r = client.get("/me/quota", headers={"Authorization": "Bearer ak_bad"})
    assert r.status_code == 401


def test_admin_can_query_any_caller_with_reset_time(
    client: TestClient, admin_headers
) -> None:
    secret = _issue(client, admin_headers, "bob", 5)
    headers = {"Authorization": f"Bearer {secret}"}
    assert client.get("/data/read", headers=headers).status_code == 200
    view = _quota_view(client, admin_headers, "bob")
    assert view["found"] is True
    assert view["used"] == 1 and view["limit"] == 5 and view["remaining"] == 4
    assert "window_reset_at" in view


# ---------- 窗口边界并发 ----------

class _FlipClock:
    """前 ``flip_after`` 次调用返回 t0，之后返回 t0 + delta（线程安全）。"""

    def __init__(self, t0: datetime, flip_after: int, delta: timedelta) -> None:
        self._t0 = t0
        self._delta = delta
        self.flip_after = flip_after
        self._calls = 0
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            self._calls += 1
            n = self._calls
        return self._t0 if n <= self.flip_after else self._t0 + self._delta


def test_window_boundary_concurrent_requests_land_in_exactly_one_window(
    client: TestClient, admin_headers, auth_service
) -> None:
    """窗口切换瞬间并发：每个请求恰好落入一个窗口，不漏记也不重复计入。

    场景：上限 3，旧窗口已用 2。6 个并发请求中 3 个看到边界前、
    3 个看到边界后。期望：旧窗口再放行 1 个，新窗口放行 3 个，
    共 4 个 200、2 个 429；落盘状态为新窗口 used=3。
    """
    secret = _issue(client, admin_headers, "edge", 3)
    headers = {"Authorization": f"Bearer {secret}"}

    t0 = datetime.now(timezone.utc)
    clock = _FlipClock(t0, flip_after=10**9, delta=timedelta(seconds=3601))
    auth_service._clock = clock

    # 旧窗口先消耗 2 次
    assert client.get("/data/read", headers=headers).status_code == 200
    assert client.get("/data/read", headers=headers).status_code == 200
    old_start = datetime.fromisoformat(
        _quota_view(client, admin_headers, "edge")["window_start"]
    )

    # 接下来 3 次取时仍在旧窗口，再之后跳到下一个窗口
    clock.flip_after = clock._calls + 3

    statuses: list[int] = []
    lock = threading.Lock()

    def call() -> None:
        r = client.get("/data/read", headers=headers)
        with lock:
            statuses.append(r.status_code)

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda _: call(), range(6)))

    allowed = statuses.count(200)
    rejected = statuses.count(429)
    assert allowed + rejected == 6  # 无请求丢失
    assert allowed == 4  # 旧窗口 1 个 + 新窗口 3 个
    assert rejected == 2

    # 清零与窗口起点更新一起生效：落盘为新窗口状态，used=3
    view = _quota_view(client, admin_headers, "edge")
    assert view["used"] == 3
    assert view["limit"] == 3
    new_start = datetime.fromisoformat(view["window_start"])
    assert new_start == old_start + timedelta(seconds=3600)
    # 新窗口已用(3) + 旧窗口本次放行(1) == 总放行(4)：无重复计入
    assert view["used"] + 1 == allowed
