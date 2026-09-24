"""访问配额：限额内放行、超额拒绝、并发不超发、窗口滚动。"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest


@pytest.fixture()
def read_key(client, admin_headers, helpers):
    issued = helpers.issue(
        client, admin_headers, "quota-user", ["items:read"],
        quota_limit=10, quota_window_seconds=60,
    )
    return issued


def test_requests_within_quota_pass(client, read_key, helpers):
    for i in range(10):
        resp = client.get("/items", headers=helpers.bearer(read_key["api_key"]))
        assert resp.status_code == 200, i

    # 第 11 次超额
    resp = client.get("/items", headers=helpers.bearer(read_key["api_key"]))
    assert resp.status_code == 429
    err = resp.json()["error"]
    assert err["reason"] == "quota_exceeded"
    assert err["key_id"] == read_key["key_id"]
    assert int(resp.headers["Retry-After"]) >= 1
    assert err["retry_after"] == int(resp.headers["Retry-After"])


def test_quota_is_per_caller_not_per_key(client, admin_headers, helpers):
    # 同一调用方两把凭证共享配额
    first = helpers.issue(
        client, admin_headers, "shared", ["items:read"],
        quota_limit=2, quota_window_seconds=60,
    )
    second = helpers.issue(
        client, admin_headers, "shared", ["items:read"],
    )
    h1, h2 = helpers.bearer(first["api_key"]), helpers.bearer(second["api_key"])
    assert client.get("/items", headers=h1).status_code == 200
    assert client.get("/items", headers=h2).status_code == 200
    resp = client.get("/items", headers=h1)
    assert resp.status_code == 429


def test_concurrent_requests_never_exceed_limit(client, read_key, helpers):
    """并发接近限额：50 个并发请求抢 10 个名额，成功者必须恰好为 10。"""
    results: list[int] = []
    lock = threading.Lock()

    def fire() -> int:
        r = client.get("/items", headers=helpers.bearer(read_key["api_key"]))
        with lock:
            results.append(r.status_code)
        return r.status_code

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(fire) for _ in range(50)]
        for f in as_completed(futures):
            f.result()

    oks = [s for s in results if s == 200]
    limited = [s for s in results if s == 429]
    assert len(oks) == 10, f"期望恰好 10 个放行，实际 {len(oks)}"
    assert len(limited) == 40
    assert set(results) <= {200, 429}


def test_quota_window_resets(client, read_key, clock, helpers):
    h = helpers.bearer(read_key["api_key"])
    for _ in range(10):
        assert client.get("/items", headers=h).status_code == 200
    assert client.get("/items", headers=h).status_code == 429

    # 窗口结束后恢复满额
    clock.advance(61)
    resp = client.get("/items", headers=h)
    assert resp.status_code == 200


def test_quota_rejected_request_does_not_consume(client, read_key, clock, helpers):
    h = helpers.bearer(read_key["api_key"])
    for _ in range(10):
        client.get("/items", headers=h)
    # 超额请求再多也不应把计数推高或影响窗口滚动
    for _ in range(5):
        assert client.get("/items", headers=h).status_code == 429
    clock.advance(61)
    assert client.get("/items", headers=h).status_code == 200
