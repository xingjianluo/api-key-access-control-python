"""真实 HTTP 服务（uvicorn 线程模式）下的并发配额验证。

与 TestClient 互补：请求经由真实网络栈与服务端工作线程进入锁临界区。
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest

pytest.importorskip("uvicorn")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def _running_server(state_file: Path, admin_key: str):
    import uvicorn

    from app.server import create_app

    config = uvicorn.Config(
        create_app(state_path=state_file, admin_key=admin_key),
        host="127.0.0.1",
        port=_free_port(),
        log_level="warning",
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # 等待端口就绪
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{config.port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_real_server_concurrent_quota(tmp_path):
    from tests.conftest import ADMIN_KEY

    state = tmp_path / "state.json"
    with _running_server(state, ADMIN_KEY) as base:
        with httpx.Client(base_url=base, timeout=10) as http:
            issued = http.post(
                "/admin/keys",
                json={
                    "caller_id": "http-race",
                    "scopes": ["items:read"],
                    "quota_limit": 25,
                    "quota_window_seconds": 3600,
                },
                headers={"Authorization": f"Bearer {ADMIN_KEY}"},
            ).json()
            key = issued["api_key"]

            def fire() -> int:
                return http.get("/items", headers={"Authorization": f"Bearer {key}"}).status_code

            with ThreadPoolExecutor(max_workers=20) as pool:
                statuses = [f.result() for f in [pool.submit(fire) for _ in range(100)]]

            assert statuses.count(200) == 25
            assert statuses.count(429) == 75

            # Retry-After 头必须在真实 HTTP 响应中可见
            rejected = httpx.get(
                base + "/items", headers={"Authorization": f"Bearer {key}"}, timeout=10
            )
            assert rejected.status_code == 429
            assert int(rejected.headers["Retry-After"]) > 0
