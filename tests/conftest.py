"""pytest 公共夹具：临时状态文件、可控时钟、TestClient。"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.server import create_app


class FakeClock:
    """可手动推进的时钟，用于过期与窗口滚动测试。"""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


ADMIN_KEY = "ak_test_admin_0001"


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def state_file(tmp_path: Path) -> Path:
    return tmp_path / "auth_state.json"


@pytest.fixture()
def app(state_file: Path, clock: FakeClock):
    application = create_app(
        state_path=state_file,
        admin_key=ADMIN_KEY,
        clock=clock,
    )
    return application


@pytest.fixture()
def client(app) -> TestClient:
    return TestClient(app)


@pytest.fixture()
def admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


def issue(client: TestClient, headers: dict, caller_id: str, scopes: list[str],
          **extra) -> dict:
    """通过管理接口签发凭证并返回响应 JSON。"""
    payload = {"caller_id": caller_id, "scopes": scopes, **extra}
    resp = client.post("/admin/keys", json=payload, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def bearer(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


@pytest.fixture()
def helpers():
    class H:
        issue = staticmethod(issue)
        bearer = staticmethod(bearer)
    return H
