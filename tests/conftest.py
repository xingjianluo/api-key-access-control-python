"""测试公共夹具：每个用例使用独立数据目录，互不污染。"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from main import create_app


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        default_quota_limit=3,
        default_quota_window_seconds=3600,
        default_key_ttl_seconds=None,
        admin_caller_id="admin",
        admin_secret_file="admin_initial_key.txt",
    )


@pytest.fixture()
def client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def admin_headers(client: TestClient, settings: Settings) -> dict[str, str]:
    secret_file = settings.data_dir / settings.admin_secret_file
    secret = secret_file.read_text(encoding="utf-8").strip()
    return {"Authorization": f"Bearer {secret}"}


@pytest.fixture()
def auth_service(client: TestClient):
    return client.app.state.auth_service
