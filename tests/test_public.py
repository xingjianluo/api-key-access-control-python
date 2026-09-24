"""公开接口：启用鉴权后行为与响应契约保持不变。"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_root_public_contract_unchanged(client: TestClient) -> None:
    # 无 Authorization 头，且响应契约与原始骨架一致
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"Hello": "World"}


def test_root_ignores_garbage_authorization(client: TestClient) -> None:
    r = client.get("/", headers={"Authorization": "Bearer not-a-real-key"})
    assert r.status_code == 200
    assert r.json() == {"Hello": "World"}


def test_openapi_still_available(client: TestClient) -> None:
    r = client.get("/openapi.json")
    assert r.status_code == 200
    assert r.json()["info"]["title"] == "API Key Access Control"
