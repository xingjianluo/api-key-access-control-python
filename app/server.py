"""FastAPI 应用工厂。

路由契约：
- ``GET /``                公开接口，始终返回 ``{"Hello": "World"}``，不鉴权；
- ``GET /items``           需 ``items:read`` 范围；
- ``POST /items``          需 ``items:write`` 范围；
- ``/admin/*``             需 ``admin`` 范围（凭证生命周期管理）。
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path

from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from app.admin import router as admin_router
from app.deps import AuthContext, register_error_handlers, require_api_key
from app.models import Credential, Principal
from app.quota import QuotaService
from app.scopes import SCOPE_ITEMS_READ, SCOPE_ITEMS_WRITE
from app.security import hash_key
from app.store import DEFAULT_QUOTA_LIMIT, DEFAULT_QUOTA_WINDOW_SECONDS, Store

BOOTSTRAP_ADMIN_CALLER = "__bootstrap_admin__"
BOOTSTRAP_ADMIN_KEY_ID = "kid_bootstrap_admin"


class ItemIn(BaseModel):
    name: str = Field(min_length=1)


def seed_bootstrap_admin(ctx: AuthContext, admin_key: str) -> None:
    """将引导用 admin 密钥以哈希形式写入存储（幂等，重启不重复创建）。"""
    key_hash = hash_key(admin_key)
    now = ctx.clock()
    with ctx.store.locked():
        existing = ctx.store.find_by_hash(key_hash)
        if existing is not None:
            return
        credential = Credential(
            key_id=BOOTSTRAP_ADMIN_KEY_ID,
            key_hash=key_hash,
            caller_id=BOOTSTRAP_ADMIN_CALLER,
            scopes=("admin",),
            created_at=now,
            expires_at=None,
        )
        ctx.store.add_credential(
            credential,
            quota_limit=1_000_000,
            quota_window_seconds=3600,
        )


def create_app(
    state_path: str | Path = "data/auth_state.json",
    *,
    admin_key: str | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    """创建并装配 FastAPI 应用。"""
    app = FastAPI(title="API Key Access Control", version="1.0.0")

    store = Store(state_path)
    store.load()
    ctx = AuthContext(store, QuotaService(store, clock=clock), clock=clock)
    app.state.auth = ctx
    app.state.admin_key = admin_key

    if admin_key:
        seed_bootstrap_admin(ctx, admin_key)

    register_error_handlers(app)
    app.include_router(admin_router)

    @app.get("/", tags=["public"])
    def read_root() -> dict[str, str]:
        # 公开接口：启用鉴权后行为与响应契约保持不变
        return {"Hello": "World"}

    @app.get("/items", tags=["protected"])
    def list_items(
        principal: Principal = Depends(require_api_key(SCOPE_ITEMS_READ)),
    ) -> dict[str, list[dict[str, str]]]:
        return {"items": [{"id": "item-1", "name": "demo-item", "owner": principal.caller_id}]}

    @app.post("/items", tags=["protected"])
    def create_item(
        body: ItemIn,
        principal: Principal = Depends(require_api_key(SCOPE_ITEMS_WRITE)),
    ) -> dict[str, str]:
        return {"id": "item-new", "name": body.name, "owner": principal.caller_id}

    return app


def configure_logging() -> None:
    """让单测日志中可见凭证标识、判定依据与配额计数。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
