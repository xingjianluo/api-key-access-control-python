"""FastAPI 应用入口。

启动时从环境变量加载配置，构造 :class:`AuthService` 并完成管理员凭证引导。
全部状态保存在本地 ``AUTH_DATA_DIR``（默认 ``./data``）下的 JSON 文件中。
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.admin_routes import router as admin_router
from app.api_routes import router as api_router
from app.config import Settings
from app.deps import build_service


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    app = FastAPI(title="API Key Access Control", version="0.1.0")
    app.state.settings = settings
    app.state.auth_service = build_service(settings)

    app.include_router(api_router)
    app.include_router(admin_router)

    @app.exception_handler(KeyError)
    async def unknown_key_id_handler(request: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"reason": "unknown_key_id", "message": str(exc).strip("'\"")},
        )

    return app


app = create_app()
