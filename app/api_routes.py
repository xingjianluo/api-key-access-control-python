"""业务接口。

- ``GET /``        公开接口，启用鉴权后行为与响应契约保持不变；
- ``GET /me``      仅需有效凭证，不要求具体 scope，返回调用方信息；
- ``GET /data/read``  需要 ``data:read`` 范围；
- ``POST /data/write`` 需要 ``data:write`` 范围。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.deps import require_scope
from app.models import Principal
from app.service import AuthService
from app.deps import get_service

router = APIRouter(tags=["api"])


@router.get("/")
def read_root() -> dict:
    """公开接口：无需鉴权，响应契约保持不变。"""
    return {"Hello": "World"}


@router.get("/me")
def me_endpoint(principal: Principal = Depends(require_scope(None))) -> dict:
    return {
        "caller_id": principal.caller_id,
        "key_id": principal.key_id,
        "scopes": sorted(principal.scopes),
    }


@router.get("/me/quota")
def my_quota_endpoint(
    principal: Principal = Depends(require_scope(None, consume_quota=False)),
    service: AuthService = Depends(get_service),
) -> dict:
    """调用方自助查询自己的配额使用情况。

    只需有效凭证，不要求具体 scope，也不消耗业务配额。
    """
    view = service.describe_quota(principal.caller_id)
    if view is None:  # 理论上不会发生：凭证签发时即初始化配额
        return {"caller_id": principal.caller_id, "found": False}
    return {
        "caller_id": view.caller_id,
        "found": True,
        "limit": view.limit,
        "used": view.used,
        "remaining": view.remaining,
        "window_start": view.window_start.isoformat(),
        "window_reset_at": view.window_reset_at.isoformat(),
    }


@router.get("/data/read")
def read_data_endpoint(
    principal: Principal = Depends(require_scope("data:read")),
) -> dict:
    return {"data": "sample-read", "caller_id": principal.caller_id}


@router.post("/data/write")
def write_data_endpoint(
    principal: Principal = Depends(require_scope("data:write")),
) -> dict:
    return {"written": True, "caller_id": principal.caller_id}
