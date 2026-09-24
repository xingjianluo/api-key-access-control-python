"""FastAPI 依赖与异常映射。

- 未认证类失败（缺失/无效/吊销/过期）-> 401，``WWW-Authenticate`` 说明原因；
- 已认证但越权 -> 403；
- 配额耗尽 -> 429，``Retry-After`` 给出明确重试秒数。
"""

from __future__ import annotations

from fastapi import Depends, Header, Request

from app.config import Settings
from app.models import FailReason, Principal
from app.service import AuthError, AuthService
from app.storage import JsonStore

_UNAUTHENTICATED = {
    FailReason.MISSING_KEY,
    FailReason.INVALID_KEY,
    FailReason.REVOKED_KEY,
    FailReason.EXPIRED_KEY,
}


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def extract_bearer(authorization: str | None) -> str | None:
    """从 ``Authorization: Bearer <key>`` 中提取明文密钥。"""
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return None
    return parts[1].strip()


def require_scope(required_scope: str | None, *, consume_quota: bool = True):
    """生成一个校验指定 scope（可选）并按调用方计配额的依赖。"""

    def dependency(
        service: AuthService = Depends(get_service),
        authorization: str | None = Header(default=None),
    ) -> Principal:
        secret = extract_bearer(authorization)
        try:
            return service.authenticate(
                secret,
                required_scope,
                consume_quota=consume_quota,
            )
        except AuthError as error:
            raise _to_http(error)

    return dependency


def _to_http(error: AuthError) -> Exception:
    # 延迟导入，避免模块加载循环
    from fastapi import HTTPException

    headers: dict[str, str] = {}
    if error.reason in _UNAUTHENTICATED:
        status_code = 401
        headers["WWW-Authenticate"] = (
            f'Bearer realm="api", error="{error.reason.value}"'
        )
    elif error.reason is FailReason.INSUFFICIENT_SCOPE:
        status_code = 403
        headers["WWW-Authenticate"] = (
            f'Bearer realm="api", error="insufficient_scope"'
        )
    else:  # QUOTA_EXCEEDED
        status_code = 429
        if error.retry_after_seconds is not None:
            headers["Retry-After"] = str(error.retry_after_seconds)

    return HTTPException(
        status_code=status_code,
        detail={"reason": error.reason.value, "message": error.detail},
        headers=headers,
    )


def build_service(settings: Settings) -> AuthService:
    """构造服务并完成首次启动引导（管理员凭证）。"""
    service = AuthService(settings, JsonStore(settings.data_dir))
    service.bootstrap_admin()
    return service
