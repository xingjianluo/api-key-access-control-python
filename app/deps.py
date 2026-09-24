"""FastAPI 依赖：提取凭证 → 认证 → 范围判定 → 配额扣减。

整条判定路径在 ``Store`` 的进程锁临界区内完成，保证并发下
"认证 + 配额扣减" 原子化。每次判定（无论放行还是拒绝）都会记录
一条结构化日志，包含凭证标识、判定依据与配额计数。
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from fastapi import Depends, Header, Request
from fastapi.responses import JSONResponse

from app.errors import (
    REASON_EXPIRED,
    REASON_FORBIDDEN,
    REASON_INVALID,
    REASON_MISSING,
    REASON_QUOTA,
    REASON_REVOKED,
    AuthError,
    expired_api_key,
    insufficient_scope,
    invalid_api_key,
    missing_api_key,
    quota_exceeded,
    revoked_api_key,
)
from app.models import Principal
from app.quota import QuotaService
from app.scopes import has_scope
from app.security import hash_key, parse_authorization
from app.store import Store

logger = logging.getLogger("app.auth")


class AuthContext:
    """持有存储与配额服务，在应用工厂中装配。"""

    def __init__(
        self,
        store: Store,
        quota: QuotaService,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.quota = quota
        self.clock = clock


def get_context(request: Request) -> AuthContext:
    """FastAPI 依赖：从 app.state 取 AuthContext。"""
    return request.app.state.auth


def _deny(reason: str, key_id: str | None, detail: str, **extra: object) -> None:
    """记录一条拒绝判定日志并抛出对应错误。"""
    logger.info(
        "判定=拒绝 reason=%s key_id=%s 判定依据=%s %s",
        reason,
        key_id or "-",
        detail,
        " ".join(f"{k}={v}" for k, v in extra.items()),
    )


def require_api_key(required_scope: str | None = None) -> Callable[..., Principal]:
    """构造一个依赖：校验 API Key、范围并扣减配额。

    Args:
        required_scope: 该接口所需范围；为 None 时只要求认证通过。
    """

    def dependency(
        request: Request,
        authorization: str | None = Header(default=None),
        ctx: AuthContext = Depends(get_context),
    ) -> Principal:
        token = parse_authorization(authorization)
        if token is None:
            _deny(REASON_MISSING, None, "Authorization 头缺失或非 Bearer 方案")
            raise missing_api_key()

        key_hash = hash_key(token)
        now = ctx.clock()

        # 整段判定放在同一临界区：并发请求串行通过，配额计数不会超发
        with ctx.store.locked():
            found = ctx.store.find_by_hash(key_hash)
            if found is None:
                _deny(REASON_INVALID, None, "密钥哈希未命中任何已保存凭证")
                raise invalid_api_key()
            caller, cred = found

            if cred.revoked:
                _deny(REASON_REVOKED, cred.key_id, "凭证 revoked=True")
                raise revoked_api_key(cred.key_id)

            if cred.expires_at is not None and cred.expires_at <= now:
                _deny(
                    REASON_EXPIRED,
                    cred.key_id,
                    f"expires_at={cred.expires_at} <= now={now:.3f}",
                )
                raise expired_api_key(cred.key_id)

            if required_scope is not None and not has_scope(cred.scopes, required_scope):
                _deny(
                    REASON_FORBIDDEN,
                    cred.key_id,
                    f"缺少范围 required={required_scope} granted={list(cred.scopes)}",
                )
                raise insufficient_scope(
                    cred.key_id, required_scope, cred.scopes
                )

            allowed, used, limit, retry_after = ctx.quota.check_and_consume(caller)
            if not allowed:
                _deny(
                    REASON_QUOTA,
                    cred.key_id,
                    f"固定窗口计数已达限额 quota={used}/{limit}",
                    **{"retry_after": retry_after},
                )
                raise quota_exceeded(cred.key_id, retry_after)

            logger.info(
                "判定=放行 reason=ok key_id=%s caller_id=%s 判定依据=凭证有效且范围满足 "
                "required_scope=%s quota=%d/%d",
                cred.key_id,
                caller.caller_id,
                required_scope or "(none)",
                used,
                limit,
            )
            return Principal(
                caller_id=caller.caller_id,
                key_id=cred.key_id,
                scopes=cred.scopes,
            )

    return dependency


def register_error_handlers(app: object) -> None:
    """在 FastAPI 应用上注册统一的 AuthError → JSON 响应处理。"""

    @app.exception_handler(AuthError)  # type: ignore[attr-defined]
    async def _handle_auth_error(request: Request, exc: AuthError) -> JSONResponse:
        headers: dict[str, str] = {}
        if exc.status_code == 401:
            headers["WWW-Authenticate"] = 'Bearer realm="api-key", charset="UTF-8"'
        if exc.retry_after is not None:
            headers["Retry-After"] = str(exc.retry_after)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "reason": exc.reason,
                    "message": exc.message,
                    "key_id": exc.key_id,
                    "retry_after": exc.retry_after,
                }
            },
            headers=headers,
        )
