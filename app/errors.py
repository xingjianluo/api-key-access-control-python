"""可区分的鉴权 / 授权 / 配额失败类型。

每种失败都有独立的 ``reason`` 代码，调用方可以据此区分：
``missing_api_key`` / ``invalid_api_key`` / ``revoked_api_key`` /
``expired_api_key`` / ``insufficient_scope`` / ``quota_exceeded``。
"""

from __future__ import annotations

#: 未提供 API Key
REASON_MISSING = "missing_api_key"
#: API Key 无法识别（哈希未命中任何凭证）
REASON_INVALID = "invalid_api_key"
#: 凭证已被吊销
REASON_REVOKED = "revoked_api_key"
#: 凭证已过有效期
REASON_EXPIRED = "expired_api_key"
#: 已认证但缺少必要权限范围（403，与 401 未认证区分）
REASON_FORBIDDEN = "insufficient_scope"
#: 调用方本窗口配额已耗尽（429，携带 Retry-After）
REASON_QUOTA = "quota_exceeded"
#: 请求参数不合法（400），例如签发了未知权限范围
REASON_BAD_REQUEST = "bad_request"


class AuthError(Exception):
    """鉴权、授权或配额判定失败。

    Attributes:
        reason: 机器可判定的失败原因代码。
        status_code: 对应的 HTTP 状态码。
        message: 面向调用方的说明。
        key_id: 涉及的凭证标识（若有），用于日志与响应可解释性。
        retry_after: 仅配额耗尽时给出，建议重试秒数。
    """

    def __init__(
        self,
        reason: str,
        status_code: int,
        message: str,
        *,
        key_id: str | None = None,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.status_code = status_code
        self.message = message
        self.key_id = key_id
        self.retry_after = retry_after


def missing_api_key() -> AuthError:
    return AuthError(
        REASON_MISSING,
        401,
        "缺少 API Key：请在 Authorization 头中提供 'Bearer <api_key>'。",
    )


def invalid_api_key(key_id: str | None = None) -> AuthError:
    return AuthError(
        REASON_INVALID,
        401,
        "API Key 无效：凭证不存在或无法识别。",
        key_id=key_id,
    )


def revoked_api_key(key_id: str) -> AuthError:
    return AuthError(
        REASON_REVOKED,
        401,
        "API Key 已被吊销，请申请新的凭证。",
        key_id=key_id,
    )


def expired_api_key(key_id: str) -> AuthError:
    return AuthError(
        REASON_EXPIRED,
        401,
        "API Key 已过期，请轮换或申请新的凭证。",
        key_id=key_id,
    )


def insufficient_scope(
    key_id: str, required: str, granted: tuple[str, ...]
) -> AuthError:
    granted_text = ", ".join(granted) if granted else "(无)"
    return AuthError(
        REASON_FORBIDDEN,
        403,
        f"权限不足：该操作需要范围 '{required}'，当前凭证范围为 {granted_text}。",
        key_id=key_id,
    )


def quota_exceeded(key_id: str, retry_after: int) -> AuthError:
    return AuthError(
        REASON_QUOTA,
        429,
        f"访问配额已耗尽，请在 {retry_after} 秒后重试。",
        key_id=key_id,
        retry_after=retry_after,
    )


def bad_request(message: str) -> AuthError:
    return AuthError(REASON_BAD_REQUEST, 400, message)
