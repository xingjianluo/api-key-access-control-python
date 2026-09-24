"""管理端路由：API Key 的签发、轮换、吊销与查询。

所有管理接口都需要 ``admin`` 范围；密钥明文仅在签发 / 轮换的响应中
返回一次，之后只能凭 key_id 管理。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.deps import AuthContext, get_context, require_api_key
from app.errors import bad_request, invalid_api_key
from app.models import Credential, Principal
from app.scopes import KNOWN_SCOPES
from app.security import generate_key, hash_key
from app.store import DEFAULT_QUOTA_LIMIT, DEFAULT_QUOTA_WINDOW_SECONDS

router = APIRouter(prefix="/admin", tags=["admin"])


# ----------------------------------------------------------------------
# 请求 / 响应模型
# ----------------------------------------------------------------------
class IssueRequest(BaseModel):
    caller_id: str = Field(min_length=1)
    scopes: list[str] = Field(default_factory=list)
    expires_in_seconds: int | None = Field(default=None, gt=0)
    quota_limit: int = Field(default=DEFAULT_QUOTA_LIMIT, gt=0)
    quota_window_seconds: int = Field(default=DEFAULT_QUOTA_WINDOW_SECONDS, gt=0)


class RotateRequest(BaseModel):
    caller_id: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    expires_in_seconds: int | None = Field(default=None, gt=0)


class RevokeRequest(BaseModel):
    caller_id: str = Field(min_length=1)
    key_id: str = Field(min_length=1)


# ----------------------------------------------------------------------
# 服务函数（不经过 HTTP，供引导与测试复用）
# ----------------------------------------------------------------------
# ----------------------------------------------------------------------
# 服务函数（不经过 HTTP，供引导与测试复用）
# ----------------------------------------------------------------------
def _validate_scopes(scopes: list[str]) -> tuple[str, ...]:
    unknown = [s for s in scopes if s not in KNOWN_SCOPES]
    if unknown:
        raise invalid_api_key()  # 占位，下面替换为 ValueError
    return tuple(sorted(set(scopes)))


def issue_credential(
    ctx: AuthContext,
    caller_id: str,
    scopes: list[str],
    *,
    expires_in_seconds: int | None = None,
    quota_limit: int = DEFAULT_QUOTA_LIMIT,
    quota_window_seconds: int = DEFAULT_QUOTA_WINDOW_SECONDS,
) -> dict:
    """生成明文密钥、哈希落盘，返回一次性明文与凭证元数据。"""
    unknown = [s for s in scopes if s not in KNOWN_SCOPES]
    if unknown:
        raise bad_request(
            f"未知的权限范围: {unknown}，合法范围: {sorted(KNOWN_SCOPES)}"
        )

    api_key, key_id = generate_key()
    now = ctx.clock()
    credential = Credential(
        key_id=key_id,
        key_hash=hash_key(api_key),
        caller_id=caller_id,
        scopes=tuple(sorted(set(scopes))),
        created_at=now,
        expires_at=(now + expires_in_seconds) if expires_in_seconds else None,
    )
    with ctx.store.locked():
        caller = ctx.store.add_credential(
            credential,
            quota_limit=quota_limit,
            quota_window_seconds=quota_window_seconds,
        )
    return {
        "api_key": api_key,  # 明文只在此响应中出现一次
        "key_id": key_id,
        "caller_id": caller_id,
        "scopes": list(credential.scopes),
        "created_at": now,
        "expires_at": credential.expires_at,
        "quota_limit": caller.quota_limit,
        "quota_window_seconds": caller.quota_window_seconds,
    }


def rotate_credential(
    ctx: AuthContext,
    caller_id: str,
    old_key_id: str,
    *,
    expires_in_seconds: int | None = None,
) -> dict:
    """吊销旧凭证并签发等价新凭证（范围一致、配额计数保留）。"""
    old = ctx.store.get_credential(caller_id, old_key_id)
    if old is None:
        raise KeyError((caller_id, old_key_id))
    api_key, key_id = generate_key()
    now = ctx.clock()
    new_credential = Credential(
        key_id=key_id,
        key_hash=hash_key(api_key),
        caller_id=caller_id,
        scopes=old.scopes,
        created_at=now,
        expires_at=(now + expires_in_seconds) if expires_in_seconds else None,
    )
    with ctx.store.locked():
        ctx.store.rotate_credential(caller_id, old_key_id, new_credential)
    return {
        "api_key": api_key,
        "key_id": key_id,
        "caller_id": caller_id,
        "scopes": list(old.scopes),
        "created_at": now,
        "expires_at": new_credential.expires_at,
        "rotated_from": old_key_id,
    }


def revoke_credential(ctx: AuthContext, caller_id: str, key_id: str) -> dict:
    with ctx.store.locked():
        changed = ctx.store.revoke_credential(caller_id, key_id)
    return {"caller_id": caller_id, "key_id": key_id, "revoked": True, "changed": changed}


def describe_callers(ctx: AuthContext) -> dict:
    now = ctx.clock()
    callers = []
    for caller in ctx.store.list_callers():
        window_reset = caller.quota_window_start + caller.quota_window_seconds
        callers.append({
            "caller_id": caller.caller_id,
            "quota": {
                "limit": caller.quota_limit,
                "used": caller.quota_used,
                "window_seconds": caller.quota_window_seconds,
                "window_start": caller.quota_window_start,
                "window_resets_at": window_reset,
                "window_active": now < window_reset,
            },
            "credentials": [
                {
                    "key_id": cred.key_id,
                    "scopes": list(cred.scopes),
                    "created_at": cred.created_at,
                    "expires_at": cred.expires_at,
                    "revoked": cred.revoked,
                }
                for cred in caller.credentials.values()
            ],
        })
    return {"callers": callers}


# ----------------------------------------------------------------------
# 路由
# ----------------------------------------------------------------------
@router.post("/keys")
def post_key(
    body: IssueRequest,
    principal: Principal = Depends(require_api_key("admin")),
    ctx: AuthContext = Depends(get_context),
) -> dict:
    return issue_credential(
        ctx,
        body.caller_id,
        body.scopes,
        expires_in_seconds=body.expires_in_seconds,
        quota_limit=body.quota_limit,
        quota_window_seconds=body.quota_window_seconds,
    )


@router.post("/keys/rotate")
def post_rotate(
    body: RotateRequest,
    principal: Principal = Depends(require_api_key("admin")),
    ctx: AuthContext = Depends(get_context),
) -> dict:
    try:
        return rotate_credential(
            ctx, body.caller_id, body.key_id,
            expires_in_seconds=body.expires_in_seconds,
        )
    except KeyError:
        raise invalid_api_key(body.key_id)


@router.post("/keys/revoke")
def post_revoke(
    body: RevokeRequest,
    principal: Principal = Depends(require_api_key("admin")),
    ctx: AuthContext = Depends(get_context),
) -> dict:
    return revoke_credential(ctx, body.caller_id, body.key_id)


@router.get("/callers")
def get_callers(
    principal: Principal = Depends(require_api_key("admin")),
    ctx: AuthContext = Depends(get_context),
) -> dict:
    return describe_callers(ctx)
