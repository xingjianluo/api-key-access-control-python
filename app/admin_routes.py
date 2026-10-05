"""管理接口：凭证签发、轮换、吊销、查询。

所有接口需要 ``admin`` 权限范围；管理操作不消耗业务配额。
明文密钥只在签发/轮换的响应中出现一次。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.deps import require_scope
from app.models import Principal
from app.service import AuthService
from app.deps import get_service

router = APIRouter(prefix="/admin/keys", tags=["admin"])


class IssueRequest(BaseModel):
    caller_id: str = Field(min_length=1)
    scopes: list[str] = Field(default_factory=list)
    ttl_seconds: int | None = Field(default=None, ge=1)
    quota_limit: int | None = Field(default=None, ge=1)


class RotateRequest(BaseModel):
    ttl_seconds: int | None = Field(default=None, ge=1)


class QuotaAdjustRequest(BaseModel):
    """在线调额请求体：只含新上限，已用量保留。"""

    limit: int = Field(ge=1)


def _credential_view(credential) -> dict:
    return {
        "key_id": credential.key_id,
        "caller_id": credential.caller_id,
        "scopes": sorted(credential.scopes),
        "created_at": credential.created_at.isoformat(),
        "expires_at": (
            credential.expires_at.isoformat() if credential.expires_at else None
        ),
        "revoked": credential.revoked,
    }


@router.post("")
def issue_key_endpoint(
    payload: IssueRequest,
    service: AuthService = Depends(get_service),
    _: Principal = Depends(require_scope("admin", consume_quota=False)),
) -> dict:
    result = service.issue_key(
        payload.caller_id,
        frozenset(payload.scopes),
        ttl_seconds=payload.ttl_seconds,
        quota_limit=payload.quota_limit,
    )
    return {
        "key_id": result.key_id,
        "caller_id": result.caller_id,
        "secret": result.secret,
        "expires_at": result.expires_at.isoformat() if result.expires_at else None,
    }


@router.post("/{key_id}/rotate")
def rotate_key_endpoint(
    key_id: str,
    payload: RotateRequest | None = None,
    service: AuthService = Depends(get_service),
    _: Principal = Depends(require_scope("admin", consume_quota=False)),
) -> dict:
    result = service.rotate_key(
        key_id, ttl_seconds=payload.ttl_seconds if payload else None
    )
    return {
        "key_id": result.key_id,
        "caller_id": result.caller_id,
        "secret": result.secret,
        "expires_at": result.expires_at.isoformat() if result.expires_at else None,
    }


@router.post("/{key_id}/revoke")
def revoke_key_endpoint(
    key_id: str,
    service: AuthService = Depends(get_service),
    _: Principal = Depends(require_scope("admin", consume_quota=False)),
) -> dict:
    service.revoke_key(key_id)
    return {"key_id": key_id, "revoked": True}


@router.get("")
def list_keys_endpoint(
    caller_id: str | None = None,
    service: AuthService = Depends(get_service),
    _: Principal = Depends(require_scope("admin", consume_quota=False)),
) -> dict:
    credentials = service.list_credentials(caller_id=caller_id)
    return {"keys": [_credential_view(c) for c in credentials]}


@router.get("/quotas/{caller_id}")
def get_quota_endpoint(
    caller_id: str,
    service: AuthService = Depends(get_service),
    _: Principal = Depends(require_scope("admin", consume_quota=False)),
) -> dict:
    view = service.quota_view(caller_id)
    if view is None:
        return {"caller_id": caller_id, "found": False}
    return {"found": True, **view}


@router.put("/quotas/{caller_id}")
def adjust_quota_endpoint(
    caller_id: str,
    payload: QuotaAdjustRequest,
    service: AuthService = Depends(get_service),
    _: Principal = Depends(require_scope("admin", consume_quota=False)),
) -> dict:
    """在线调整配额上限：立即生效，已用量保留，不重启服务。"""
    return service.set_quota_limit(caller_id, payload.limit)
