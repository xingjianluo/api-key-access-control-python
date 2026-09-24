"""领域模型与失败原因枚举（骨架：仅类型定义）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class FailReason(str, Enum):
    """可区分的鉴权失败原因。"""

    MISSING_KEY = "missing_key"
    INVALID_KEY = "invalid_key"
    REVOKED_KEY = "revoked_key"
    EXPIRED_KEY = "expired_key"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    QUOTA_EXCEEDED = "quota_exceeded"


@dataclass(frozen=True)
class Credential:
    """持久化的凭证记录（只保存哈希，不保存明文）。"""

    key_id: str
    key_hash: str
    caller_id: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    created_at: datetime = field(default_factory=datetime)
    expires_at: datetime | None = None
    revoked: bool = False


@dataclass
class QuotaState:
    """单个调用方的固定窗口配额状态。

    ``limit`` 为该调用方每窗口的配额额度，随状态一起持久化，
    重启后保持不变；首次为该调用方签发凭证时确定。
    """

    caller_id: str
    window_start: datetime
    limit: int
    count: int = 0


@dataclass(frozen=True)
class Principal:
    """鉴权通过后注入请求上下文的调用方身份。"""

    caller_id: str
    key_id: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class IssueResult:
    """签发/轮换结果：明文密钥仅此一次返回。"""

    key_id: str
    caller_id: str
    secret: str
    expires_at: datetime | None
