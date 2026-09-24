"""数据模型：调用方、凭证记录、配额状态。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Credential:
    """一条已保存的凭证记录（不含明文密钥）。"""

    key_id: str
    key_hash: str
    caller_id: str
    scopes: tuple[str, ...]
    created_at: float
    expires_at: float | None
    revoked: bool = False


@dataclass
class Caller:
    """调用方：拥有若干凭证与一个固定窗口配额。"""

    caller_id: str
    credentials: dict[str, Credential] = field(default_factory=dict)
    quota_limit: int = 100
    quota_window_seconds: int = 3600
    quota_used: int = 0
    quota_window_start: float = 0.0


@dataclass(frozen=True)
class Principal:
    """通过认证后的调用方身份，注入到受保护路由。"""

    caller_id: str
    key_id: str
    scopes: tuple[str, ...]
