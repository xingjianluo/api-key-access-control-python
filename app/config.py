"""本地配置。

所有配置均可通过环境变量覆盖，不依赖任何外部服务：

``AUTH_DATA_DIR``               凭证/配额持久化目录
``AUTH_DEFAULT_QUOTA_LIMIT``    每个调用方每个窗口的默认配额
``AUTH_QUOTA_WINDOW_SECONDS``   固定窗口长度（秒）
``AUTH_KEY_TTL_SECONDS``        新凭证默认有效期（秒），不设表示永不过期
``AUTH_ADMIN_CALLER_ID``        初始管理员调用方标识
``AUTH_ADMIN_SECRET_FILE``      初始管理员明文密钥落盘文件
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


@dataclass(frozen=True)
class Settings:
    """运行配置，全部可本地落盘，不依赖外部服务。"""

    data_dir: Path = Path("data")
    default_quota_limit: int = 100
    default_quota_window_seconds: int = 3600
    default_key_ttl_seconds: int | None = None
    admin_caller_id: str = "admin"
    admin_secret_file: str = "admin_initial_key.txt"

    @classmethod
    def from_env(cls) -> "Settings":
        ttl_raw = os.environ.get("AUTH_KEY_TTL_SECONDS")
        return cls(
            data_dir=Path(os.environ.get("AUTH_DATA_DIR", "data")),
            default_quota_limit=_env_int("AUTH_DEFAULT_QUOTA_LIMIT", 100),
            default_quota_window_seconds=_env_int("AUTH_QUOTA_WINDOW_SECONDS", 3600),
            default_key_ttl_seconds=int(ttl_raw) if ttl_raw not in (None, "") else None,
            admin_caller_id=os.environ.get("AUTH_ADMIN_CALLER_ID", "admin"),
            admin_secret_file=os.environ.get(
                "AUTH_ADMIN_SECRET_FILE", "admin_initial_key.txt"
            ),
        )
