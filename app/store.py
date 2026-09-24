"""凭证与配额的持久化存储。

使用本地 JSON 文件持久化，进程内用 ``threading.RLock`` 保证
"查找凭证 → 校验状态 → 扣减配额" 整条判定路径原子化；
每次变更后立刻 fsync + 原子 rename 落盘，因此：

- 同一凭证的并发请求不会突破限额（临界区内串行）；
- 服务重启后凭证吊销 / 过期状态与已消耗配额都会延续，不会静默重置。

不依赖任何外部服务或第三方库。
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
import tempfile
import threading
from pathlib import Path

from app.models import Caller, Credential

SCHEMA_VERSION = 1
DEFAULT_QUOTA_LIMIT = 100
DEFAULT_QUOTA_WINDOW_SECONDS = 3600


class Store:
    """调用方 / 凭证 / 配额的持久化存储。"""

    def __init__(self, path: str | Path = "data/auth_state.json") -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._callers: dict[str, Caller] = {}

    # ------------------------------------------------------------------
    # 锁与持久化
    # ------------------------------------------------------------------
    @contextlib.contextmanager
    def locked(self):
        """暴露锁上下文，供依赖层把整段鉴权判定放进同一临界区。"""
        with self._lock:
            yield

    def load(self) -> None:
        """从磁盘加载状态；文件不存在时初始化为空状态。"""
        with self._lock:
            if not self.path.exists():
                self._callers = {}
                return
            with self.path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
            self._callers = {
                cid: self._caller_from_dict(cid, data)
                for cid, data in raw.get("callers", {}).items()
            }

    def _persist_locked(self) -> None:
        """持锁将当前状态原子写入磁盘（临时文件 + fsync + os.replace）。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": SCHEMA_VERSION,
            "callers": {
                cid: self._caller_to_dict(caller)
                for cid, caller in self._callers.items()
            },
        }
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)
            raise

    # ------------------------------------------------------------------
    # 序列化
    # ------------------------------------------------------------------
    @staticmethod
    def _credential_to_dict(cred: Credential) -> dict:
        return {
            "key_id": cred.key_id,
            "key_hash": cred.key_hash,
            "caller_id": cred.caller_id,
            "scopes": list(cred.scopes),
            "created_at": cred.created_at,
            "expires_at": cred.expires_at,
            "revoked": cred.revoked,
        }

    @staticmethod
    def _credential_from_dict(data: dict) -> Credential:
        return Credential(
            key_id=data["key_id"],
            key_hash=data["key_hash"],
            caller_id=data["caller_id"],
            scopes=tuple(data["scopes"]),
            created_at=data["created_at"],
            expires_at=data["expires_at"],
            revoked=data["revoked"],
        )

    def _caller_to_dict(self, caller: Caller) -> dict:
        return {
            "quota_limit": caller.quota_limit,
            "quota_window_seconds": caller.quota_window_seconds,
            "quota_used": caller.quota_used,
            "quota_window_start": caller.quota_window_start,
            "credentials": {
                kid: self._credential_to_dict(cred)
                for kid, cred in caller.credentials.items()
            },
        }

    def _caller_from_dict(self, caller_id: str, data: dict) -> Caller:
        return Caller(
            caller_id=caller_id,
            credentials={
                kid: self._credential_from_dict(cdata)
                for kid, cdata in data.get("credentials", {}).items()
            },
            quota_limit=data["quota_limit"],
            quota_window_seconds=data["quota_window_seconds"],
            quota_used=data["quota_used"],
            quota_window_start=data["quota_window_start"],
        )

    # ------------------------------------------------------------------
    # 凭证生命周期
    # ------------------------------------------------------------------
    def add_credential(
        self,
        credential: Credential,
        *,
        quota_limit: int = DEFAULT_QUOTA_LIMIT,
        quota_window_seconds: int = DEFAULT_QUOTA_WINDOW_SECONDS,
    ) -> Caller:
        """为调用方新增凭证；调用方不存在时按给定配额创建。"""
        with self._lock:
            caller = self._callers.get(credential.caller_id)
            if caller is None:
                caller = Caller(
                    caller_id=credential.caller_id,
                    quota_limit=quota_limit,
                    quota_window_seconds=quota_window_seconds,
                )
                self._callers[caller.caller_id] = caller
            caller.credentials[credential.key_id] = credential
            self._persist_locked()
            return caller

    def rotate_credential(
        self, caller_id: str, old_key_id: str, new_credential: Credential
    ) -> None:
        """原子轮换：吊销旧凭证并写入新凭证，配额计数保留。"""
        with self._lock:
            caller = self._callers.get(caller_id)
            if caller is None or old_key_id not in caller.credentials:
                raise KeyError((caller_id, old_key_id))
            old = caller.credentials[old_key_id]
            caller.credentials[old_key_id] = Credential(
                key_id=old.key_id,
                key_hash=old.key_hash,
                caller_id=old.caller_id,
                scopes=old.scopes,
                created_at=old.created_at,
                expires_at=old.expires_at,
                revoked=True,
            )
            caller.credentials[new_credential.key_id] = new_credential
            self._persist_locked()

    def find_by_hash(self, key_hash: str) -> tuple[Caller, Credential] | None:
        """按密钥哈希查找 (调用方, 凭证)。

        对全部已存哈希做常量时间比较，避免直接用字典命中带来的计时差异。
        """
        with self._lock:
            match: Credential | None = None
            for caller in self._callers.values():
                for cred in caller.credentials.values():
                    if hmac.compare_digest(cred.key_hash, key_hash):
                        match = cred
                        return caller, match
            return None

    def get_caller(self, caller_id: str) -> Caller | None:
        with self._lock:
            return self._callers.get(caller_id)

    def get_credential(self, caller_id: str, key_id: str) -> Credential | None:
        with self._lock:
            caller = self._callers.get(caller_id)
            return caller.credentials.get(key_id) if caller else None

    def list_callers(self) -> list[Caller]:
        with self._lock:
            return list(self._callers.values())

    def revoke_credential(self, caller_id: str, key_id: str) -> bool:
        """吊销凭证，返回是否实际发生变更。"""
        with self._lock:
            caller = self._callers.get(caller_id)
            if caller is None or key_id not in caller.credentials:
                return False
            cred = caller.credentials[key_id]
            if cred.revoked:
                return False
            caller.credentials[key_id] = Credential(
                key_id=cred.key_id,
                key_hash=cred.key_hash,
                caller_id=cred.caller_id,
                scopes=cred.scopes,
                created_at=cred.created_at,
                expires_at=cred.expires_at,
                revoked=True,
            )
            self._persist_locked()
            return True

    # ------------------------------------------------------------------
    # 配额
    # ------------------------------------------------------------------
    def consume_quota(
        self, caller: Caller, now: float
    ) -> tuple[bool, int, int]:
        """原子扣减一次配额；窗口过期则开启新窗口。

        Returns:
            (是否放行, 本窗口已用计数（含本次）, 限额)。
        """
        with self._lock:
            if now - caller.quota_window_start >= caller.quota_window_seconds:
                caller.quota_window_start = now
                caller.quota_used = 0
            if caller.quota_used < caller.quota_limit:
                caller.quota_used += 1
                self._persist_locked()
                return True, caller.quota_used, caller.quota_limit
            return False, caller.quota_used, caller.quota_limit

    def quota_retry_after(self, caller: Caller, now: float) -> int:
        """当前固定窗口剩余秒数（配额耗尽时作为 Retry-After，至少 1 秒）。"""
        reset_at = caller.quota_window_start + caller.quota_window_seconds
        return max(1, int(reset_at - now + 0.999999))
