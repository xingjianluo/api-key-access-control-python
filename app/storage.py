"""JSON 文件持久化。

- 原子写：先写临时文件再 ``os.replace``，避免半写文件；
- 进程内并发：``threading.RLock`` 串行化所有读改写；
- 跨进程互斥：对 ``.lock`` 文件加 ``fcntl.flock`` 排他锁；
- 服务重启后凭证与配额计数从文件原样恢复。
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Iterator

from app.models import Credential, QuotaState

_CREDENTIALS_FILE = "credentials.json"
_QUOTAS_FILE = "quotas.json"
_LOCK_FILE = ".lock"


def _dump_credentials(credentials: dict[str, Credential]) -> dict:
    out = {}
    for key_id, c in credentials.items():
        d = asdict(c)
        d["scopes"] = sorted(c.scopes)
        d["created_at"] = c.created_at.isoformat()
        d["expires_at"] = c.expires_at.isoformat() if c.expires_at else None
        out[key_id] = d
    return out


def _load_credentials(raw: dict) -> dict[str, Credential]:
    result: dict[str, Credential] = {}
    for key_id, d in raw.items():
        result[key_id] = Credential(
            key_id=d["key_id"],
            key_hash=d["key_hash"],
            caller_id=d["caller_id"],
            scopes=frozenset(d.get("scopes", ())),
            created_at=datetime.fromisoformat(d["created_at"]),
            expires_at=(
                datetime.fromisoformat(d["expires_at"])
                if d.get("expires_at")
                else None
            ),
            revoked=bool(d.get("revoked", False)),
        )
    return result


def _dump_quotas(quotas: dict[str, QuotaState]) -> dict:
    return {
        caller_id: {
            "caller_id": q.caller_id,
            "window_start": q.window_start.isoformat(),
            "limit": q.limit,
            "count": q.count,
        }
        for caller_id, q in quotas.items()
    }


def _load_quotas(raw: dict) -> dict[str, QuotaState]:
    return {
        caller_id: QuotaState(
            caller_id=d["caller_id"],
            window_start=datetime.fromisoformat(d["window_start"]),
            limit=int(d.get("limit", 100)),
            count=int(d["count"]),
        )
        for caller_id, d in raw.items()
    }


class JsonStore:
    """凭证与配额的本地持久化存储。"""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._credentials_path = self.data_dir / _CREDENTIALS_FILE
        self._quotas_path = self.data_dir / _QUOTAS_FILE
        self._lock_path = self.data_dir / _LOCK_FILE
        self._thread_lock = threading.RLock()
        self._lock_fp = open(self._lock_path, "a+")

    @contextmanager
    def locked(self) -> Iterator[None]:
        """获取进程内锁 + 跨进程文件锁，期间完成读改写。"""
        with self._thread_lock:
            fcntl.flock(self._lock_fp.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(self._lock_fp.fileno(), fcntl.LOCK_UN)

    def _atomic_write_json(self, path: Path, payload: dict) -> None:
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        with open(tmp_path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, ensure_ascii=False, indent=2, sort_keys=True)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp_path, path)

    def _read_json(self, path: Path) -> dict:
        if not path.exists():
            return {}
        with open(path, encoding="utf-8") as fp:
            return json.load(fp)

    def load_credentials(self) -> dict[str, Credential]:
        return _load_credentials(self._read_json(self._credentials_path))

    def save_credentials(self, credentials: dict[str, Credential]) -> None:
        self._atomic_write_json(self._credentials_path, _dump_credentials(credentials))

    def load_quotas(self) -> dict[str, QuotaState]:
        return _load_quotas(self._read_json(self._quotas_path))

    def save_quotas(self, quotas: dict[str, QuotaState]) -> None:
        self._atomic_write_json(self._quotas_path, _dump_quotas(quotas))
