"""访问配额判定服务。

真正的原子计数在 ``Store.consume_quota`` 中完成（持进程锁并立即落盘）；
本层只负责注入时钟并换算 Retry-After，便于测试时使用虚拟时钟。
"""

from __future__ import annotations

import time
from collections.abc import Callable

from app.models import Caller
from app.store import Store


class QuotaService:
    """按调用方计量的固定窗口配额服务。"""

    def __init__(self, store: Store, clock: Callable[[], float] = time.time) -> None:
        self.store = store
        self._clock = clock

    def check_and_consume(self, caller: Caller) -> tuple[bool, int, int, int]:
        """原子扣减一次配额。

        Returns:
            (是否放行, 本窗口已用计数, 限额, 建议重试秒数)。
            放行时重试秒数为 0。
        """
        now = self._clock()
        allowed, used, limit = self.store.consume_quota(caller, now)
        if allowed:
            return True, used, limit, 0
        return False, used, limit, self.store.quota_retry_after(caller, now)
