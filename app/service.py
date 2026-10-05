"""鉴权核心服务。

职责：
1. 凭证生命周期：签发 / 轮换 / 吊销，只存 SHA-256 哈希；
2. 权限判定：按 scope 拒绝越权，与未认证可区分；
3. 访问配额：按调用方固定窗口计数，并发下不超限，重启后延续；
4. 在线调额：不重启调整调用方上限，立即生效且已用量保留；
5. 配额视图：只读查询已用/剩余/上限/窗口重开时间，不消耗配额。

所有鉴权结论均通过名为 ``auth`` 的 logger 输出：
凭证标识（key_id）、判定依据（reason）、配额计数（used/limit）。
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

from app.config import Settings
from app.models import Credential, FailReason, IssueResult, Principal, QuotaState
from app.security import compare_secret, generate_key_id, generate_secret, hash_secret
from app.storage import JsonStore

logger = logging.getLogger("auth")


def utc_now() -> datetime:
    """统一的时间来源（UTC，感知时区），测试可打桩替换。"""
    return datetime.now(timezone.utc)


class AuthError(Exception):
    """鉴权失败，携带可区分的失败原因与配额重试依据。"""

    def __init__(
        self,
        reason: FailReason,
        detail: str = "",
        *,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(detail or reason.value)
        self.reason = reason
        self.detail = detail or reason.value
        self.retry_after_seconds = retry_after_seconds


class AuthService:
    """凭证生命周期 + 权限判定 + 访问配额。"""

    def __init__(self, settings: Settings, store: JsonStore) -> None:
        self.settings = settings
        self.store = store
        self._clock = utc_now

    # ---------- 凭证生命周期 ----------

    def issue_key(
        self,
        caller_id: str,
        scopes: frozenset[str] = frozenset(),
        ttl_seconds: int | None = None,
        quota_limit: int | None = None,
    ) -> IssueResult:
        """签发新凭证。明文密钥只随返回值给出一次。"""
        with self.store.locked():
            credentials = self.store.load_credentials()
            quotas = self.store.load_quotas()

            key_id = self._unique_key_id(credentials)
            secret = generate_secret()
            now = self._clock()
            ttl = (
                ttl_seconds
                if ttl_seconds is not None
                else self.settings.default_key_ttl_seconds
            )
            expires_at = now + timedelta(seconds=ttl) if ttl else None

            credential = Credential(
                key_id=key_id,
                key_hash=hash_secret(secret),
                caller_id=caller_id,
                scopes=frozenset(scopes),
                created_at=now,
                expires_at=expires_at,
                revoked=False,
            )
            credentials[key_id] = credential

            existing_quota = quotas.get(caller_id)
            if existing_quota is None:
                limit = (
                    quota_limit
                    if quota_limit is not None
                    else self.settings.default_quota_limit
                )
                quotas[caller_id] = QuotaState(
                    caller_id=caller_id,
                    window_start=now,
                    limit=limit,
                    count=0,
                )

            self.store.save_credentials(credentials)
            self.store.save_quotas(quotas)

        logger.info(
            "key issued | key_id=%s caller_id=%s scopes=%s expires_at=%s",
            key_id, caller_id, sorted(scopes), expires_at,
        )
        return IssueResult(
            key_id=key_id,
            caller_id=caller_id,
            secret=secret,
            expires_at=expires_at,
        )

    def rotate_key(self, key_id: str, ttl_seconds: int | None = None) -> IssueResult:
        """轮换凭证：key_id 与调用方/scope 不变，哈希与过期时间更新。

        旧明文密钥立即失效。
        """
        with self.store.locked():
            credentials = self.store.load_credentials()
            credential = credentials.get(key_id)
            if credential is None:
                raise KeyError(f"unknown key_id: {key_id}")

            secret = generate_secret()
            now = self._clock()
            ttl = (
                ttl_seconds
                if ttl_seconds is not None
                else self.settings.default_key_ttl_seconds
            )
            expires_at = now + timedelta(seconds=ttl) if ttl else None

            credentials[key_id] = Credential(
                key_id=credential.key_id,
                key_hash=hash_secret(secret),
                caller_id=credential.caller_id,
                scopes=credential.scopes,
                created_at=credential.created_at,
                expires_at=expires_at,
                revoked=False,
            )
            self.store.save_credentials(credentials)

        logger.info(
            "key rotated | key_id=%s caller_id=%s expires_at=%s",
            key_id, credential.caller_id, expires_at,
        )
        return IssueResult(
            key_id=key_id,
            caller_id=credential.caller_id,
            secret=secret,
            expires_at=expires_at,
        )

    def revoke_key(self, key_id: str) -> None:
        """吊销凭证：此后该密钥的一切请求按 revoked_key 拒绝。"""
        with self.store.locked():
            credentials = self.store.load_credentials()
            credential = credentials.get(key_id)
            if credential is None:
                raise KeyError(f"unknown key_id: {key_id}")

            credentials[key_id] = Credential(
                key_id=credential.key_id,
                key_hash=credential.key_hash,
                caller_id=credential.caller_id,
                scopes=credential.scopes,
                created_at=credential.created_at,
                expires_at=credential.expires_at,
                revoked=True,
            )
            self.store.save_credentials(credentials)

        logger.info(
            "key revoked | key_id=%s caller_id=%s", key_id, credential.caller_id
        )

    def list_credentials(self, caller_id: str | None = None) -> list[Credential]:
        """列出凭证元数据（绝不含明文/哈希以外的敏感信息，哈希也仅内部存储）。"""
        with self.store.locked():
            credentials = list(self.store.load_credentials().values())
        if caller_id is not None:
            credentials = [c for c in credentials if c.caller_id == caller_id]
        return sorted(credentials, key=lambda c: (c.caller_id, c.key_id))

    def get_quota(self, caller_id: str) -> QuotaState | None:
        with self.store.locked():
            return self.store.load_quotas().get(caller_id)

    # ---------- 配额视图与在线调额 ----------

    def quota_view(self, caller_id: str) -> dict | None:
        """配额使用情况的只读视图（不落盘，不消耗配额）。

        窗口已过期时在视图层面滚动到当前窗口：已用归零、窗口起点对齐，
        并给出窗口重开时间与重试秒数。真正的状态滚动在下一次计数时
        于锁内原子落盘。
        """
        with self.store.locked():
            quota = self.store.load_quotas().get(caller_id)
            if quota is None:
                return None
            return self._quota_view_dict(quota, self._clock())

    def set_quota_limit(self, caller_id: str, new_limit: int) -> dict:
        """在线调整某调用方的配额上限，立即生效，已用量保留。

        - 调高/调低都只改 ``limit``，不动 ``count``；
        - 若当前窗口已过期，先在锁内原子滚动窗口（清零 + 起点更新一起落盘）；
        - 与正常业务请求、其他调额请求都在同一把锁内串行，
          不超发、不丢计数；
        - 新上限低于已用量时，后续请求按超额 429 拒绝，
          ``Retry-After`` 由窗口剩余时间给出。
        """
        if new_limit < 1:
            raise ValueError("quota limit must be >= 1")
        with self.store.locked():
            quotas = self.store.load_quotas()
            quota = quotas.get(caller_id)
            if quota is None:
                raise KeyError(f"unknown caller_id: {caller_id}")
            now = self._clock()
            quota = self._roll_forward(quota, now)
            old_limit = quota.limit
            quota.limit = new_limit
            quotas[caller_id] = quota
            self.store.save_quotas(quotas)
            view = self._quota_view_dict(quota, now)

        logger.info(
            "quota limit updated | caller_id=%s limit=%d->%d used=%d window_start=%s",
            caller_id, old_limit, new_limit, quota.count, quota.window_start,
        )
        return view

    def _quota_view_dict(self, quota: QuotaState, now: datetime) -> dict:
        effective = self._roll_forward(quota, now)
        window = timedelta(seconds=self.settings.default_quota_window_seconds)
        reset_at = effective.window_start + window
        retry_after = max(int((reset_at - now).total_seconds()), 0)
        return {
            "caller_id": effective.caller_id,
            "limit": effective.limit,
            "used": effective.count,
            "remaining": max(effective.limit - effective.count, 0),
            "window_start": effective.window_start.isoformat(),
            "window_reset_at": reset_at.isoformat(),
            "retry_after_seconds": retry_after,
        }

    def _roll_forward(self, quota: QuotaState, now: datetime) -> QuotaState:
        """窗口过期时把状态滚动到当前窗口：清零与起点更新在同一步完成。

        窗口起点按窗口长度对齐（保持固定边界），调用方需处于锁内；
        该函数只改内存对象，是否落盘由调用方决定。
        """
        window = timedelta(seconds=self.settings.default_quota_window_seconds)
        if now - quota.window_start >= window:
            elapsed = (now - quota.window_start) // window
            quota.window_start = quota.window_start + elapsed * window
            quota.count = 0
        return quota

    # ---------- 首次启动引导 ----------

    def bootstrap_admin(self) -> str | None:
        """首次启动时为管理员调用方签发初始密钥。

        已存在该调用方的凭证时返回 None；首次签发时把明文密钥写入本地文件
        （权限 600），并返回明文，供本地验证使用。密钥只保存哈希。
        """
        with self.store.locked():
            existing = [
                c
                for c in self.store.load_credentials().values()
                if c.caller_id == self.settings.admin_caller_id and not c.revoked
            ]
            if existing:
                return None
            result = self.issue_key(
                self.settings.admin_caller_id,
                frozenset({"admin"}),
            )

        secret_path = self.settings.data_dir / self.settings.admin_secret_file
        with open(secret_path, "w", encoding="utf-8") as fp:
            fp.write(result.secret + "\n")
        os.chmod(secret_path, 0o600)
        logger.warning(
            "bootstrap admin key created | key_id=%s caller_id=%s secret_file=%s",
            result.key_id, result.caller_id, secret_path,
        )
        return result.secret

    # ---------- 认证 + 权限 + 配额 ----------
    def authenticate(
        self,
        secret: str | None,
        required_scope: str | None = None,
        *,
        consume_quota: bool = True,
    ) -> Principal:
        """校验请求凭证并返回调用方身份，失败抛 :class:`AuthError`。

        判定顺序（与失败原因一一对应）：
        1. 缺失凭证 -> missing_key
        2. 哈希匹配不到 -> invalid_key
        3. 已吊销 -> revoked_key
        4. 已过期 -> expired_key
        5. 缺少 scope -> insufficient_scope（已认证但越权）
        6. 配额耗尽 -> quota_exceeded（带 retry_after）
        """
        if not secret:
            logger.warning("auth deny | key_id=- reason=%s detail=no api key",
                           FailReason.MISSING_KEY.value)
            raise AuthError(FailReason.MISSING_KEY, "缺少 API Key")

        with self.store.locked():
            credentials = self.store.load_credentials()
            matched = self._find_by_secret(credentials, secret)
            if matched is None:
                logger.warning("auth deny | key_id=- reason=%s detail=hash not found",
                               FailReason.INVALID_KEY.value)
                raise AuthError(FailReason.INVALID_KEY, "API Key 无效")

            now = self._clock()
            if matched.revoked:
                logger.warning(
                    "auth deny | key_id=%s caller_id=%s reason=%s",
                    matched.key_id, matched.caller_id, FailReason.REVOKED_KEY.value,
                )
                raise AuthError(FailReason.REVOKED_KEY, "API Key 已吊销")

            if matched.expires_at is not None and now >= matched.expires_at:
                logger.warning(
                    "auth deny | key_id=%s caller_id=%s reason=%s expires_at=%s",
                    matched.key_id, matched.caller_id,
                    FailReason.EXPIRED_KEY.value, matched.expires_at,
                )
                raise AuthError(FailReason.EXPIRED_KEY, "API Key 已过期")

            if required_scope is not None and required_scope not in matched.scopes:
                logger.warning(
                    "auth deny | key_id=%s caller_id=%s reason=%s required=%s held=%s",
                    matched.key_id, matched.caller_id,
                    FailReason.INSUFFICIENT_SCOPE.value,
                    required_scope, sorted(matched.scopes),
                )
                raise AuthError(
                    FailReason.INSUFFICIENT_SCOPE,
                    f"缺少权限范围: {required_scope}",
                )

            if consume_quota:
                self._check_and_consume_quota(matched.caller_id, now)

            logger.info(
                "auth allow | key_id=%s caller_id=%s scope=%s",
                matched.key_id, matched.caller_id, required_scope,
            )
            return Principal(
                caller_id=matched.caller_id,
                key_id=matched.key_id,
                scopes=matched.scopes,
            )

    # ---------- 内部辅助 ----------

    def _check_and_consume_quota(self, caller_id: str, now: datetime) -> None:
        quotas = self.store.load_quotas()
        quota = quotas.get(caller_id)
        if quota is None:
            # 理论上不会发生：凭证签发时即初始化配额
            quota = QuotaState(
                caller_id=caller_id,
                window_start=now,
                limit=self.settings.default_quota_limit,
                count=0,
            )

        window = timedelta(seconds=self.settings.default_quota_window_seconds)
        # 窗口重开：清零与窗口起点更新在锁内同一步完成，
        # 边界前后的请求只会落入恰好一个窗口。
        quota = self._roll_forward(quota, now)

        if quota.count >= quota.limit:
            retry_after = int(
                (quota.window_start + window - now).total_seconds()
            )
            retry_after = max(retry_after, 1)
            logger.warning(
                "auth deny | key_id=- caller_id=%s reason=%s quota=%d/%d "
                "window_start=%s retry_after=%ds",
                caller_id, FailReason.QUOTA_EXCEEDED.value,
                quota.count, quota.limit, quota.window_start, retry_after,
            )
            raise AuthError(
                FailReason.QUOTA_EXCEEDED,
                f"访问配额已用尽: {quota.count}/{quota.limit}",
                retry_after_seconds=retry_after,
            )

        quota.count += 1
        quotas[caller_id] = quota
        self.store.save_quotas(quotas)
        logger.info(
            "quota count | caller_id=%s quota=%d/%d window_start=%s",
            caller_id, quota.count, quota.limit, quota.window_start,
        )

    @staticmethod
    def _find_by_secret(
        credentials: dict[str, Credential], secret: str
    ) -> Credential | None:
        for credential in credentials.values():
            if compare_secret(secret, credential.key_hash):
                return credential
        return None

    @staticmethod
    def _unique_key_id(credentials: dict[str, Credential]) -> str:
        while True:
            key_id = generate_key_id()
            if key_id not in credentials:
                return key_id
