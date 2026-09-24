"""密钥生成与哈希。

明文密钥仅在签发/轮换时返回一次；持久化只保留 SHA-256 哈希。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_SECRET_PREFIX = "ak_"
_KEY_PREFIX = "key_"


def generate_secret() -> str:
    """生成高强度随机明文密钥，形如 ``ak_xxxx...``。"""
    return _SECRET_PREFIX + secrets.token_urlsafe(32)


def generate_key_id() -> str:
    """生成凭证标识 key_id（非敏感，可出现在日志中）。"""
    return _KEY_PREFIX + secrets.token_hex(8)


def hash_secret(secret: str) -> str:
    """计算密钥的 SHA-256 十六进制摘要用于存储与比对。"""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def compare_secret(presented: str, expected_hash: str) -> bool:
    """常数时间比较：明文密钥的哈希是否等于存储的哈希。"""
    return hmac.compare_digest(hash_secret(presented), expected_hash)
