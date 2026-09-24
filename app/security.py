"""凭证生成与哈希。

密钥只在签发 / 轮换的响应中出现一次；服务端只保存
SHA-256 哈希（hex），状态文件中不存在明文。
"""

from __future__ import annotations

import hashlib
import secrets

KEY_PREFIX = "ak_"
KEY_ID_PREFIX = "kid_"

_RANDOM_BYTES = 32


def generate_key() -> tuple[str, str]:
    """生成新的 API Key 明文及其标识。

    Returns:
        (api_key 明文, key_id)。明文形如 ``ak_<64 hex>``，
        标识形如 ``kid_<16 hex>``，仅用于日志与管理接口，不含密钥信息。
    """
    token = secrets.token_hex(_RANDOM_BYTES)
    key_id = KEY_ID_PREFIX + secrets.token_hex(8)
    return KEY_PREFIX + token, key_id


def hash_key(api_key: str) -> str:
    """返回 API Key 的 SHA-256 hex 哈希。

    比对采用 ``hmac.compare_digest`` 进行常量时间比较（见 store），
    避免计时侧信道。
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def parse_authorization(header: str | None) -> str | None:
    """从 ``Authorization: Bearer <key>`` 头中解析明文密钥。

    - 头缺失或方案不是 Bearer（大小写不敏感）→ None（视为未提供）。
    - 其余情况返回 Bearer 之后的凭证原文（可能为空串，交由哈希查找判无效）。
    """
    if not header:
        return None
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token if token else None
