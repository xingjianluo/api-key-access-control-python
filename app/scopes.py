"""权限范围定义与判定。

范围模型：每个凭证在签发时被授予一组字符串范围；受保护接口声明
自己所需的单一范围。``admin`` 为管理范围，不隐式包含业务范围。
"""

from __future__ import annotations

#: 读取业务资源
SCOPE_ITEMS_READ = "items:read"
#: 写入业务资源
SCOPE_ITEMS_WRITE = "items:write"
#: 管理接口（签发 / 轮换 / 吊销 / 查询）
SCOPE_ADMIN = "admin"

KNOWN_SCOPES: frozenset[str] = frozenset(
    {SCOPE_ITEMS_READ, SCOPE_ITEMS_WRITE, SCOPE_ADMIN}
)


def has_scope(granted: tuple[str, ...], required: str) -> bool:
    """判定已授权范围是否满足所需范围。

    目前为精确匹配模型；未来若引入层级范围可在此扩展，
    调用方代码无需改动。
    """
    return required in granted
