"""判定日志必须包含凭证标识、判定依据与配额计数。"""

from __future__ import annotations

import logging


def test_allow_log_has_keyid_basis_and_quota(client, admin_headers, helpers, caplog):
    issued = helpers.issue(
        client, admin_headers, "logger", ["items:read"],
        quota_limit=4, quota_window_seconds=60,
    )
    with caplog.at_level(logging.INFO, logger="app.auth"):
        client.get("/items", headers=helpers.bearer(issued["api_key"]))

    line = [
        r.message
        for r in caplog.records
        if "判定=放行" in r.message and issued["key_id"] in r.message
    ][0]
    assert issued["key_id"] in line
    assert "判定依据=" in line
    assert "quota=1/4" in line


def test_deny_logs_are_distinguishable(client, admin_headers, helpers, caplog):
    issued = helpers.issue(
        client, admin_headers, "logger2", ["items:read"],
        quota_limit=1, quota_window_seconds=60,
    )
    h = helpers.bearer(issued["api_key"])
    with caplog.at_level(logging.INFO, logger="app.auth"):
        client.get("/items", headers=h)
        client.get("/items", headers=h)  # 超额
        client.get("/items")            # 缺失
        client.get("/items", headers=helpers.bearer("ak_bad"))  # 无效

    msgs = [r.message for r in caplog.records]
    assert any("reason=quota_exceeded" in m and issued["key_id"] in m for m in msgs)
    assert any("reason=missing_api_key" in m for m in msgs)
    assert any("reason=invalid_api_key" in m for m in msgs)
