# API Key 鉴权与访问控制（本地可验证）

为现有 FastAPI 服务增加一套**完全本地化、不依赖任何外部服务**的 API Key 鉴权与访问控制能力，
覆盖凭证生命周期、按调用方的权限范围与访问配额，并在并发与服务重启场景下保持结论一致、可解释。

## 能力总览

| 能力 | 说明 |
| --- | --- |
| 凭证签发 | 明文密钥仅在签发/轮换的 HTTP 响应中返回一次，磁盘仅存 SHA-256 哈希 |
| 凭证轮换 | `key_id` 与调用方/范围不变，旧明文立即失效，新明文一次性返回 |
| 凭证吊销 | 标记吊销并持久化，此后请求以 `revoked_key` 拒绝 |
| 凭证过期 | 签发时可设 TTL；过期请求以 `expired_key` 拒绝 |
| 权限范围 | 按调用方持有 scope 判定，越权 403，与未认证 401 严格区分 |
| 公开接口 | `GET /` 无需鉴权，启用后响应契约仍为 `{"Hello": "World"}` |
| 访问配额 | 按调用方固定窗口计数；配额内放行，超额 429 并带 `Retry-After` |
| 并发安全 | 进程内锁 + `fcntl` 文件锁串行化“读-判-写”，并发绝不突破限额 |
| 重启延续 | 凭证/吊销/配额均落盘，重启后已消耗配额不会静默重置 |
| 可解释日志 | `auth` logger 输出 key_id、判定原因、`配额=used/limit`、retry_after |

## 快速开始

```bash
uv sync
uv run uvicorn main:app --reload
# 交互式文档：http://127.0.0.1:8000/docs
```

首次启动若不存在管理员凭证，会自动引导一个管理员调用方（scope=`admin`），
明文密钥写入数据目录下的 `admin_initial_key.txt`（文件权限 600），日志也会提示其位置。
之后再次启动不会重复引导。

## 凭证生命周期

凭证通过 `Authorization: Bearer <secret>` 传递。管理接口均需要 `admin` 范围，
且管理操作**不消耗**业务配额。

```bash
ADMIN_KEY=$(cat data/admin_initial_key.txt)

# 1) 签发：指定调用方、scope 列表、可选 TTL 与每窗口配额
curl -s -H "Authorization: Bearer $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{"caller_id":"alice","scopes":["data:read"],"ttl_seconds":3600,"quota_limit":100}' \
  http://127.0.0.1:8000/admin/keys
# -> {"key_id":"key_xxx","caller_id":"alice","secret":"ak_...","expires_at":"..."}

# 2) 轮换：key_id 不变，旧 secret 立即失效
curl -s -X POST -H "Authorization: Bearer $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{"ttl_seconds":7200}' \
  http://127.0.0.1:8000/admin/keys/key_xxx/rotate

# 3) 吊销
curl -s -X POST -H "Authorization: Bearer $ADMIN_KEY" \
  http://127.0.0.1:8000/admin/keys/key_xxx/revoke

# 查询凭证元数据 / 查询某调用方配额
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://127.0.0.1:8000/admin/keys
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://127.0.0.1:8000/admin/keys/quotas/alice
```

磁盘布局（默认 `./data/`，已加入 `.gitignore`）：

- `credentials.json`：凭证元数据与 `key_hash`（**绝无明文**），原子写入（tmp + `os.replace`）；
- `quotas.json`：每个调用方的窗口起点、额度与已用计数；
- `.lock`：跨进程排他锁文件。

### 失败原因（可区分）

| 场景 | HTTP | 响应 `detail.reason` | 响应头 |
| --- | --- | --- | --- |
| 缺失/格式错误 Authorization | 401 | `missing_key` | `WWW-Authenticate: Bearer error="missing_key"` |
| 哈希匹配不到（含轮换后旧密钥） | 401 | `invalid_key` | `WWW-Authenticate: Bearer error="invalid_key"` |
| 已吊销 | 401 | `revoked_key` | `WWW-Authenticate: Bearer error="revoked_key"` |
| 已过期 | 401 | `expired_key` | `WWW-Authenticate: Bearer error="expired_key"` |
| 凭证有效但缺少 scope | 403 | `insufficient_scope` | `WWW-Authenticate: Bearer error="insufficient_scope"` |
| 配额用尽 | 429 | `quota_exceeded` | `Retry-After: <秒>` |

判定顺序为：缺失 → 无效 → 吊销 → 过期 → 越权 → 配额；
因此“未认证”与“越权”天然可区分（401 vs 403）。

## 权限范围模型

- scope 是不透明字符串（如 `data:read`、`data:write`、`admin`），凭证签发时给定；
- `GET /me` 只要求**有效凭证**，不要求具体 scope；
- `GET /data/read` 要求 `data:read`；`POST /data/write` 要求 `data:write`；
- scope 按凭证持有，配额按 `caller_id` 计量——同一调用方的多把凭证共享一份配额；
- 越权等被拒请求不消耗配额。

## 配额规则

- **计量维度**：调用方（`caller_id`）。首次为某调用方签发凭证时确定其 `limit`；
- **算法**：固定窗口。每窗口长度由 `AUTH_QUOTA_WINDOW_SECONDS` 配置（默认 3600 秒），
  窗口结束后计数归零重新计量；
- **计数时机**：仅当凭证有效、scope 校验通过后才计数（拒绝类请求不计费）；
- **超额响应**：429，`Retry-After` 为当前窗口剩余秒数，是明确的重试依据；
- **并发保证**：认证全流程（加载→判定→计数→落盘）在进程内 `RLock` 与
  `fcntl.flock` 排他锁内完成，因此同一凭证/调用方在并发请求下成功数恰好等于 `limit`，
  不会突破；
- **重启保证**：每次计数成功都立即原子落盘，服务重启从文件恢复，
  已消耗配额不会被静默重置（测试 `test_quota_persists_across_restart` 覆盖）。

## 配置（环境变量）

| 变量 | 默认值 | 含义 |
| --- | --- | --- |
| `AUTH_DATA_DIR` | `data` | 凭证/配额持久化目录 |
| `AUTH_DEFAULT_QUOTA_LIMIT` | `100` | 调用方每窗口默认配额 |
| `AUTH_QUOTA_WINDOW_SECONDS` | `3600` | 固定窗口长度（秒） |
| `AUTH_KEY_TTL_SECONDS` | 未设置（永不过期） | 新凭证默认 TTL（秒） |
| `AUTH_ADMIN_CALLER_ID` | `admin` | 初始管理员调用方标识 |
| `AUTH_ADMIN_SECRET_FILE` | `admin_initial_key.txt` | 初始管理员明文密钥文件名 |

## 本地验证方法

一键端到端脚本（真实 uvicorn 进程 + curl + 中途重启，退出自动清理）：

```bash
./scripts/local_verify.sh
```

脚本依次验证：公开接口契约、401/403 区分、签发、10 并发打限额 3
（恰好 3 个 200、8 个 429）、配额查询、**重启后仍 429**、吊销拒绝。

单元/集成测试（TestClient，包含并发、过期、吊销、越权、重启延续、日志内容断言）：

```bash
uv run pytest -q
```

测试分布：

- `tests/test_public.py`：公开接口行为与响应契约；
- `tests/test_credentials.py`：不明文落盘、缺失/无效/吊销/过期原因可区分、轮换；
- `tests/test_scopes.py`：scope 模型与 401/403 区分；
- `tests/test_quota.py`：配额放行/拒绝、**并发接近限额不突破**、按调用方隔离、
  窗口重置、**重启后配额延续**；
- `tests/test_restart_and_logging.py`：吊销/轮换的重启延续，
  以及日志包含 key_id、判定原因、配额计数（`caplog` 断言）。

查看运行时可解释日志（示例）：

```
INFO  [auth] auth allow | key_id=key_.. caller_id=alice scope=data:read
INFO  [auth] quota count | caller_id=alice quota=2/3 window_start=...
WARN  [auth] auth deny | key_id=- caller_id=alice reason=quota_exceeded quota=3/3 ... retry_after=3599s
WARN  [auth] auth deny | key_id=key_.. caller_id=alice reason=insufficient_scope required=data:write held=['data:read']
```

## 代码结构

```
main.py               FastAPI 组装、状态注入、KeyError->404
app/models.py         领域模型与失败原因枚举
app/config.py         环境变量配置
app/security.py       密钥生成、SHA-256 哈希、常数时间比较
app/storage.py        JSON 原子持久化 + 线程锁/文件锁
app/service.py        凭证生命周期、认证、scope 判定、配额核心
app/deps.py           FastAPI 依赖与 401/403/429 映射
app/api_routes.py     公开接口与业务接口
app/admin_routes.py   凭证管理接口（admin scope）
scripts/local_verify.sh  真实进程端到端验证
tests/                pytest 测试套件
```
