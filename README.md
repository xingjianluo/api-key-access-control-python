# API Key 鉴权与访问控制（本地、零外部依赖）

基于 FastAPI 的本地可验证实现，覆盖：

1. **凭证生命周期**：API Key 的签发、轮换、吊销、过期；服务端只存 SHA-256 哈希，不存明文。
2. **权限范围（Scope）**：按调用方授权，越权返回 `403 insufficient_scope`，与未认证 `401` 明确区分。
3. **访问配额（Quota）**：按调用方计量的固定窗口配额，超额返回 `429` 并携带 `Retry-After`；并发不超发、重启不重置。

全部状态保存在本地单个 JSON 文件中，进程内用锁保证判定原子性，不依赖 Redis、数据库等任何外部服务。

---

## 目录结构

```
app/
  models.py    # 数据模型：Credential / Caller / Principal
  errors.py    # 6 种可区分失败原因 + 统一错误构造
  security.py  # 密钥生成、SHA-256 哈希、Bearer 头解析
  scopes.py    # 范围定义与判定
  store.py     # JSON 持久化 + RLock + 原子配额扣减（核心）
  quota.py     # 固定窗口配额服务（含 Retry-After 计算）
  deps.py      # FastAPI 依赖：认证→吊销/过期→范围→配额，含判定日志
  admin.py     # 管理接口：签发/轮换/吊销/查询
  server.py    # 应用工厂、引导管理员、公开与受保护路由
tests/         # 30 个测试，含真实 HTTP 并发与重启持久化
```

## 快速开始

```bash
uv sync

# 启动（可选：注入一个引导管理员密钥，仅在首次启动时落盘其哈希）
BOOTSTRAP_ADMIN_KEY=ak_root_change_me uv run uvicorn main:app --reload
```

默认状态文件：`data/auth_state.json`（可用环境变量 `AUTH_STATE_PATH` 覆盖）。

### 接口一览

| 方法 & 路径 | 鉴权要求 | 说明 |
| --- | --- | --- |
| `GET /` | 公开 | 始终返回 `{"Hello": "World"}`，契约不受鉴权影响 |
| `GET /items` | `items:read` | 受保护业务接口示例 |
| `POST /items` | `items:write` | 受保护业务接口示例 |
| `POST /admin/keys` | `admin` | 签发凭证 |
| `POST /admin/keys/rotate` | `admin` | 轮换凭证 |
| `POST /admin/keys/revoke` | `admin` | 吊销凭证 |
| `GET /admin/callers` | `admin` | 查询调用方、凭证元数据与配额计数 |

## 凭证生命周期

- **签发**：`POST /admin/keys`，请求体：

  ```json
  {
    "caller_id": "alice",
    "scopes": ["items:read"],
    "expires_in_seconds": 3600,
    "quota_limit": 100,
    "quota_window_seconds": 3600
  }
  ```

  响应中的 `api_key`（形如 `ak_<64hex>`）**只出现这一次**；`key_id`（`kid_<16hex>`）用于后续管理与日志追踪，不含密钥信息。
- **存储**：状态文件只保存 `SHA-256(api_key)`。凭证明文无法从文件恢复。
- **轮换**：`POST /admin/keys/rotate` 原子完成"旧凭证吊销 + 新凭证签发"，范围继承、**配额计数保留**，响应再次返回一次性明文。
- **吊销**：`POST /admin/keys/revoke` 立即生效，重复吊销幂等（`changed=false`）。
- **过期**：签发时可设 `expires_in_seconds`；过期判定使用服务器当前时间，过期后再请求被拒。

### 失败原因（全部可区分）

| HTTP | reason | 场景 |
| --- | --- | --- |
| 401 | `missing_api_key` | 缺少 Authorization 头或不是 Bearer 方案 |
| 401 | `invalid_api_key` | 提供了密钥但哈希无法识别 |
| 401 | `revoked_api_key` | 凭证已吊销（响应含 `key_id`） |
| 401 | `expired_api_key` | 凭证已过期（响应含 `key_id`） |
| 403 | `insufficient_scope` | 已认证但缺少接口所需范围 |
| 429 | `quota_exceeded` | 本窗口配额耗尽，响应头 `Retry-After` 给出重试秒数 |
| 400 | `bad_request` | 请求参数错误（如签发未知 scope） |

错误响应统一形如：

```json
{
  "error": {
    "reason": "quota_exceeded",
    "message": "访问配额已耗尽，请在 42 秒后重试。",
    "key_id": "kid_...",
    "retry_after": 42
  }
}
```

401 响应还带 `WWW-Authenticate: Bearer realm="api-key"` 头。

## 权限范围模型

- 可选范围：`items:read`、`items:write`、`admin`（见 `app/scopes.py`）。
- 每个凭证在签发时被授予一个范围集合；每个受保护接口声明**单一必需范围**，精确匹配。
- `admin` 不隐式包含业务范围：管理员密钥访问 `/items` 同样得到 403；业务密钥访问 `/admin/*` 同样 403。
- 未认证（401）与已认证但越权（403）是两条独立失败路径，原因码不同。
- 公开接口 `GET /` 不经过任何鉴权依赖，行为与响应契约在启用鉴权前后完全一致。

## 配额规则

- **粒度**：按**调用方**（`caller_id`）计量，同一调用方的多把凭证共享一个计数器。
- **模型**：固定窗口。每窗口 `quota_limit` 次；窗口结束后计数清零重新计量。
- **并发安全**：`哈希查找 → 吊销/过期/范围判定 → 配额扣减` 整条路径在 `threading.RLock` 临界区内完成；扣减成功立即 fsync + 原子 rename 落盘。因此并发请求最多放行 `limit` 次，不会突破限额。
- **重启延续**：计数与窗口起点持久化在状态文件中，服务重启后不会静默重置；只有窗口自然到期才清零。
- **超额反馈**：429 响应同时提供响应头 `Retry-After: <秒>` 与 JSON 中的 `retry_after` 字段，给出明确重试依据。
- 被拒绝（401/403/429）的请求中，仅**通过认证与授权**的请求才会尝试扣减配额；429 不增加计数。

## 可解释性：判定日志

每次鉴权判定（放行或拒绝）都以 `app.auth` logger 输出一行，包含凭证标识、判定依据与配额计数。`pytest` 默认开启实时日志（见 `pytest.ini` 的 `log_cli`），例如：

```
INFO app.auth 判定=拒绝 reason=missing_api_key key_id=- 判定依据=Authorization 头缺失或非 Bearer 方案
INFO app.auth 判定=拒绝 reason=revoked_api_key key_id=kid_8f.. 判定依据=凭证 revoked=True
INFO app.auth 判定=放行 reason=ok key_id=kid_c3.. caller_id=alice 判定依据=凭证有效且范围满足 required_scope=items:read quota=1/100
INFO app.auth 判定=拒绝 reason=quota_exceeded key_id=kid_.. 判定依据=固定窗口计数已达限额 quota=10/10 retry_after=60
```

## 本地验证

```bash
uv run pytest -q          # 30 个测试，实时打印判定日志
```

测试覆盖：

- **凭证生命周期**：缺失/无效/已吊销/已过期分别被拒且原因可区分；合法请求不误拒；轮换后旧钥吊销、新钥可用且配额保留。
- **越权访问**：缺范围返回 403 并与 401 区分；业务范围与 `admin` 双向隔离；公开接口契约不变。
- **并发接近限额**：TestClient 50 并发抢 10 名额恰好放行 10；真实 uvicorn + httpx 100 并发抢 25 名额恰好放行 25，其余 75 全部 429 且带 `Retry-After`。
- **重启后配额延续**：新建应用实例从同一状态文件恢复，已耗尽配额仍为 429；吊销状态延续；引导管理员幂等；状态文件中无任何明文密钥。

### 手工演练（curl）

```bash
BOOTSTRAP_ADMIN_KEY=ak_root_change_me uv run uvicorn main:app --port 8000 &

# 签发
curl -s -X POST localhost:8000/admin/keys -H "Authorization: Bearer ak_root_change_me" \
  -H 'Content-Type: application/json' \
  -d '{"caller_id":"alice","scopes":["items:read"],"quota_limit":3,"quota_window_seconds":60}'

# 调用（把 ak_... 换成上一步返回的明文）
curl -i localhost:8000/items -H "Authorization: Bearer ak_..."
# 第 4 次：HTTP/1.1 429，Retry-After 头与 reason=quota_exceeded
```

## 设计说明与边界

- 哈希采用 SHA-256（无加盐）：API Key 是 256 位高熵随机串，本身足以抵抗字典/彩虹表；查找时对所有已存哈希做 `hmac.compare_digest` 常量时间比较。
- 持久化为单文件 JSON + 进程锁，适用于单实例本地验证场景；多实例水平扩展需要换用共享存储（不在本项目范围）。
