#!/usr/bin/env bash
# 本地端到端验证脚本：启动服务 -> 公开接口 -> 签发 -> 越权/未认证区分
# -> 配额并发不超限 -> 自助查询 -> 在线调额（调高/调低）-> 重启延续
# -> 吊销/过期 -> 关停。不依赖任何外部服务。
set -euo pipefail

DATA_DIR="$(mktemp -d)"
PORT="${PORT:-8765}"
BASE="http://127.0.0.1:${PORT}"
export AUTH_DATA_DIR="${DATA_DIR}"
export AUTH_DEFAULT_QUOTA_LIMIT=3
export AUTH_QUOTA_WINDOW_SECONDS=3600

echo "== data dir: ${DATA_DIR}"
uv run uvicorn main:app --host 127.0.0.1 --port "${PORT}" --log-level warning &
SERVER_PID=$!
trap 'kill ${SERVER_PID} 2>/dev/null || true; rm -rf "${DATA_DIR}"' EXIT

echo "== 等待服务启动 =="
for _ in $(seq 1 50); do
  curl -sf "${BASE}/" >/dev/null && break
  sleep 0.1
done

echo
echo "== 1. 公开接口（无需鉴权，契约不变） =="
curl -s "${BASE}/"; echo

echo "== 2. 未认证访问受保护接口（401 missing_key） =="
curl -s -o /dev/null -w "status=%{http_code}\n" "${BASE}/me"

echo "== 读取首次启动引导的管理员密钥 =="
ADMIN_KEY=$(tr -d '\n' < "${DATA_DIR}/admin_initial_key.txt")
ADMIN_H=(-H "Authorization: Bearer ${ADMIN_KEY}")

echo "== 3. 为 caller=demo 签发带 data:read、配额 3 的密钥 =="
ISSUE=$(curl -s "${ADMIN_H[@]}" -H 'Content-Type: application/json' \
  -d '{"caller_id":"demo","scopes":["data:read"],"quota_limit":3}' \
  "${BASE}/admin/keys")
echo "${ISSUE}"
USER_KEY=$(python3 -c "import json,sys;print(json.load(sys.stdin)['secret'])" <<<"${ISSUE}")
USER_H=(-H "Authorization: Bearer ${USER_KEY}")

echo
echo "== 4. 合法请求通过 / 越权 403 与未认证 401 可区分 =="
curl -s "${USER_H[@]}" "${BASE}/me"; echo
curl -s -o /dev/null -w "write status=%{http_code} (期望 403)\n" -X POST "${USER_H[@]}" "${BASE}/data/write"
curl -s -o /dev/null -w "bad key status=%{http_code} (期望 401)\n" -H "Authorization: Bearer ak_bad" "${BASE}/data/read"

echo
echo "== 5. 并发接近限额：10 个并发读，剩余额度 2（/me 已用 1），恰好 2 个 200、8 个 429 =="
seq 10 | xargs -P 10 -I{} curl -s -o /dev/null -w "%{http_code}\n" "${USER_H[@]}" "${BASE}/data/read" \
  | sort | uniq -c

echo "== 6. 查询配额计数（持久化在 data/quotas.json） =="
curl -s "${ADMIN_H[@]}" "${BASE}/admin/keys/quotas/demo"; echo

echo
echo "== 7. 调用方自助查询配额（自己的凭证即可，不消耗业务配额） =="
curl -s "${USER_H[@]}" "${BASE}/me/quota"; echo
curl -s "${USER_H[@]}" "${BASE}/me/quota" | python3 -c "import json,sys;d=json.load(sys.stdin);assert d['used']==3 and d['remaining']==0,d;print('自助查询不计数：used 仍为', d['used'])"

echo
echo "== 8. 在线调额：调高 3 -> 5，立即生效，已用量 3 保留 =="
curl -s -X PUT "${ADMIN_H[@]}" -H 'Content-Type: application/json' \
  -d '{"limit":5}' "${BASE}/admin/keys/quotas/demo"; echo
echo "-- 调高后恰好再放行 2 个（5-3），第 3 个 429 --"
seq 3 | xargs -P 3 -I{} curl -s -o /dev/null -w "%{http_code}\n" "${USER_H[@]}" "${BASE}/data/read" \
  | sort | uniq -c

echo
echo "== 9. 在线调额：调低 5 -> 1（低于已用量 5），继续 429 且带 Retry-After，已用量不清零 =="
curl -s -X PUT "${ADMIN_H[@]}" -H 'Content-Type: application/json' \
  -d '{"limit":1}' "${BASE}/admin/keys/quotas/demo"; echo
curl -s -o /dev/null -w "after lower status=%{http_code} (期望 429)\n" "${USER_H[@]}" "${BASE}/data/read"
curl -s "${USER_H[@]}" "${BASE}/me/quota"; echo

echo
echo "== 10. 重启服务，配额结论保持 429（调额与已用量均延续） =="
kill ${SERVER_PID}; wait ${SERVER_PID} 2>/dev/null || true
trap - EXIT
uv run uvicorn main:app --host 127.0.0.1 --port "${PORT}" --log-level warning &
SERVER_PID=$!
trap 'kill ${SERVER_PID} 2>/dev/null || true; rm -rf "${DATA_DIR}"' EXIT
for _ in $(seq 1 50); do
  curl -sf "${BASE}/" >/dev/null && break
  sleep 0.1
done
curl -s "${USER_H[@]}" -o /dev/null -w "after restart status=%{http_code} (期望 429)\n" "${BASE}/data/read"

echo
echo "== 11. 吊销后请求被拒（401 revoked_key） =="
KEY_ID=$(python3 -c "import json,sys;print(json.load(sys.stdin)['key_id'])" <<<"${ISSUE}")
curl -s -o /dev/null "${ADMIN_H[@]}" -X POST "${BASE}/admin/keys/${KEY_ID}/revoke"
curl -s "${USER_H[@]}" "${BASE}/data/read"; echo
echo "== 全部本地验证完成 =="
