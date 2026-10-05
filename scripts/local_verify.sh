#!/usr/bin/env bash
# 本地端到端验证脚本：启动服务 -> 公开接口 -> 签发 -> 越权/未认证区分
# -> 配额并发不超限 -> 自助查询 -> 在线调额（调高/调低）-> 重启延续
# -> 吊销 -> 关停。不依赖任何外部服务，退出自动清理临时数据目录。
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
echo "== 5. 并发接近限额：10 个并发读（此前 /me 已耗 1 次，剩余 2），恰好 2 个 200、8 个 429 =="
RESULT=$(seq 10 | xargs -P 10 -I{} curl -s -o /dev/null -w "%{http_code}\n" "${USER_H[@]}" "${BASE}/data/read")
echo "${RESULT}" | sort | uniq -c
N200=$(echo "${RESULT}" | grep -c "^200$")
N429=$(echo "${RESULT}" | grep -c "^429$")
[ "${N200}" = "2" ] && [ "${N429}" = "8" ] \
  || { echo "FAIL: 并发放行数 ${N200}x200/${N429}x429，期望 2x200/8x429"; exit 1; }

echo "== 6. 查询配额计数（持久化在 data/quotas.json） =="
curl -s "${ADMIN_H[@]}" "${BASE}/admin/keys/quotas/demo"; echo

echo
echo "== 6b. 调用方自助查询配额（GET /me/quota，无需 admin，不耗配额） =="
for _ in 1 2 3; do
  SELF=$(curl -s "${USER_H[@]}" "${BASE}/me/quota")
  echo "${SELF}"
done
USED=$(python3 -c "import json,sys;print(json.load(sys.stdin)['used'])" <<<"${SELF}")
[ "${USED}" = "3" ] || { echo "FAIL: 自助查询后 used=${USED}，期望 3（查询不得耗配额）"; exit 1; }

echo
echo "== 6c. 在线调高配额 3 -> 5（立即生效，已用 3 保留） =="
curl -s -X PUT "${ADMIN_H[@]}" -H 'Content-Type: application/json' \
  -d '{"limit":5}' "${BASE}/admin/keys/quotas/demo"; echo
R1=$(curl -s -o /dev/null -w "%{http_code}" "${USER_H[@]}" "${BASE}/data/read")
R2=$(curl -s -o /dev/null -w "%{http_code}" "${USER_H[@]}" "${BASE}/data/read")
R3=$(curl -s -o /dev/null -w "%{http_code}" "${USER_H[@]}" "${BASE}/data/read")
echo "调高后连续 3 个请求 -> ${R1} ${R2} ${R3}（期望 200 200 429）"
[ "${R1}/${R2}/${R3}" = "200/200/429" ] || { echo "FAIL: 调高未按期望生效"; exit 1; }

echo
echo "== 6d. 在线调低配额到 1（低于已用 5）：继续 429 并带 Retry-After =="
curl -s -X PUT "${ADMIN_H[@]}" -H 'Content-Type: application/json' \
  -d '{"limit":1}' "${BASE}/admin/keys/quotas/demo"; echo
HEADERS=$(curl -s -o /dev/null -D - "${USER_H[@]}" "${BASE}/data/read")
echo "${HEADERS}" | grep -Ei "^HTTP/|^retry-after"
echo "${HEADERS}" | grep -q "429" || { echo "FAIL: 调低后期望 429"; exit 1; }
echo "${HEADERS}" | grep -qi "^retry-after" || { echo "FAIL: 缺少 Retry-After"; exit 1; }

echo
echo "== 7. 重启服务，配额结论保持 429（已用 5 >= 上限 1） =="
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
echo "== 8. 吊销后请求被拒（401 revoked_key） =="
KEY_ID=$(python3 -c "import json,sys;print(json.load(sys.stdin)['key_id'])" <<<"${ISSUE}")
curl -s -o /dev/null "${ADMIN_H[@]}" -X POST "${BASE}/admin/keys/${KEY_ID}/revoke"
curl -s "${USER_H[@]}" "${BASE}/data/read"; echo
echo "== 全部本地验证完成 =="
