#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE=(docker compose -p asm-ext09-e2e -f "$ROOT_DIR/docker-compose.e2e.yml")
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/asm-ext09.XXXXXX")
CONTROL_DIR="$WORK_DIR/control"
mkdir -p "$CONTROL_DIR"
PIDS=()

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    for log in "$WORK_DIR"/*.log; do
      [[ -f "$log" ]] || continue
      echo "===== $(basename "$log") =====" >&2
      tail -n 100 "$log" >&2 || true
    done
  fi
  if [[ ${#PIDS[@]} -gt 0 ]]; then
    kill "${PIDS[@]}" 2>/dev/null || true
    wait "${PIDS[@]}" 2>/dev/null || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
  exit "$status"
}
trap cleanup EXIT INT TERM

cd "$ROOT_DIR"
"${COMPOSE[@]}" up -d --wait

for migration in migrations/*.up.sql; do
  "${COMPOSE[@]}" exec -T mysql-e2e \
    mysql --default-character-set=utf8mb4 -uasm -pchangeme asm_e2e < "$migration"
done

go build -o "$WORK_DIR/api" ./cmd/api
go build -o "$WORK_DIR/worker" ./cmd/worker
go build -o "$WORK_DIR/mock-provider" ./integration/ext09/mockprovider
go build -o "$WORK_DIR/e2e-driver" ./integration/ext09/driver
(cd engines/baiyan && go build -o "$WORK_DIR/baiyan-engine" ./cmd/baiyan-engine)

MOCK_PROVIDER_TOKEN=mock-provider-token \
MOCK_PROVIDER_ADDR=127.0.0.1:19191 \
  "$WORK_DIR/mock-provider" >"$WORK_DIR/mock-provider.log" 2>&1 &
PIDS+=("$!")

DB_HOST=127.0.0.1 DB_PORT=3307 DB_USER=asm DB_PASSWORD=changeme DB_NAME=asm_e2e \
REDIS_ADDR=127.0.0.1:16379 REDIS_PASSWORD= \
GIN_MODE=release API_PORT=18080 \
JWT_ACCESS_SECRET=e2e-access-secret-at-least-32-bytes JWT_REFRESH_SECRET=e2e-refresh-secret-at-least-32-bytes \
DISCOVERY_CALLBACK_SECRET=e2e-callback-secret \
DISCOVERY_CALLBACK_SECRET_REF=baiyan-e2e \
DISCOVERY_CALLBACK_SECRETS='{"baiyan-old":"e2e-old-callback-secret","baiyan-e2e":"e2e-callback-secret"}' \
DISCOVERY_CALLBACK_BASE_URL=http://127.0.0.1:18080 \
DISCOVERY_ENGINE_BASE_URL=http://127.0.0.1:19090 \
DISCOVERY_ENGINE_TOKEN=e2e-engine-token \
  "$WORK_DIR/api" >"$WORK_DIR/api.log" 2>&1 &
PIDS+=("$!")

DB_HOST=127.0.0.1 DB_PORT=3307 DB_USER=asm DB_PASSWORD=changeme DB_NAME=asm_e2e \
REDIS_ADDR=127.0.0.1:16379 REDIS_PASSWORD= \
DISCOVERY_CALLBACK_BASE_URL=http://127.0.0.1:18080 \
DISCOVERY_ENGINE_BASE_URL=http://127.0.0.1:19090 \
DISCOVERY_ENGINE_TOKEN=e2e-engine-token \
ASSET_MISS_THRESHOLD=3 \
  "$WORK_DIR/worker" >"$WORK_DIR/worker.log" 2>&1 &
PIDS+=("$!")

start_engine() {
  BAIYAN_LISTEN_ADDR=127.0.0.1:19090 \
  BAIYAN_ENGINE_TOKEN=e2e-engine-token \
  BAIYAN_ENGINE_ID=baiyan-e2e \
  BAIYAN_CALLBACK_SECRET=e2e-callback-secret \
  BAIYAN_CALLBACK_ALLOWED_ORIGIN=http://127.0.0.1:18080 \
  BAIYAN_JOB_STORE_DIR="$WORK_DIR/jobs" \
  BAIYAN_PASSIVE_PROVIDER_NAME=certificate_transparency \
  BAIYAN_PASSIVE_PROVIDER_URL=http://127.0.0.1:19191/subdomains \
  BAIYAN_PASSIVE_PROVIDER_TOKEN=mock-provider-token \
  BAIYAN_DNS_PROVIDER_URL=http://127.0.0.1:19191/dns \
  BAIYAN_DNS_PROVIDER_TOKEN=mock-provider-token \
    "$WORK_DIR/baiyan-engine" >>"$WORK_DIR/baiyan-engine.log" 2>&1 &
  ENGINE_PID=$!
  PIDS+=("$ENGINE_PID")
}

: >"$WORK_DIR/baiyan-engine.log"
start_engine

for _ in {1..100}; do
  if curl -fsS http://127.0.0.1:18080/healthz >/dev/null 2>&1 && \
     curl -sS -o /dev/null -H 'Authorization: Bearer e2e-engine-token' http://127.0.0.1:19090/scan/job-0 2>/dev/null; then
    break
  fi
  sleep 0.1
done
curl -fsS http://127.0.0.1:18080/healthz >/dev/null 2>&1
curl -sS -o /dev/null -H 'Authorization: Bearer e2e-engine-token' http://127.0.0.1:19090/scan/job-0

for pid in "${PIDS[@]}"; do
  command_line=$(ps -o command= -p "$pid")
  if [[ "$command_line" == *masscan* || "$command_line" == *dirscan* || "$command_line" == *observer_ward* ]]; then
    echo "active scanner process detected: $command_line" >&2
    exit 1
  fi
done

E2E_DB_DSN='asm:changeme@tcp(127.0.0.1:3307)/asm_e2e?parseTime=true&loc=UTC&charset=utf8mb4' \
E2E_REDIS_ADDR=127.0.0.1:16379 \
E2E_API_URL=http://127.0.0.1:18080 \
E2E_ENGINE_URL=http://127.0.0.1:19090 \
E2E_ENGINE_TOKEN=e2e-engine-token \
E2E_ENGINE_ID=baiyan-e2e \
E2E_CALLBACK_SECRET=e2e-callback-secret \
E2E_PROVIDER_URL=http://127.0.0.1:19191 \
E2E_PROVIDER_TOKEN=mock-provider-token \
E2E_JWT_ACCESS_SECRET=e2e-access-secret-at-least-32-bytes \
E2E_JWT_REFRESH_SECRET=e2e-refresh-secret-at-least-32-bytes \
E2E_CONTROL_DIR="$CONTROL_DIR" \
  "$WORK_DIR/e2e-driver" >"$WORK_DIR/e2e-driver.log" 2>&1 &
DRIVER_PID=$!
PIDS+=("$DRIVER_PID")

while kill -0 "$DRIVER_PID" 2>/dev/null; do
  if [[ -f "$CONTROL_DIR/engine-restart.request" && ! -f "$CONTROL_DIR/engine-restart.done" ]]; then
    kill -9 "$ENGINE_PID"
    wait "$ENGINE_PID" 2>/dev/null || true
    previous_engine_pid="$ENGINE_PID"
    kept_pids=()
    for pid in "${PIDS[@]}"; do
      [[ "$pid" == "$previous_engine_pid" ]] || kept_pids+=("$pid")
    done
    PIDS=("${kept_pids[@]}")
    start_engine
    for _ in {1..100}; do
      if curl -sS -o /dev/null -H 'Authorization: Bearer e2e-engine-token' http://127.0.0.1:19090/scan/job-0 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    curl -sS -o /dev/null -H 'Authorization: Bearer e2e-engine-token' http://127.0.0.1:19090/scan/job-0
    touch "$CONTROL_DIR/engine-restart.done"
  fi
  if [[ -f "$CONTROL_DIR/redis-stop.request" && ! -f "$CONTROL_DIR/redis-stop.done" ]]; then
    "${COMPOSE[@]}" stop redis-e2e >/dev/null
    touch "$CONTROL_DIR/redis-stop.done"
  fi
  if [[ -f "$CONTROL_DIR/redis-start.request" && ! -f "$CONTROL_DIR/redis-start.done" ]]; then
    "${COMPOSE[@]}" up -d --wait redis-e2e >/dev/null
    touch "$CONTROL_DIR/redis-start.done"
  fi
  sleep 0.05
done

wait "$DRIVER_PID"
cat "$WORK_DIR/e2e-driver.log"
