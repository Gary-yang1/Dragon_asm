#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

dotenv_value() {
  local key="$1"
  local line

  [[ -f "$ROOT_DIR/.env" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    case "$line" in
      "${key}="*)
        printf '%s' "${line#*=}"
        return 0
        ;;
    esac
  done <"$ROOT_DIR/.env"
}

APP_IMAGE="${APP_IMAGE:-asm-backend-dev}"
API_CONTAINER="${API_CONTAINER:-asm-api-dev}"
WORKER_CONTAINER="${WORKER_CONTAINER:-asm-worker-dev}"
REDIS_SERVICE="${REDIS_SERVICE:-redis}"
BAIYAN_SERVICE="${BAIYAN_SERVICE:-baiyan-engine}"
REBUILD_BACKEND="${REBUILD_BACKEND:-1}"

API_PORT="${API_PORT:-8081}"
BAIYAN_ENGINE_PORT="${BAIYAN_ENGINE_PORT:-9090}"
APP_VERSION="${APP_VERSION:-dev}"
GIN_MODE="${GIN_MODE:-debug}"

DB_HOST_FOR_MIGRATE="${DB_HOST_FOR_MIGRATE:-127.0.0.1}"
DB_HOST_FOR_CONTAINER="${DB_HOST_FOR_CONTAINER:-host.docker.internal}"
DB_PORT="${DB_PORT:-3306}"
DB_NAME="${DB_NAME:-asm}"
DB_USER="${DB_USER:-asm}"
DB_PASSWORD="${DB_PASSWORD:-changeme}"

MYSQL_CONTAINER="${MYSQL_CONTAINER:-mysql-server}"
MYSQL_ROOT_USER="${MYSQL_ROOT_USER:-root}"
MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-yourpassword}"

REDIS_ADDR_FOR_CONTAINER="${REDIS_ADDR_FOR_CONTAINER:-host.docker.internal:6379}"
REDIS_PASSWORD="${REDIS_PASSWORD:-}"

JWT_ACCESS_SECRET="${JWT_ACCESS_SECRET:-dev-access-secret-change-me-very-long}"
JWT_REFRESH_SECRET="${JWT_REFRESH_SECRET:-dev-refresh-secret-change-me-very-long}"
DISCOVERY_CALLBACK_SECRET="${DISCOVERY_CALLBACK_SECRET:-dev-callback-secret-change-me-very-long}"
DISCOVERY_CALLBACK_SECRET_REF="${DISCOVERY_CALLBACK_SECRET_REF:-baiyan-primary}"
DISCOVERY_CALLBACK_BASE_URL="${DISCOVERY_CALLBACK_BASE_URL:-http://host.docker.internal:${API_PORT}}"
PROCESS_PASSIVE_ENGINE_TOKEN="${DISCOVERY_PASSIVE_ENGINE_TOKEN:-}"
PROCESS_LEGACY_ENGINE_TOKEN="${DISCOVERY_ENGINE_TOKEN:-}"
DOTENV_PASSIVE_ENGINE_TOKEN="$(dotenv_value DISCOVERY_PASSIVE_ENGINE_TOKEN)"
DOTENV_LEGACY_ENGINE_TOKEN="$(dotenv_value DISCOVERY_ENGINE_TOKEN)"
CONFIGURED_PASSIVE_ENGINE_TOKEN="${PROCESS_PASSIVE_ENGINE_TOKEN:-${PROCESS_LEGACY_ENGINE_TOKEN:-${DOTENV_PASSIVE_ENGINE_TOKEN:-$DOTENV_LEGACY_ENGINE_TOKEN}}}"
PASSIVE_ENGINE_TOKEN_FILE="$ROOT_DIR/secrets/baiyan-engine-token"
DISCOVERY_PASSIVE_ENGINE_TOKEN=""
# This script always starts its own Baiyan container and publishes it on the
# host. Pin the API/Worker route to that instance instead of allowing an
# environment override to start one engine while monitoring another.
DISCOVERY_PASSIVE_ENGINE_BASE_URL="http://host.docker.internal:${BAIYAN_ENGINE_PORT}"
# Keep the legacy aliases available to older backend images during local
# upgrades. New images receive the explicit passive-engine variables below.
DISCOVERY_ENGINE_BASE_URL="$DISCOVERY_PASSIVE_ENGINE_BASE_URL"
DISCOVERY_ENGINE_TOKEN=""
DISCOVERY_ACTIVE_ENGINE_BASE_URL="${DISCOVERY_ACTIVE_ENGINE_BASE_URL:-$(dotenv_value DISCOVERY_ACTIVE_ENGINE_BASE_URL)}"
DISCOVERY_ACTIVE_ENGINE_ACCESS_KEY="${DISCOVERY_ACTIVE_ENGINE_ACCESS_KEY:-$(dotenv_value DISCOVERY_ACTIVE_ENGINE_ACCESS_KEY)}"
DISCOVERY_ACTIVE_ENGINE_SECRET_KEY="${DISCOVERY_ACTIVE_ENGINE_SECRET_KEY:-$(dotenv_value DISCOVERY_ACTIVE_ENGINE_SECRET_KEY)}"
DISCOVERY_ACTIVE_ENGINE_PROJECT_MAP="${DISCOVERY_ACTIVE_ENGINE_PROJECT_MAP:-$(dotenv_value DISCOVERY_ACTIVE_ENGINE_PROJECT_MAP)}"
DISCOVERY_ACTIVE_DISPATCH_ENABLED="${DISCOVERY_ACTIVE_DISPATCH_ENABLED:-$(dotenv_value DISCOVERY_ACTIVE_DISPATCH_ENABLED)}"
DISCOVERY_ACTIVE_REQUIRE_APPROVAL="${DISCOVERY_ACTIVE_REQUIRE_APPROVAL:-$(dotenv_value DISCOVERY_ACTIVE_REQUIRE_APPROVAL)}"
DISCOVERY_ACTIVE_REQUIRE_OWNERSHIP="${DISCOVERY_ACTIVE_REQUIRE_OWNERSHIP:-$(dotenv_value DISCOVERY_ACTIVE_REQUIRE_OWNERSHIP)}"
REPORT_EXPORT_DIR="${REPORT_EXPORT_DIR:-/tmp/asm-report-exports}"
ASSET_MISS_THRESHOLD="${ASSET_MISS_THRESHOLD:-3}"

DB_DSN="${DB_USER}:${DB_PASSWORD}@tcp(${DB_HOST_FOR_MIGRATE}:${DB_PORT})/${DB_NAME}?parseTime=true&loc=UTC&charset=utf8mb4"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

is_strong_passive_engine_token() {
  local token="$1"
  [[ ${#token} -ge 32 ]] && [[ ! "$token" =~ [[:space:]] ]]
}

initialize_passive_engine_token() {
  local token=""
  local token_source="persisted"

  if [[ -f "$PASSIVE_ENGINE_TOKEN_FILE" ]]; then
    IFS= read -r token <"$PASSIVE_ENGINE_TOKEN_FILE" || true
    if ! is_strong_passive_engine_token "$token"; then
      echo "invalid persisted Baiyan token: remove $PASSIVE_ENGINE_TOKEN_FILE to regenerate it" >&2
      exit 1
    fi
    chmod 600 "$PASSIVE_ENGINE_TOKEN_FILE"
  else
    if is_strong_passive_engine_token "$CONFIGURED_PASSIVE_ENGINE_TOKEN"; then
      token="$CONFIGURED_PASSIVE_ENGINE_TOKEN"
      token_source="migrated from existing configuration"
    else
      if [[ -n "$CONFIGURED_PASSIVE_ENGINE_TOKEN" ]]; then
        echo "==> Ignoring weak legacy Baiyan token and generating a secure replacement"
      fi
      require_cmd openssl
      token="$(openssl rand -hex 32)"
      token_source="generated"
    fi

    mkdir -p "$(dirname "$PASSIVE_ENGINE_TOKEN_FILE")"
    chmod 700 "$(dirname "$PASSIVE_ENGINE_TOKEN_FILE")"
    local temporary_token_file
    temporary_token_file="$(mktemp "${PASSIVE_ENGINE_TOKEN_FILE}.tmp.XXXXXX")"
    chmod 600 "$temporary_token_file"
    printf '%s\n' "$token" >"$temporary_token_file"
    if ln "$temporary_token_file" "$PASSIVE_ENGINE_TOKEN_FILE" 2>/dev/null; then
      rm -f "$temporary_token_file"
    else
      # A concurrent launcher created the canonical token first. Reuse that
      # winner so independently started containers cannot receive two tokens.
      rm -f "$temporary_token_file"
      IFS= read -r token <"$PASSIVE_ENGINE_TOKEN_FILE" || true
      if ! is_strong_passive_engine_token "$token"; then
        echo "invalid persisted Baiyan token: remove $PASSIVE_ENGINE_TOKEN_FILE to regenerate it" >&2
        exit 1
      fi
      token_source="persisted (created concurrently)"
    fi
  fi

  DISCOVERY_PASSIVE_ENGINE_TOKEN="$token"
  DISCOVERY_ENGINE_TOKEN="$token"
  echo "==> Baiyan token ready (${token_source}; stored outside Git)"
}

initialize_engine_settings_key() {
  require_cmd openssl
  local key_file="$ROOT_DIR/secrets/engine-settings.key"
  mkdir -p "$ROOT_DIR/secrets"
  if [[ ! -f "$key_file" ]]; then
    local temporary_key_file
    temporary_key_file="$(mktemp "$ROOT_DIR/secrets/engine-settings.key.tmp.XXXXXX")"
    chmod 600 "$temporary_key_file"
    openssl rand 32 >"$temporary_key_file"
    ln "$temporary_key_file" "$key_file" 2>/dev/null || true
    rm -f "$temporary_key_file"
  fi
  chmod 600 "$key_file"
  [[ "$(wc -c < "$key_file" | tr -d ' ')" == "32" ]] || { echo "invalid engine settings encryption key" >&2; exit 1; }
  echo "==> Engine settings encryption key ready (stored outside Git)"
}

ensure_database() {
  echo "==> Ensuring MySQL database and user exist"
  docker exec "$MYSQL_CONTAINER" mysql \
    --default-character-set=utf8mb4 \
    -u"$MYSQL_ROOT_USER" \
    -p"$MYSQL_ROOT_PASSWORD" \
    -e "CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        CREATE USER IF NOT EXISTS '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASSWORD}';
        ALTER USER '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASSWORD}';
        GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'%';
        FLUSH PRIVILEGES;"
}

start_redis() {
  echo "==> Starting Redis"
  docker compose up -d "$REDIS_SERVICE"
}

build_baiyan() {
  echo "==> Building Baiyan discovery engine"
  docker compose --profile baiyan build "$BAIYAN_SERVICE"
}

start_baiyan() {
  echo "==> Starting Baiyan discovery engine"
  BAIYAN_ENGINE_PORT="$BAIYAN_ENGINE_PORT" \
    BAIYAN_CALLBACK_ALLOWED_ORIGIN="$DISCOVERY_CALLBACK_BASE_URL" \
    DISCOVERY_PASSIVE_ENGINE_TOKEN="$DISCOVERY_PASSIVE_ENGINE_TOKEN" \
    DISCOVERY_ENGINE_TOKEN="$DISCOVERY_ENGINE_TOKEN" \
    DISCOVERY_CALLBACK_SECRET="$DISCOVERY_CALLBACK_SECRET" \
    DISCOVERY_CALLBACK_SECRET_REF="$DISCOVERY_CALLBACK_SECRET_REF" \
    docker compose --profile baiyan up -d --no-build "$BAIYAN_SERVICE"
}

run_migrations() {
  echo "==> Running migrations"
  DB_DSN="$DB_DSN" make migrate-up
}

build_image() {
  if [[ "$REBUILD_BACKEND" == "0" ]]; then
    if docker image inspect "$APP_IMAGE" >/dev/null 2>&1; then
      echo "==> Reusing backend image: ${APP_IMAGE}"
      return
    fi
    echo "backend image ${APP_IMAGE} does not exist; cannot reuse it" >&2
    exit 1
  fi
  echo "==> Building backend image: ${APP_IMAGE}"
  docker build -t "$APP_IMAGE" .
}

start_containers() {
  echo "==> Replacing backend containers"
  docker rm -f "$API_CONTAINER" "$WORKER_CONTAINER" >/dev/null 2>&1 || true

  docker run -d --name "$API_CONTAINER" \
    -v "$ROOT_DIR/secrets/engine-settings.key:/run/secrets/engine-settings.key:ro" \
    -e ENGINE_SETTINGS_KEY_FILE=/run/secrets/engine-settings.key \
    -p "${API_PORT}:${API_PORT}" \
    -e API_PORT="$API_PORT" \
    -e GIN_MODE="$GIN_MODE" \
    -e APP_VERSION="$APP_VERSION" \
    -e DB_HOST="$DB_HOST_FOR_CONTAINER" \
    -e DB_PORT="$DB_PORT" \
    -e DB_USER="$DB_USER" \
    -e DB_PASSWORD="$DB_PASSWORD" \
    -e DB_NAME="$DB_NAME" \
    -e REDIS_ADDR="$REDIS_ADDR_FOR_CONTAINER" \
    -e REDIS_PASSWORD="$REDIS_PASSWORD" \
    -e JWT_ACCESS_SECRET="$JWT_ACCESS_SECRET" \
    -e JWT_REFRESH_SECRET="$JWT_REFRESH_SECRET" \
    -e DISCOVERY_CALLBACK_SECRET="$DISCOVERY_CALLBACK_SECRET" \
    -e DISCOVERY_CALLBACK_SECRET_REF="$DISCOVERY_CALLBACK_SECRET_REF" \
    -e DISCOVERY_CALLBACK_BASE_URL="$DISCOVERY_CALLBACK_BASE_URL" \
    -e DISCOVERY_PASSIVE_ENGINE_BASE_URL="$DISCOVERY_PASSIVE_ENGINE_BASE_URL" \
    -e DISCOVERY_PASSIVE_ENGINE_TOKEN="$DISCOVERY_PASSIVE_ENGINE_TOKEN" \
    -e DISCOVERY_ENGINE_BASE_URL="$DISCOVERY_ENGINE_BASE_URL" \
    -e DISCOVERY_ENGINE_TOKEN="$DISCOVERY_ENGINE_TOKEN" \
    -e DISCOVERY_ACTIVE_ENGINE_BASE_URL="$DISCOVERY_ACTIVE_ENGINE_BASE_URL" \
    -e DISCOVERY_ACTIVE_ENGINE_ACCESS_KEY="$DISCOVERY_ACTIVE_ENGINE_ACCESS_KEY" \
    -e DISCOVERY_ACTIVE_ENGINE_SECRET_KEY="$DISCOVERY_ACTIVE_ENGINE_SECRET_KEY" \
    -e DISCOVERY_ACTIVE_ENGINE_PROJECT_MAP="$DISCOVERY_ACTIVE_ENGINE_PROJECT_MAP" \
    -e DISCOVERY_ACTIVE_DISPATCH_ENABLED="$DISCOVERY_ACTIVE_DISPATCH_ENABLED" \
    -e DISCOVERY_ACTIVE_REQUIRE_APPROVAL="$DISCOVERY_ACTIVE_REQUIRE_APPROVAL" \
    -e DISCOVERY_ACTIVE_REQUIRE_OWNERSHIP="$DISCOVERY_ACTIVE_REQUIRE_OWNERSHIP" \
    -e REPORT_EXPORT_DIR="$REPORT_EXPORT_DIR" \
    -e ASSET_MISS_THRESHOLD="$ASSET_MISS_THRESHOLD" \
    "$APP_IMAGE" /app/api >/dev/null

  docker run -d --name "$WORKER_CONTAINER" \
    -v "$ROOT_DIR/secrets/engine-settings.key:/run/secrets/engine-settings.key:ro" \
    -e ENGINE_SETTINGS_KEY_FILE=/run/secrets/engine-settings.key \
    -e DB_HOST="$DB_HOST_FOR_CONTAINER" \
    -e DB_PORT="$DB_PORT" \
    -e DB_USER="$DB_USER" \
    -e DB_PASSWORD="$DB_PASSWORD" \
    -e DB_NAME="$DB_NAME" \
    -e REDIS_ADDR="$REDIS_ADDR_FOR_CONTAINER" \
    -e REDIS_PASSWORD="$REDIS_PASSWORD" \
    -e DISCOVERY_CALLBACK_BASE_URL="$DISCOVERY_CALLBACK_BASE_URL" \
    -e DISCOVERY_PASSIVE_ENGINE_BASE_URL="$DISCOVERY_PASSIVE_ENGINE_BASE_URL" \
    -e DISCOVERY_PASSIVE_ENGINE_TOKEN="$DISCOVERY_PASSIVE_ENGINE_TOKEN" \
    -e DISCOVERY_ENGINE_BASE_URL="$DISCOVERY_ENGINE_BASE_URL" \
    -e DISCOVERY_ENGINE_TOKEN="$DISCOVERY_ENGINE_TOKEN" \
    -e DISCOVERY_ACTIVE_ENGINE_BASE_URL="$DISCOVERY_ACTIVE_ENGINE_BASE_URL" \
    -e DISCOVERY_ACTIVE_ENGINE_ACCESS_KEY="$DISCOVERY_ACTIVE_ENGINE_ACCESS_KEY" \
    -e DISCOVERY_ACTIVE_ENGINE_SECRET_KEY="$DISCOVERY_ACTIVE_ENGINE_SECRET_KEY" \
    -e DISCOVERY_ACTIVE_ENGINE_PROJECT_MAP="$DISCOVERY_ACTIVE_ENGINE_PROJECT_MAP" \
    -e DISCOVERY_ACTIVE_DISPATCH_ENABLED="$DISCOVERY_ACTIVE_DISPATCH_ENABLED" \
    -e DISCOVERY_ACTIVE_REQUIRE_APPROVAL="$DISCOVERY_ACTIVE_REQUIRE_APPROVAL" \
    -e DISCOVERY_ACTIVE_REQUIRE_OWNERSHIP="$DISCOVERY_ACTIVE_REQUIRE_OWNERSHIP" \
    -e REPORT_EXPORT_DIR="$REPORT_EXPORT_DIR" \
    "$APP_IMAGE" /app/worker >/dev/null
}

health_check() {
  echo "==> Checking API health"
  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${API_PORT}/healthz" >/dev/null 2>&1; then
      login_status="$(curl -sS -o /dev/null -w '%{http_code}' \
        -X POST "http://127.0.0.1:${API_PORT}/api/v1/auth/login" \
        -H 'Content-Type: application/json' \
        --data '{}' || true)"
      if [[ "$login_status" == "400" ]]; then
        curl -fsS "http://127.0.0.1:${API_PORT}/healthz"
        echo
        return
      fi
    fi
    sleep 1
  done

  echo "API did not become ready with business routes mounted. Recent logs:" >&2
  docker logs --tail 80 "$API_CONTAINER" >&2 || true
  exit 1
}

baiyan_health_check() {
  echo "==> Checking Baiyan management status"
  local management_status
  for _ in $(seq 1 30); do
    management_status="$(curl -fsS \
      -H "Authorization: Bearer ${DISCOVERY_PASSIVE_ENGINE_TOKEN}" \
      "http://127.0.0.1:${BAIYAN_ENGINE_PORT}/management/status" 2>/dev/null || true)"
    if [[ "$management_status" == *'"status":"ready"'* ]]; then
      echo "Baiyan engine ready: http://127.0.0.1:${BAIYAN_ENGINE_PORT}/management/status"
      return
    fi
    sleep 1
  done

  echo "Baiyan engine did not become ready. Recent logs:" >&2
  docker compose --profile baiyan logs --tail 80 "$BAIYAN_SERVICE" >&2 || true
  exit 1
}

status() {
  docker ps \
    --filter "name=${API_CONTAINER}" \
    --filter "name=${WORKER_CONTAINER}" \
    --filter "name=${BAIYAN_SERVICE}" \
    --filter "name=asm-redis-1" \
    --filter "name=${MYSQL_CONTAINER}" \
    --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
}

start() {
  require_cmd docker
  require_cmd make
  require_cmd migrate
  require_cmd curl
  initialize_passive_engine_token
  initialize_engine_settings_key

  # Finish all network- and compiler-dependent work before touching the
  # running stack. A failed build therefore leaves current services online.
  build_baiyan
  build_image
  start_redis
  ensure_database
  run_migrations
  start_baiyan
  baiyan_health_check
  start_containers
  health_check
  status

  echo
  echo "Backend started: http://127.0.0.1:${API_PORT}"
}

stop() {
  require_cmd docker
  docker rm -f "$API_CONTAINER" "$WORKER_CONTAINER" >/dev/null 2>&1 || true
  docker compose --profile baiyan stop "$BAIYAN_SERVICE" >/dev/null 2>&1 || true
  echo "Backend containers stopped."
}

logs() {
  require_cmd docker
  docker logs -f "$API_CONTAINER" "$WORKER_CONTAINER"
}

main() {
  case "${1:-start}" in
    start)
      start
      ;;
    restart)
      # All build steps happen before their corresponding containers are
      # replaced, so a transient build failure leaves the running stack intact.
      start
      ;;
    stop)
      stop
      ;;
    status)
      status
      ;;
    logs)
      logs
      ;;
    *)
      echo "Usage: $0 [start|restart|stop|status|logs]" >&2
      exit 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
