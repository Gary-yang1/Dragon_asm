#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

APP_IMAGE="${APP_IMAGE:-asm-backend-dev}"
API_CONTAINER="${API_CONTAINER:-asm-api-dev}"
WORKER_CONTAINER="${WORKER_CONTAINER:-asm-worker-dev}"
REDIS_SERVICE="${REDIS_SERVICE:-redis}"

API_PORT="${API_PORT:-8081}"
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
REPORT_EXPORT_DIR="${REPORT_EXPORT_DIR:-/tmp/asm-report-exports}"
ASSET_MISS_THRESHOLD="${ASSET_MISS_THRESHOLD:-3}"

DB_DSN="${DB_USER}:${DB_PASSWORD}@tcp(${DB_HOST_FOR_MIGRATE}:${DB_PORT})/${DB_NAME}?parseTime=true&loc=UTC&charset=utf8mb4"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
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

run_migrations() {
  echo "==> Running migrations"
  DB_DSN="$DB_DSN" make migrate-up
}

build_image() {
  echo "==> Building backend image: ${APP_IMAGE}"
  docker build -t "$APP_IMAGE" .
}

start_containers() {
  echo "==> Replacing backend containers"
  docker rm -f "$API_CONTAINER" "$WORKER_CONTAINER" >/dev/null 2>&1 || true

  docker run -d --name "$API_CONTAINER" \
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
    -e REPORT_EXPORT_DIR="$REPORT_EXPORT_DIR" \
    -e ASSET_MISS_THRESHOLD="$ASSET_MISS_THRESHOLD" \
    "$APP_IMAGE" /app/api >/dev/null

  docker run -d --name "$WORKER_CONTAINER" \
    -e DB_HOST="$DB_HOST_FOR_CONTAINER" \
    -e DB_PORT="$DB_PORT" \
    -e DB_USER="$DB_USER" \
    -e DB_PASSWORD="$DB_PASSWORD" \
    -e DB_NAME="$DB_NAME" \
    -e REDIS_ADDR="$REDIS_ADDR_FOR_CONTAINER" \
    -e REDIS_PASSWORD="$REDIS_PASSWORD" \
    -e REPORT_EXPORT_DIR="$REPORT_EXPORT_DIR" \
    "$APP_IMAGE" /app/worker >/dev/null
}

health_check() {
  echo "==> Checking API health"
  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${API_PORT}/healthz" >/dev/null; then
      curl -fsS "http://127.0.0.1:${API_PORT}/healthz"
      echo
      return
    fi
    sleep 1
  done

  echo "API did not become healthy. Recent logs:" >&2
  docker logs --tail 80 "$API_CONTAINER" >&2 || true
  exit 1
}

status() {
  docker ps \
    --filter "name=${API_CONTAINER}" \
    --filter "name=${WORKER_CONTAINER}" \
    --filter "name=asm-redis-1" \
    --filter "name=${MYSQL_CONTAINER}" \
    --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
}

start() {
  require_cmd docker
  require_cmd make
  require_cmd migrate
  require_cmd curl

  start_redis
  ensure_database
  run_migrations
  build_image
  start_containers
  health_check
  status

  echo
  echo "Backend started: http://127.0.0.1:${API_PORT}"
}

stop() {
  require_cmd docker
  docker rm -f "$API_CONTAINER" "$WORKER_CONTAINER" >/dev/null 2>&1 || true
  echo "Backend containers stopped."
}

logs() {
  require_cmd docker
  docker logs -f "$API_CONTAINER" "$WORKER_CONTAINER"
}

case "${1:-start}" in
  start)
    start
    ;;
  restart)
    stop
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
