#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
IMAGE_NAME=${BAIYAN_ENGINE_TEST_IMAGE:-asm-baiyan-engine:security-test}
CONTAINER_NAME=asm-baiyan-engine-security-test
VOLUME_NAME=asm-baiyan-engine-security-test-jobs

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
cleanup

docker build \
  --file "$ROOT_DIR/engines/baiyan/Dockerfile.engine" \
  --tag "$IMAGE_NAME" \
  "$ROOT_DIR/engines/baiyan"

configured_user=$(docker image inspect --format '{{.Config.User}}' "$IMAGE_NAME")
if [[ "$configured_user" != "10001:10001" ]]; then
  echo "unexpected image user: $configured_user" >&2
  exit 1
fi

docker volume create "$VOLUME_NAME" >/dev/null
docker run --detach \
  --name "$CONTAINER_NAME" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --mount "type=volume,source=$VOLUME_NAME,target=/var/lib/baiyan/jobs" \
  --env BAIYAN_LISTEN_ADDR=:9090 \
  --env BAIYAN_ENGINE_TOKEN=image-test-engine-token \
  --env BAIYAN_ENGINE_ID=image-test-engine \
  --env BAIYAN_CALLBACK_SECRET=image-test-callback-secret \
  --env BAIYAN_CALLBACK_ALLOWED_ORIGIN=http://asm-api:8080 \
  "$IMAGE_NAME" >/dev/null

for _ in {1..50}; do
  if [[ $(docker inspect --format '{{.State.Running}}' "$CONTAINER_NAME") == "true" ]]; then
    break
  fi
  sleep 0.1
done

if [[ $(docker inspect --format '{{.State.Running}}' "$CONTAINER_NAME") != "true" ]]; then
  docker logs "$CONTAINER_NAME" >&2
  exit 1
fi
if [[ $(docker exec "$CONTAINER_NAME" id -u) != "10001" ]]; then
  echo "engine process is not running as uid 10001" >&2
  exit 1
fi
docker exec "$CONTAINER_NAME" sh -c 'touch /var/lib/baiyan/jobs/.write-test && test -w /var/lib/baiyan/jobs'
docker exec "$CONTAINER_NAME" sh -c 'test -x /app/baiyan-engine && test "$(find /app -mindepth 1 -maxdepth 1 | wc -l)" -eq 1'

readonly_rootfs=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$CONTAINER_NAME")
cap_drop=$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$CONTAINER_NAME")
security_opt=$(docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$CONTAINER_NAME")
if [[ "$readonly_rootfs" != "true" || "$cap_drop" != *"ALL"* || "$security_opt" != *"no-new-privileges:true"* ]]; then
  echo "container hardening options are incomplete" >&2
  exit 1
fi

printf '{"image":"%s","user":"%s","read_only":%s,"cap_drop":%s,"security_opt":%s,"job_store_writable":true,"app_files":1}\n' \
  "$IMAGE_NAME" "$configured_user" "$readonly_rootfs" "$cap_drop" "$security_opt"
