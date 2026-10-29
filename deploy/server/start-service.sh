#!/bin/sh
set -eu
case "${1:-}" in api|worker) ;; *) echo 'Expected api or worker' >&2; exit 64;; esac
DEPLOY_WAIT_ONLY=1 /app/migrate-deployment
exec "/app/$1"
