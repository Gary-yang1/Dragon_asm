-- sqlc queries for the auth (app_user) domain.
-- Every read filters on the soft-delete sentinel so soft-deleted rows are
-- excluded by default; callers never need to remember to add the filter.

-- name: GetUserByUsername :one
-- Login lookup. username is globally unique, so this returns at most one live row.
SELECT * FROM app_user
WHERE username = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetUserByID :one
SELECT * FROM app_user
WHERE id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: CreateUser :execresult
-- Provisioning helper (used by seeding/tests; no public registration endpoint in M0-6).
INSERT INTO app_user (
    tenant_id, org_id, username, display_name, password_hash, status, created_by, updated_by
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
