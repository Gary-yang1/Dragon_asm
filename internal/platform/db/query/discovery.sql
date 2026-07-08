-- sqlc queries for the discovery scope domain.
-- All reads are scoped by project_id and soft-delete sentinel so cross-project
-- reads/writes cannot leak through missing repository checks.

-- name: CreateScope :execresult
INSERT INTO scope (
    tenant_id, org_id, project_id,
    name, status, authorized_by,
    valid_from, valid_until,
    created_by, updated_by
) VALUES (
    ?, ?, ?,
    ?, ?, ?,
    ?, ?,
    ?, ?
);

-- name: GetScopeByID :one
SELECT * FROM scope
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListScopesByProject :many
SELECT * FROM scope
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: UpdateScope :exec
UPDATE scope
SET name = ?,
    status = ?,
    authorized_by = ?,
    valid_from = ?,
    valid_until = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: UpdateScopeStatus :exec
UPDATE scope
SET status = ?,
    updated_by = ?,
    updated_at = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: InsertScopeTarget :exec
INSERT INTO scope_target (
    tenant_id, org_id, project_id,
    scope_id, target_type, match_mode, target_value,
    created_by, updated_by
) VALUES (
    ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?
);

-- name: ListScopeTargetsByScope :many
SELECT * FROM scope_target
WHERE scope_id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: SoftDeleteScopeTargets :exec
UPDATE scope_target
SET deleted_at = ?,
    updated_by = ?
WHERE scope_id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';
