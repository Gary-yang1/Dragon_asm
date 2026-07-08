-- sqlc queries for the asset domain.
-- Every read is scoped by project_id AND filters on the soft-delete sentinel, so
-- soft-deleted rows and cross-project rows are excluded by default; callers never
-- need to remember to add either filter.

-- name: GetAssetByID :one
SELECT * FROM asset
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetAssetByKey :one
SELECT * FROM asset
WHERE project_id = ? AND asset_key = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: CountAssetsByProject :one
SELECT COUNT(*) FROM asset
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListAssetsByProject :many
SELECT * FROM asset
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id
LIMIT ? OFFSET ?;

-- name: UpsertAsset :execresult
-- Idempotent import: a new normalized asset_key inserts; a repeat within the same
-- project updates only the discovery-refreshable fields (last_seen, source,
-- confidence, display_name, value, updated_by). first_seen, owner, business_unit
-- and status are preserved so a re-import never resets ownership or un-ignores an
-- asset an operator deliberately set to 'ignored'/'inactive'.
INSERT INTO asset (
    tenant_id, org_id, project_id, asset_type, asset_key,
    display_name, value, source, owner, business_unit,
    confidence, status, first_seen, last_seen, created_by, updated_by
) VALUES (
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?
)
ON DUPLICATE KEY UPDATE
    last_seen    = VALUES(last_seen),
    source       = VALUES(source),
    confidence   = VALUES(confidence),
    display_name = VALUES(display_name),
    value        = VALUES(value),
    updated_by   = VALUES(updated_by);

-- name: UpdateAssetFields :exec
-- Operator edit of the non-key metadata fields. asset_type/asset_key/value are
-- the normalized identity and are never touched here; status is restricted to
-- the live statuses (deleted is reserved for the soft-delete operation). The
-- WHERE clause carries both id and project_id so a cross-project update is
-- impossible at the DB layer, and the soft-delete filter prevents editing a
-- tombstoned row.
UPDATE asset
SET display_name  = ?,
    source        = ?,
    owner         = ?,
    business_unit = ?,
    status        = ?,
    updated_by    = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';
