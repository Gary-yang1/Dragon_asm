-- sqlc queries for the asset_relation domain.
-- Every read is scoped by project_id AND filters on the soft-delete sentinel, so
-- soft-deleted rows and cross-project rows are excluded by default.

-- name: UpsertRelation :execresult
-- Idempotent relation upsert: a new (project_id, from, to, type) edge inserts; a
-- repeat refreshes only the discovery-updatable fields (last_seen, source,
-- confidence, updated_by). first_seen and created_by are preserved so a re-import
-- never resets the edge's origin.
INSERT INTO asset_relation (
    tenant_id, org_id, project_id, from_asset_id, to_asset_id,
    relation_type, source, confidence, first_seen, last_seen, created_by, updated_by
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON DUPLICATE KEY UPDATE
    last_seen  = VALUES(last_seen),
    source     = VALUES(source),
    confidence = VALUES(confidence),
    updated_by = VALUES(updated_by);

-- name: ListRelationsByAsset :many
-- Both directions for one asset (out-edges where from_asset_id = ? and in-edges
-- where to_asset_id = ?), project-scoped and live. The service tags each row's
-- direction based on which endpoint equals the requested asset id.
SELECT * FROM asset_relation
WHERE project_id = ? AND (from_asset_id = ? OR to_asset_id = ?)
  AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id
LIMIT ? OFFSET ?;

-- name: CountRelationsByAsset :one
SELECT COUNT(*) FROM asset_relation
WHERE project_id = ? AND (from_asset_id = ? OR to_asset_id = ?)
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetRelationByEndpoints :one
-- Fetch the live edge for a (project, from, to, type) tuple. Used to return the
-- upserted row; excludes soft-deleted rows.
SELECT * FROM asset_relation
WHERE project_id = ? AND from_asset_id = ? AND to_asset_id = ? AND relation_type = ?
  AND deleted_at = '1970-01-01 00:00:00.000';