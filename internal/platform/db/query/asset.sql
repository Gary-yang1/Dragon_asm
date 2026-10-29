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

-- name: ListAssetsByProjectIDs :many
SELECT * FROM asset
WHERE project_id = sqlc.arg(project_id)
  AND id IN (sqlc.slice('ids'))
  AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- Filtered variants. The API accepted asset_type/status/keyword and ignored them,
-- so the console could only narrow the rows already on screen. An empty argument
-- means "no filter" so one query serves every combination.
-- name: ListAssetsByProjectFiltered :many
SELECT * FROM asset
WHERE asset.project_id = sqlc.arg(project_id)
  AND asset.deleted_at = '1970-01-01 00:00:00.000'
  AND (sqlc.arg(asset_type) = '' OR asset.asset_type = sqlc.arg(asset_type))
  AND (
      sqlc.arg(category) = ''
      OR (sqlc.arg(category) = 'domains' AND asset.asset_type IN ('domain', 'subdomain'))
      OR (sqlc.arg(category) = 'ips' AND asset.asset_type = 'ip' AND NOT EXISTS (SELECT 1 FROM asset_network_attribution n WHERE n.project_id = asset.project_id AND n.asset_id = asset.id AND n.role = 'cdn_edge'))
      OR (sqlc.arg(category) = 'cdn_edges' AND asset.asset_type = 'ip' AND EXISTS (SELECT 1 FROM asset_network_attribution n WHERE n.project_id = asset.project_id AND n.asset_id = asset.id AND n.role = 'cdn_edge'))
      OR (sqlc.arg(category) = 'web' AND asset.asset_type = 'web')
      OR (sqlc.arg(category) = 'external' AND asset.asset_type IN ('cloud_resource', 'third_party'))
  )
  AND (sqlc.arg(status) = '' OR asset.status = sqlc.arg(status))
  AND (
      sqlc.arg(keyword) = ''
      OR asset.display_name LIKE CONCAT('%', sqlc.arg(keyword), '%')
      OR asset.value LIKE CONCAT('%', sqlc.arg(keyword), '%')
      OR asset.owner LIKE CONCAT('%', sqlc.arg(keyword), '%')
      OR asset.business_unit LIKE CONCAT('%', sqlc.arg(keyword), '%')
  )
ORDER BY id
LIMIT ? OFFSET ?;

-- name: CountAssetsByProjectFiltered :one
SELECT COUNT(*) FROM asset
WHERE asset.project_id = sqlc.arg(project_id)
  AND asset.deleted_at = '1970-01-01 00:00:00.000'
  AND (sqlc.arg(asset_type) = '' OR asset.asset_type = sqlc.arg(asset_type))
  AND (
      sqlc.arg(category) = ''
      OR (sqlc.arg(category) = 'domains' AND asset.asset_type IN ('domain', 'subdomain'))
      OR (sqlc.arg(category) = 'ips' AND asset.asset_type = 'ip' AND NOT EXISTS (SELECT 1 FROM asset_network_attribution n WHERE n.project_id = asset.project_id AND n.asset_id = asset.id AND n.role = 'cdn_edge'))
      OR (sqlc.arg(category) = 'cdn_edges' AND asset.asset_type = 'ip' AND EXISTS (SELECT 1 FROM asset_network_attribution n WHERE n.project_id = asset.project_id AND n.asset_id = asset.id AND n.role = 'cdn_edge'))
      OR (sqlc.arg(category) = 'web' AND asset.asset_type = 'web')
      OR (sqlc.arg(category) = 'external' AND asset.asset_type IN ('cloud_resource', 'third_party'))
  )
  AND (sqlc.arg(status) = '' OR asset.status = sqlc.arg(status))
  AND (
      sqlc.arg(keyword) = ''
      OR asset.display_name LIKE CONCAT('%', sqlc.arg(keyword), '%')
      OR asset.value LIKE CONCAT('%', sqlc.arg(keyword), '%')
      OR asset.owner LIKE CONCAT('%', sqlc.arg(keyword), '%')
      OR asset.business_unit LIKE CONCAT('%', sqlc.arg(keyword), '%')
  );

-- name: GetAssetSummary :one
-- CDN edge addresses (asset_network_attribution role cdn_edge) are DNS answers,
-- not assets the organisation runs: they are counted on their own and kept out
-- of every managed figure, where their churn and empty owners would distort it.
SELECT
    COUNT(*) AS total,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 THEN 1 END) AS managed_total,
    COUNT(CASE WHEN status = 'active' AND is_edge = 0 THEN 1 END) AS active,
    COUNT(CASE WHEN status = 'inactive' AND is_edge = 0 THEN 1 END) AS inactive,
    COUNT(CASE WHEN status = 'ignored' THEN 1 END) AS ignored,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND asset_type = 'domain' THEN 1 END) AS domain_count,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND asset_type = 'subdomain' THEN 1 END) AS subdomain_count,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND asset_type = 'ip' THEN 1 END) AS ip_count,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND asset_type = 'port' THEN 1 END) AS port_count,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND asset_type = 'service' THEN 1 END) AS service_count,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND asset_type = 'web' THEN 1 END) AS web_count,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND asset_type = 'certificate' THEN 1 END) AS certificate_count,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND asset_type = 'cloud_resource' THEN 1 END) AS cloud_resource_count,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND asset_type = 'third_party' THEN 1 END) AS third_party_count,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 1 THEN 1 END) AS cdn_edge_count,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND first_seen >= sqlc.arg(new_since) THEN 1 END) AS new_24h,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND last_seen >= sqlc.arg(observed_since) THEN 1 END) AS observed_24h,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND last_seen < sqlc.arg(stale_before) THEN 1 END) AS stale_30d,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND owner = '' THEN 1 END) AS unowned,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND business_unit = '' THEN 1 END) AS unassigned_business_unit,
    COUNT(CASE WHEN status <> 'ignored' AND is_edge = 0 AND confidence < sqlc.arg(low_confidence_below) THEN 1 END) AS low_confidence
FROM (
    SELECT a.status, a.asset_type, a.first_seen, a.last_seen, a.owner, a.business_unit, a.confidence,
           EXISTS (SELECT 1 FROM asset_network_attribution n
                   WHERE n.project_id = a.project_id AND n.asset_id = a.id AND n.role = 'cdn_edge') AS is_edge
    FROM asset a
    WHERE a.project_id = sqlc.arg(project_id)
      AND a.deleted_at = '1970-01-01 00:00:00.000'
) AS summarized;

-- name: CountSharedIPAssets :one
-- An address many live names resolve to is likely shared hosting or an edge the
-- rule set does not list. It is a hint, not a judgement: the address stays in
-- the inventory and is only labelled.
SELECT COUNT(*) FROM (
    SELECT t.id
    FROM asset t
    JOIN asset_relation r
      ON r.project_id = t.project_id AND r.to_asset_id = t.id
     AND r.relation_type = 'resolves_to' AND r.deleted_at = '1970-01-01 00:00:00.000'
    WHERE t.project_id = sqlc.arg(project_id)
      AND t.asset_type = 'ip'
      AND t.status <> 'ignored'
      AND t.deleted_at = '1970-01-01 00:00:00.000'
      AND NOT EXISTS (SELECT 1 FROM asset_network_attribution n
                      WHERE n.project_id = t.project_id AND n.asset_id = t.id AND n.role = 'cdn_edge')
    GROUP BY t.id
    HAVING COUNT(DISTINCT r.from_asset_id) >= sqlc.arg(min_names)
) AS shared;

-- name: FindProjectRootDomainAsset :one
SELECT a.id FROM project_domain_profile pdp
INNER JOIN asset a ON a.id = pdp.asset_id AND a.project_id = pdp.project_id
WHERE pdp.project_id = ?
  AND ? LIKE CONCAT('%.', a.value)
  AND pdp.deleted_at = '1970-01-01 00:00:00.000'
  AND a.deleted_at = '1970-01-01 00:00:00.000'
ORDER BY CHAR_LENGTH(a.value) DESC, a.id
LIMIT 1;

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
    source       = CASE WHEN source IN ('', 'discovery') THEN VALUES(source) ELSE source END,
    confidence   = GREATEST(confidence, VALUES(confidence)),
    display_name = CASE WHEN display_name = '' THEN VALUES(display_name) ELSE display_name END,
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

-- name: UpdateAssetLifecycle :exec
-- Lifecycle transition: set miss_count and status together for one project-scoped
-- live asset. The service decides the target (status, miss_count) after reading
-- the current row and the configurable threshold; this query applies it. The
-- WHERE clause carries project_id + the soft-delete filter so a cross-project or
-- tombstoned asset cannot be transitioned.
UPDATE asset
SET miss_count = ?,
    status     = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';
