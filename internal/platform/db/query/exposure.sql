-- sqlc queries for exposure snapshots and change_event writes.

-- name: GetExposureByKey :one
SELECT * FROM exposure
WHERE project_id = ? AND exposure_key = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetExposureByID :one
SELECT * FROM exposure
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListExposuresByProject :many
SELECT * FROM exposure
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id
LIMIT ? OFFSET ?;

-- name: CountExposuresByProject :one
SELECT COUNT(*) FROM exposure
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: UpsertExposure :execresult
INSERT INTO exposure (
    tenant_id, org_id, project_id, asset_id, exposure_type, exposure_key,
    name, value, protocol, port, service, version, cpe, url, fingerprint,
    cert_subject, cert_issuer, cert_serial, cert_not_before, cert_not_after, cert_san_json,
    evidence_hash, source, confidence, first_seen, last_seen, created_by, updated_by
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?
)
ON DUPLICATE KEY UPDATE
    asset_id       = VALUES(asset_id),
    name           = VALUES(name),
    value          = VALUES(value),
    protocol       = VALUES(protocol),
    port           = VALUES(port),
    service        = VALUES(service),
    version        = VALUES(version),
    cpe            = VALUES(cpe),
    url            = VALUES(url),
    fingerprint    = VALUES(fingerprint),
    cert_subject   = VALUES(cert_subject),
    cert_issuer    = VALUES(cert_issuer),
    cert_serial    = VALUES(cert_serial),
    cert_not_before = VALUES(cert_not_before),
    cert_not_after  = VALUES(cert_not_after),
    cert_san_json  = VALUES(cert_san_json),
    evidence_hash  = VALUES(evidence_hash),
    source         = CASE WHEN source IN ('', 'discovery') THEN VALUES(source) ELSE source END,
    confidence     = GREATEST(confidence, VALUES(confidence)),
    last_seen      = VALUES(last_seen),
    updated_by     = VALUES(updated_by);

-- name: InsertChangeEvent :execresult
INSERT INTO change_event (
    tenant_id, org_id, project_id, entity_type, entity_id, change_type,
    severity, title, summary, source, before_json, after_json, detected_at
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?
);
