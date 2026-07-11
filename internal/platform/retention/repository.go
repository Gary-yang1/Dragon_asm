package retention

import (
	"context"
	"database/sql"
	"time"
)

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// Repository archives and prunes hot retention-managed tables.
type Repository interface {
	ArchiveAuditLogs(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	DeleteArchivedAuditLogs(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	ArchiveChangeEvents(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	DeleteArchivedChangeEvents(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	ArchiveDiscoveryCallbacks(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	DeleteArchivedDiscoveryCallbacks(ctx context.Context, cutoff time.Time, limit int) (int64, error)
}

type sqlRepository struct {
	db execer
}

// NewRepository creates a SQL-backed retention repository.
func NewRepository(db execer) Repository {
	return &sqlRepository{db: db}
}

func (r *sqlRepository) ArchiveAuditLogs(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, archiveAuditLogsSQL, cutoff, limit)
	return rowsAffected(res, err)
}

func (r *sqlRepository) DeleteArchivedAuditLogs(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, deleteArchivedAuditLogsSQL, cutoff, limit)
	return rowsAffected(res, err)
}

func (r *sqlRepository) ArchiveChangeEvents(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, archiveChangeEventsSQL, cutoff, limit)
	return rowsAffected(res, err)
}

func (r *sqlRepository) DeleteArchivedChangeEvents(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, deleteArchivedChangeEventsSQL, cutoff, limit)
	return rowsAffected(res, err)
}

func (r *sqlRepository) ArchiveDiscoveryCallbacks(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, archiveDiscoveryCallbacksSQL, cutoff, limit)
	return rowsAffected(res, err)
}

func (r *sqlRepository) DeleteArchivedDiscoveryCallbacks(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, deleteArchivedDiscoveryCallbacksSQL, cutoff, limit)
	return rowsAffected(res, err)
}

func rowsAffected(res sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}

const archiveAuditLogsSQL = `
INSERT IGNORE INTO audit_log_archive (
    id, tenant_id, org_id, project_id, actor_id, actor_type, action,
    resource_type, resource_id, result, ip, user_agent, request_id,
    before_json, after_json, metadata_json, error_code, error_message, created_at
)
SELECT
    id, tenant_id, org_id, project_id, actor_id, actor_type, action,
    resource_type, resource_id, result, ip, user_agent, request_id,
    before_json, after_json, metadata_json, error_code, error_message, created_at
FROM audit_log
WHERE created_at < ?
ORDER BY created_at, id
LIMIT ?`

const deleteArchivedAuditLogsSQL = `
DELETE al FROM audit_log al
JOIN (
    SELECT al2.id
    FROM audit_log al2
    JOIN audit_log_archive ala ON ala.id = al2.id
    WHERE al2.created_at < ?
    ORDER BY al2.created_at, al2.id
    LIMIT ?
) archived ON archived.id = al.id`

const archiveChangeEventsSQL = `
INSERT IGNORE INTO change_event_archive (
    id, tenant_id, org_id, project_id, entity_type, entity_id, change_type,
    severity, title, summary, source, before_json, after_json, detected_at, created_at
)
SELECT
    id, tenant_id, org_id, project_id, entity_type, entity_id, change_type,
    severity, title, summary, source, before_json, after_json, detected_at, created_at
FROM change_event
WHERE detected_at < ?
ORDER BY detected_at, id
LIMIT ?`

const deleteArchivedChangeEventsSQL = `
DELETE ce FROM change_event ce
JOIN (
    SELECT ce2.id, ce2.detected_at
    FROM change_event ce2
    JOIN change_event_archive cea ON cea.id = ce2.id AND cea.detected_at = ce2.detected_at
    WHERE ce2.detected_at < ?
    ORDER BY ce2.detected_at, ce2.id
    LIMIT ?
) archived ON archived.id = ce.id AND archived.detected_at = ce.detected_at`

const archiveDiscoveryCallbacksSQL = `
INSERT IGNORE INTO discovery_callback_archive (
    id, tenant_id, org_id, project_id, run_id, seq, phase, status,
    payload_hash, result_count, error_summary, received_at, enqueued_at,
    created_at, updated_at, deleted_at
)
SELECT
    id, tenant_id, org_id, project_id, run_id, seq, phase, status,
    payload_hash, result_count, error_summary, received_at, enqueued_at,
    created_at, updated_at, deleted_at
FROM discovery_callback
WHERE received_at < ?
ORDER BY received_at, id
LIMIT ?`

const deleteArchivedDiscoveryCallbacksSQL = `
DELETE dc FROM discovery_callback dc
JOIN (
    SELECT dc2.id
    FROM discovery_callback dc2
    JOIN discovery_callback_archive dca ON dca.id = dc2.id
    WHERE dc2.received_at < ?
    ORDER BY dc2.received_at, dc2.id
    LIMIT ?
) archived ON archived.id = dc.id`
