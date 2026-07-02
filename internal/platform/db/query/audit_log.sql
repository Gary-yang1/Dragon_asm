-- sqlc queries for the audit_log domain.
-- audit_log is append-only: INSERT only, no UPDATE, no DELETE.

-- name: InsertAuditLog :exec
INSERT INTO audit_log (
    tenant_id, org_id, project_id,
    actor_id, actor_type,
    action, resource_type, resource_id,
    result, ip, user_agent, request_id,
    before_json, after_json, metadata_json,
    error_code, error_message
) VALUES (
    ?, ?, ?,
    ?, ?,
    ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?,
    ?, ?
);
