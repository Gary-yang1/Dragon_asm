-- sqlc queries for remediation tickets.

-- name: CreateTicket :execresult
INSERT INTO ticket (
    tenant_id, org_id, project_id, title, description, assignee,
    business_unit, status, priority, due_at, external_ticket_id,
    created_by, updated_by
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?
);

-- name: GetTicketByID :one
SELECT * FROM ticket
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListTicketsByProject :many
SELECT * FROM ticket
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id
LIMIT ? OFFSET ?;

-- name: CountTicketsByProject :one
SELECT COUNT(*) FROM ticket
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: LinkTicketRisk :execresult
INSERT INTO ticket_risk (
    tenant_id, org_id, project_id, ticket_id, risk_id, created_by
) VALUES (
    ?, ?, ?, ?, ?, ?
);

-- name: ListTicketRisks :many
SELECT * FROM ticket_risk
WHERE project_id = ? AND ticket_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: UpdateTicketStatus :execresult
UPDATE ticket
SET status = ?,
    assignee = ?,
    due_at = ?,
    resolution = ?,
    retest_result = ?,
    closed_at = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND status = ? AND deleted_at = '1970-01-01 00:00:00.000';
