-- sqlc queries for report dashboard statistics and asynchronous exports.

-- name: ReportRiskDashboard :one
SELECT
    COUNT(*) AS total_risks,
    SUM(CASE WHEN status NOT IN ('fixed','risk_accepted','false_positive') THEN 1 ELSE 0 END) AS open_risks,
    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_risks,
    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high_risks,
    SUM(CASE WHEN status NOT IN ('fixed','risk_accepted','false_positive') AND sla_due_at > '1970-01-01 00:00:00.000' AND sla_due_at < ? THEN 1 ELSE 0 END) AS overdue_risks,
    SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) AS fixed_risks
FROM risk
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ReportTicketDashboard :one
SELECT
    COUNT(*) AS total_tickets,
    SUM(CASE WHEN status NOT IN ('closed','cancelled','rejected') THEN 1 ELSE 0 END) AS open_tickets,
    SUM(CASE WHEN status NOT IN ('closed','cancelled','rejected') AND due_at > '1970-01-01 00:00:00.000' AND due_at < ? THEN 1 ELSE 0 END) AS overdue_tickets,
    SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) AS closed_tickets
FROM ticket
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ReportExposureDashboard :one
SELECT
    COUNT(*) AS total_exposures,
    SUM(CASE WHEN exposure_type = 'port' THEN 1 ELSE 0 END) AS port_exposures,
    SUM(CASE WHEN exposure_type = 'web' THEN 1 ELSE 0 END) AS web_exposures,
    SUM(CASE WHEN exposure_type = 'certificate' AND cert_not_after > '1970-01-01 00:00:00.000' AND cert_not_after <= ? THEN 1 ELSE 0 END) AS expiring_certs
FROM exposure
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ReportRiskTrend :many
SELECT DATE(first_seen) AS day, COUNT(*) AS new_risks
FROM risk
WHERE project_id = ?
  AND deleted_at = '1970-01-01 00:00:00.000'
  AND first_seen >= ?
  AND first_seen < ?
GROUP BY DATE(first_seen)
ORDER BY day;

-- name: ReportFixedRiskTrend :many
SELECT DATE(fixed_at) AS day, COUNT(*) AS fixed_risks
FROM risk
WHERE project_id = ?
  AND deleted_at = '1970-01-01 00:00:00.000'
  AND fixed_at >= ?
  AND fixed_at < ?
GROUP BY DATE(fixed_at)
ORDER BY day;

-- name: ReportTopAssetsByRisk :many
SELECT asset_id, COUNT(*) AS risk_count, MAX(score) AS max_score
FROM risk
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
GROUP BY asset_id
ORDER BY risk_count DESC, max_score DESC, asset_id
LIMIT ?;

-- name: ReportTopBusinessUnitsByRisk :many
SELECT business_unit, COUNT(*) AS risk_count, MAX(score) AS max_score
FROM risk
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
GROUP BY business_unit
ORDER BY risk_count DESC, max_score DESC, business_unit
LIMIT ?;

-- name: ReportRemediationStats :one
SELECT
    COUNT(*) AS total_risks,
    SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) AS fixed_risks,
    SUM(CASE WHEN status = 'fixed' AND sla_due_at > '1970-01-01 00:00:00.000' AND fixed_at <= sla_due_at THEN 1 ELSE 0 END) AS sla_met_risks,
    COALESCE(AVG(CASE WHEN status = 'fixed' AND fixed_at > first_seen THEN TIMESTAMPDIFF(HOUR, first_seen, fixed_at) END), 0) AS mttr_hours,
    SUM(CASE WHEN status NOT IN ('fixed','risk_accepted','false_positive') AND TIMESTAMPDIFF(DAY, first_seen, ?) <= 7 THEN 1 ELSE 0 END) AS age_0_7,
    SUM(CASE WHEN status NOT IN ('fixed','risk_accepted','false_positive') AND TIMESTAMPDIFF(DAY, first_seen, ?) BETWEEN 8 AND 30 THEN 1 ELSE 0 END) AS age_8_30,
    SUM(CASE WHEN status NOT IN ('fixed','risk_accepted','false_positive') AND TIMESTAMPDIFF(DAY, first_seen, ?) > 30 THEN 1 ELSE 0 END) AS age_over_30,
    SUM(CASE WHEN status = 'reopened' THEN 1 ELSE 0 END) AS reopened_risks
FROM risk
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: CreateReportExport :execresult
INSERT INTO report_export (
    tenant_id, org_id, project_id, report_type, status, format,
    fields_json, filters_json, redacted, requested_by
) VALUES (
    ?, ?, ?, ?, 'pending', ?,
    ?, ?, ?, ?
);

-- name: GetReportExportByID :one
SELECT * FROM report_export
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListReportExports :many
SELECT * FROM report_export
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY created_at DESC, id DESC
LIMIT ? OFFSET ?;

-- name: CountReportExports :one
SELECT COUNT(*) FROM report_export
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ClaimPendingReportExport :one
SELECT * FROM report_export
WHERE status = 'pending' AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id
LIMIT 1
FOR UPDATE;

-- name: MarkReportExportRunning :execresult
UPDATE report_export
SET status = 'running', started_at = ?, updated_at = ?
WHERE id = ? AND project_id = ? AND status = 'pending' AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkReportExportSucceeded :execresult
UPDATE report_export
SET status = 'succeeded', row_count = ?, file_path = ?, finished_at = ?, updated_at = ?
WHERE id = ? AND project_id = ? AND status = 'running' AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkReportExportFailed :execresult
UPDATE report_export
SET status = 'failed', error_message = ?, finished_at = ?, updated_at = ?
WHERE id = ? AND project_id = ? AND status = 'running' AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListRiskExportRows :many
SELECT
    id, asset_id, exposure_id, risk_key, risk_type, title, severity, score,
    score_level, rule_id, source, evidence_summary, evidence_ref, status,
    owner, business_unit, sla_due_at, first_seen, last_seen, fixed_at
FROM risk
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id
LIMIT ? OFFSET ?;

-- name: ListTicketExportRows :many
SELECT
    id, title, assignee, business_unit, status, priority, due_at,
    resolution, retest_result, external_ticket_id, closed_at, created_at, updated_at
FROM ticket
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id
LIMIT ? OFFSET ?;

-- name: ListExposureExportRows :many
SELECT
    id, asset_id, exposure_type, exposure_key, name, value, protocol, port,
    service, version, cpe, url, fingerprint, cert_subject, cert_issuer,
    cert_serial, cert_not_after, source, confidence, first_seen, last_seen
FROM exposure
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id
LIMIT ? OFFSET ?;
