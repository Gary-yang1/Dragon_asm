-- sqlc queries for vulnerability definitions and risk instances.

-- name: CreateVulnerabilityDefinition :execresult
INSERT INTO vulnerability_definition (
    tenant_id, org_id, project_id, rule_id, cve_id, title, description,
    severity, cpe_pattern, remediation, source, enabled, created_by, updated_by
) VALUES (
    ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?
);

-- name: GetVulnerabilityDefinitionByID :one
SELECT * FROM vulnerability_definition
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetVulnerabilityDefinitionByRuleID :one
SELECT * FROM vulnerability_definition
WHERE project_id = ? AND rule_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListVulnerabilityDefinitionsByProject :many
SELECT * FROM vulnerability_definition
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: CreateRiskRule :execresult
INSERT INTO risk_rule (
    tenant_id, org_id, project_id, rule_id, name, description,
    risk_type, severity, match_type, match_value, remediation, source,
    enabled, created_by, updated_by
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?
);

-- name: GetRiskRuleByID :one
SELECT * FROM risk_rule
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetRiskRuleByRuleID :one
SELECT * FROM risk_rule
WHERE project_id = ? AND rule_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListEnabledRiskRules :many
SELECT * FROM risk_rule
WHERE project_id = ? AND enabled = TRUE AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: SetRiskRuleEnabled :execresult
UPDATE risk_rule
SET enabled = ?, updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: CreateRisk :execresult
INSERT INTO risk (
    tenant_id, org_id, project_id, asset_id, exposure_id, vuln_definition_id,
    risk_key, risk_type, title, severity, score, rule_id, source,
    score_level, score_model_version, score_factors_json, scored_at,
    evidence_summary, evidence_ref, status, owner, business_unit,
    sla_due_at, suppressed, suppression_rule_id, suppressed_until,
    first_seen, last_seen, confirmed_at, fixed_at, created_by, updated_by
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?
);

-- name: GetRiskByID :one
SELECT * FROM risk
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetRiskByIDForUpdate :one
SELECT * FROM risk
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
FOR UPDATE;

-- name: GetRiskByKey :one
SELECT * FROM risk
WHERE project_id = ? AND risk_key = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListRisksByProject :many
SELECT * FROM risk
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id
LIMIT ? OFFSET ?;

-- name: CountRisksByProject :one
SELECT COUNT(*) FROM risk
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: RefreshRisk :execresult
UPDATE risk
SET title = ?,
    severity = ?,
    score = ?,
    score_level = ?,
    score_model_version = ?,
    score_factors_json = ?,
    scored_at = ?,
    source = ?,
    evidence_summary = ?,
    evidence_ref = ?,
    owner = ?,
    business_unit = ?,
    suppressed = ?,
    suppression_rule_id = ?,
    suppressed_until = ?,
    last_seen = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ReopenRisk :execresult
UPDATE risk
SET status = 'reopened',
    title = ?,
    severity = ?,
    score = ?,
    score_level = ?,
    score_model_version = ?,
    score_factors_json = ?,
    scored_at = ?,
    source = ?,
    evidence_summary = ?,
    evidence_ref = ?,
    owner = ?,
    business_unit = ?,
    suppressed = ?,
    suppression_rule_id = ?,
    suppressed_until = ?,
    last_seen = ?,
    fixed_at = '1970-01-01 00:00:00.000',
    updated_by = ?
WHERE id = ? AND project_id = ? AND status = 'fixed' AND deleted_at = '1970-01-01 00:00:00.000';

-- name: UpdateRiskStatus :execresult
UPDATE risk
SET status = ?,
    owner = ?,
    sla_due_at = ?,
    confirmed_at = ?,
    fixed_at = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND status = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: InsertRiskChangeEvent :execresult
INSERT INTO change_event (
    tenant_id, org_id, project_id, entity_type, entity_id, change_type,
    severity, title, summary, source, before_json, after_json, detected_at
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?
);

-- name: UpdateRiskScore :execresult
UPDATE risk
SET score = ?,
    score_level = ?,
    score_model_version = ?,
    score_factors_json = ?,
    scored_at = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: InsertRiskScoreHistory :execresult
INSERT INTO risk_score_history (
    tenant_id, org_id, project_id, risk_id, score, score_level,
    score_model_version, score_factors_json, reason, scored_at, created_by
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?
);

-- name: ListRiskScoreHistory :many
SELECT * FROM risk_score_history
WHERE project_id = ? AND risk_id = ?
ORDER BY scored_at, id;

-- name: InsertRiskStatusHistory :execresult
INSERT INTO risk_status_history (
    tenant_id, org_id, project_id, risk_id, action,
    old_status, new_status, actor_id, reason, request_id
) VALUES (
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?
);

-- name: ListRiskStatusHistory :many
SELECT * FROM risk_status_history
WHERE project_id = ? AND risk_id = ?
ORDER BY created_at, id;

-- name: CreateSuppressionRule :execresult
INSERT INTO suppression_rule (
    tenant_id, org_id, project_id, name, risk_type, rule_id, asset_id,
    reason, expires_at, enabled, created_by, updated_by
) VALUES (
    ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?
);

-- name: GetSuppressionRuleByID :one
SELECT * FROM suppression_rule
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListActiveSuppressionRules :many
SELECT * FROM suppression_rule
WHERE project_id = ?
  AND enabled = TRUE
  AND deleted_at = '1970-01-01 00:00:00.000'
  AND (expires_at = '1970-01-01 00:00:00.000' OR expires_at > ?)
ORDER BY id;

-- name: SetSuppressionRuleEnabled :execresult
UPDATE suppression_rule
SET enabled = ?, updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: InsertRiskDecision :execresult
INSERT INTO risk_decision (
    tenant_id, org_id, project_id, risk_id, decision, reason,
    approved_by, expires_at, review_required_at, created_by
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?
);

-- name: ListRiskDecisions :many
SELECT * FROM risk_decision
WHERE project_id = ? AND risk_id = ?
ORDER BY created_at, id;

-- name: ListExpiredRiskDecisions :many
SELECT * FROM risk_decision
WHERE project_id = ?
  AND decision IN ('risk_accepted', 'false_positive')
  AND (
    (expires_at > '1970-01-01 00:00:00.000' AND expires_at <= ?)
    OR (review_required_at > '1970-01-01 00:00:00.000' AND review_required_at <= ?)
  )
ORDER BY expires_at, review_required_at, id
LIMIT ?;

-- name: UpsertSLAPolicy :execresult
INSERT INTO sla_policy (
    tenant_id, org_id, project_id, severity, business_unit,
    response_hours, resolution_hours, enabled, created_by, updated_by
) VALUES (
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?
)
ON DUPLICATE KEY UPDATE
    response_hours = VALUES(response_hours),
    resolution_hours = VALUES(resolution_hours),
    enabled = VALUES(enabled),
    updated_by = VALUES(updated_by);

-- name: GetSLAPolicy :one
SELECT * FROM sla_policy
WHERE project_id = ?
  AND severity = ?
  AND business_unit = ?
  AND enabled = TRUE
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListSLAPoliciesByProject :many
SELECT * FROM sla_policy
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY severity, business_unit;

-- name: ListOpenRisksForSLARecalc :many
SELECT * FROM risk
WHERE project_id = ?
  AND status NOT IN ('fixed', 'risk_accepted', 'false_positive')
  AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id
LIMIT ?;

-- name: CountOverdueRisks :one
SELECT COUNT(*) FROM risk
WHERE project_id = ?
  AND status NOT IN ('fixed', 'risk_accepted', 'false_positive')
  AND sla_due_at > '1970-01-01 00:00:00.000'
  AND sla_due_at < ?
  AND deleted_at = '1970-01-01 00:00:00.000';
