-- sqlc queries for notification rules and delivery ledger.

-- name: CreateNotificationRule :execresult
INSERT INTO notification_rule (
    tenant_id, org_id, project_id, name, trigger_name, condition_json,
    channel, recipients_json, throttle_window, enabled, created_by, updated_by
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?
);

-- name: GetNotificationRuleByID :one
SELECT * FROM notification_rule
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListNotificationRulesByProject :many
SELECT * FROM notification_rule
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: ListEnabledNotificationRulesByTrigger :many
SELECT * FROM notification_rule
WHERE project_id = ?
  AND trigger_name = ?
  AND enabled = TRUE
  AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: SetNotificationRuleEnabled :execresult
UPDATE notification_rule
SET enabled = ?, updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: InsertNotificationDelivery :execresult
INSERT INTO notification_delivery (
    tenant_id, org_id, project_id, rule_id, trigger_name, channel,
    throttle_key, dedupe_key, status, subject, payload_json, sent_at
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?
);
