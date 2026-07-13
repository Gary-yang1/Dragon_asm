-- sqlc queries for the discovery scope domain.
-- All reads are scoped by project_id and soft-delete sentinel so cross-project
-- reads/writes cannot leak through missing repository checks.

-- name: CreateScope :execresult
INSERT INTO scope (
    tenant_id, org_id, project_id,
    name, status, authorized_by,
    valid_from, valid_until,
    created_by, updated_by
) VALUES (
    ?, ?, ?,
    ?, ?, ?,
    ?, ?,
    ?, ?
);

-- name: GetScopeByID :one
SELECT * FROM scope
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListScopesByProject :many
SELECT * FROM scope
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: UpdateScope :exec
UPDATE scope
SET name = ?,
    status = ?,
    authorized_by = ?,
    valid_from = ?,
    valid_until = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: UpdateScopeStatus :exec
UPDATE scope
SET status = ?,
    updated_by = ?,
    updated_at = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: InsertScopeTarget :exec
INSERT INTO scope_target (
    tenant_id, org_id, project_id,
    scope_id, target_type, match_mode, target_value,
    created_by, updated_by
) VALUES (
    ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?
);

-- name: ListScopeTargetsByScope :many
SELECT * FROM scope_target
WHERE scope_id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: SoftDeleteScopeTargets :exec
UPDATE scope_target
SET deleted_at = ?,
    updated_by = ?
WHERE scope_id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- Task template queries.
-- name: CreateTaskTemplate :execresult
INSERT INTO task_template (
    tenant_id, org_id, project_id,
    scope_id, name, task_type,
    config, schedule, enabled,
    timeout_seconds, rate_limit, concurrency, retry_limit,
    created_by, updated_by
) VALUES (
    ?, ?, ?,
    ?, ?, ?,
    ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?
);

-- name: GetTaskTemplateByID :one
SELECT * FROM task_template
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListTaskTemplatesByProject :many
SELECT * FROM task_template
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: UpdateTaskTemplate :exec
UPDATE task_template
SET name = ?,
    task_type = ?,
    config = ?,
    schedule = ?,
    timeout_seconds = ?,
    rate_limit = ?,
    concurrency = ?,
    retry_limit = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: SetTaskTemplateEnabled :exec
UPDATE task_template
SET enabled = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: SoftDeleteTaskTemplate :exec
UPDATE task_template
SET deleted_at = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- Task run queries.
-- name: CreateTaskRun :execresult
INSERT INTO task_run (
    tenant_id, org_id, project_id, template_id, scope_id, task_type,
    status, progress, timeout_seconds, rate_limit, concurrency, retry_limit,
    attempt, engine_job_id, dispatched_at, last_callback_at, result_count,
    callback_secret_ref, started_at, finished_at, error_summary, created_by, updated_by
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?
);

-- name: GetTaskRunByID :one
SELECT * FROM task_run
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListTaskRunsByProject :many
SELECT * FROM task_run
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: ListRunningTaskRunsForReconcile :many
SELECT * FROM task_run
WHERE status = 'running'
  AND engine_job_id <> ''
  AND dispatched_at <> '1970-01-01 00:00:00.000'
  AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY dispatched_at, id
LIMIT ?;

-- name: MarkTaskRunRunning :execresult
UPDATE task_run
SET status = ?,
    progress = 0,
    started_at = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND status = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkTaskRunDispatched :execresult
UPDATE task_run
SET status = ?,
    progress = 0,
    engine_job_id = ?,
    dispatched_at = ?,
    started_at = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND status = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkTaskRunDispatchFailed :execresult
UPDATE task_run
SET status = ?,
    progress = 0,
    error_summary = ?,
    finished_at = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND status = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkTaskRunSucceeded :execresult
UPDATE task_run
SET status = ?,
    progress = ?,
    result_count = ?,
    error_summary = ?,
    finished_at = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND status = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkTaskRunPartialSuccess :execresult
UPDATE task_run
SET status = ?,
    progress = ?,
    result_count = ?,
    error_summary = ?,
    finished_at = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND status = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkTaskRunFailed :execresult
UPDATE task_run
SET status = ?,
    progress = ?,
    result_count = ?,
    error_summary = ?,
    finished_at = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND status = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkTaskRunCancelled :execresult
UPDATE task_run
SET status = ?,
    progress = ?,
    error_summary = ?,
    finished_at = ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND status = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: IncrementTaskRunAttempt :exec
UPDATE task_run
SET attempt = attempt + ?,
    updated_by = ?,
    updated_at = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkTaskRunCallbackReceived :execresult
UPDATE task_run
SET last_callback_at = ?,
    result_count = result_count + ?,
    updated_by = ?
WHERE id = ? AND project_id = ? AND status = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- Discovery callback queries.
-- name: InsertDiscoveryCallback :execresult
INSERT IGNORE INTO discovery_callback (
    tenant_id, org_id, project_id, run_id, seq, schema_version,
    phase, status, observed_at, payload_hash, payload_json, payload_size,
    result_count, error_summary, received_at, ingest_status
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?
);

-- name: GetDiscoveryCallback :one
SELECT id, tenant_id, org_id, project_id, run_id, seq, schema_version,
       phase, status, observed_at, payload_hash, payload_json, payload_size,
       result_count, error_summary, received_at, enqueued_at, ingest_status,
       ingest_attempt, ingest_error, processed_at, created_at, updated_at, deleted_at
FROM discovery_callback
WHERE project_id = ? AND run_id = ? AND seq = ?
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListPendingDiscoveryCallbacks :many
SELECT id, tenant_id, org_id, project_id, run_id, seq, schema_version,
       phase, status, observed_at, payload_hash, payload_json, payload_size,
       result_count, error_summary, received_at, enqueued_at, ingest_status,
       ingest_attempt, ingest_error, processed_at, created_at, updated_at, deleted_at
FROM discovery_callback
WHERE (
      ingest_status = 'pending'
      OR (ingest_status = 'failed' AND ingest_attempt < 10)
      OR (ingest_status = 'processing' AND ingest_attempt < 10 AND updated_at < DATE_SUB(CURRENT_TIMESTAMP(3), INTERVAL 5 MINUTE))
  )
  AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY received_at ASC, id ASC
LIMIT ?;

-- name: MarkDiscoveryCallbackEnqueued :exec
UPDATE discovery_callback
SET enqueued_at = ?
WHERE project_id = ? AND run_id = ? AND seq = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkDiscoveryCallbackProcessing :execresult
UPDATE discovery_callback
SET ingest_status = 'processing',
    ingest_attempt = ingest_attempt + 1,
    ingest_error = ''
WHERE project_id = ? AND run_id = ? AND seq = ?
  AND (
      ingest_status IN ('pending', 'failed')
      OR (ingest_status = 'processing' AND updated_at < DATE_SUB(CURRENT_TIMESTAMP(3), INTERVAL 5 MINUTE))
  )
  AND ingest_attempt < 10
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkDiscoveryCallbackProcessed :execresult
UPDATE discovery_callback
SET ingest_status = 'processed',
    ingest_error = '',
    processed_at = ?
WHERE project_id = ? AND run_id = ? AND seq = ?
  AND ingest_status = 'processing'
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: MarkDiscoveryCallbackFailed :exec
UPDATE discovery_callback
SET ingest_status = 'failed',
    ingest_error = ?
WHERE project_id = ? AND run_id = ? AND seq = ?
  AND ingest_status = 'processing'
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListDiscoveryCallbacksForRunForUpdate :many
SELECT id, tenant_id, org_id, project_id, run_id, seq, schema_version,
       phase, status, observed_at, payload_hash, payload_json, payload_size,
       result_count, error_summary, received_at, enqueued_at, ingest_status,
       ingest_attempt, ingest_error, processed_at, created_at, updated_at, deleted_at
FROM discovery_callback
WHERE project_id = ? AND run_id = ?
  AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY seq
FOR UPDATE;

-- Discovery observation queries.
-- name: UpsertDiscoveryObservation :execresult
INSERT INTO discovery_observation (
    tenant_id, org_id, project_id, run_id, seq, kind, natural_key, client_ref,
    provider, capability, observed_at, confidence, active_probe, evidence_hash,
    evidence_ref, normalized_json, normalized_size, ingest_status, ingest_error
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?
)
ON DUPLICATE KEY UPDATE
    id = LAST_INSERT_ID(id),
    seq = VALUES(seq),
    client_ref = VALUES(client_ref),
    capability = VALUES(capability),
    observed_at = GREATEST(observed_at, VALUES(observed_at)),
    confidence = VALUES(confidence),
    active_probe = VALUES(active_probe),
    evidence_hash = VALUES(evidence_hash),
    evidence_ref = VALUES(evidence_ref),
    normalized_json = VALUES(normalized_json),
    normalized_size = VALUES(normalized_size),
    ingest_status = VALUES(ingest_status),
    ingest_error = VALUES(ingest_error);

-- name: GetDiscoveryObservation :one
SELECT * FROM discovery_observation
WHERE id = ? AND project_id = ?
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListDiscoveryObservationsByRun :many
SELECT * FROM discovery_observation
WHERE project_id = ? AND run_id = ?
  AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY seq, id;

-- name: ListDiscoveryObservationsByRunSeq :many
SELECT * FROM discovery_observation
WHERE project_id = ? AND run_id = ? AND seq = ?
  AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: ListDiscoveryObservationsByNaturalKey :many
SELECT * FROM discovery_observation
WHERE project_id = ? AND kind = ? AND natural_key = ?
  AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY observed_at DESC, id DESC;

-- name: MarkDiscoveryObservationMaterialized :exec
UPDATE discovery_observation
SET ingest_status = 'materialized', ingest_error = ''
WHERE id = ? AND project_id = ?
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListCurrentDiscoveryAssetObservationKeys :many
SELECT DISTINCT natural_key
FROM discovery_observation
WHERE project_id = ? AND run_id = ? AND capability = ?
  AND kind = 'asset' AND ingest_status = 'materialized'
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListDiscoveryLifecycleAssets :many
SELECT DISTINCT a.*
FROM asset a
JOIN discovery_observation o
  ON o.project_id = a.project_id AND o.natural_key = a.asset_key
WHERE a.project_id = ? AND o.capability = ? AND o.kind = 'asset'
  AND o.ingest_status = 'materialized'
  AND a.source = 'discovery'
  AND a.deleted_at = '1970-01-01 00:00:00.000'
  AND o.deleted_at = '1970-01-01 00:00:00.000'
ORDER BY a.id;
