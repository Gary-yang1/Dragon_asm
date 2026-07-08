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

-- name: MarkTaskRunRunning :execresult
UPDATE task_run
SET status = ?,
    progress = 0,
    started_at = ?,
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
