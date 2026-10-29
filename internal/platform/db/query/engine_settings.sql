-- name: GetEngineSettingsHead :one
SELECT version FROM engine_settings_head WHERE id = 1;

-- name: LockEngineSettingsHead :one
SELECT version FROM engine_settings_head WHERE id = 1 FOR UPDATE;

-- name: GetEngineSettingsVersion :one
SELECT version, encrypted_payload, created_by, created_at FROM engine_settings_version WHERE version = ?;

-- name: CreateEngineSettingsVersion :exec
INSERT INTO engine_settings_version (version, encrypted_payload, created_by) VALUES (?, ?, ?);

-- name: SetEngineSettingsHead :exec
UPDATE engine_settings_head SET version = ? WHERE id = 1;

-- name: BindEngineRunSettings :exec
INSERT INTO engine_run_settings (project_id, run_id, version) VALUES (?, ?, ?);

-- name: GetEngineRunSettings :one
SELECT version FROM engine_run_settings WHERE project_id = ? AND run_id = ?;
