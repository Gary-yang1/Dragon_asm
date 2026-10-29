-- Mirrors migrations/000026_add_hot_path_indexes.up.sql so sqlc sees the same
-- schema the database has. Indexes do not affect generated code; this keeps the
-- two definitions from drifting.
ALTER TABLE change_event
    ADD KEY idx_change_event_detected (detected_at, id);

ALTER TABLE task_run
    ADD KEY idx_task_run_status_dispatched (status, dispatched_at, id);

ALTER TABLE report_export
    ADD KEY idx_report_export_status_id (status, deleted_at, id);

ALTER TABLE risk
    ADD KEY idx_risk_project_first_seen (project_id, first_seen),
    ADD KEY idx_risk_project_fixed_at (project_id, fixed_at);
