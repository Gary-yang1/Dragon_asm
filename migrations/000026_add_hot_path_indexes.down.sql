-- Drops the hot-path indexes added by 000026. Reversing this loses only query
-- performance; no data is affected.
ALTER TABLE risk
    DROP KEY idx_risk_project_first_seen,
    DROP KEY idx_risk_project_fixed_at;

ALTER TABLE report_export
    DROP KEY idx_report_export_status_id;

ALTER TABLE task_run
    DROP KEY idx_task_run_status_dispatched;

ALTER TABLE change_event
    DROP KEY idx_change_event_detected;
