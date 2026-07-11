-- Reverse M2-5 discovery callback idempotency ledger.
DROP TABLE IF EXISTS discovery_callback;
ALTER TABLE task_run DROP KEY uk_task_run_project_id;
