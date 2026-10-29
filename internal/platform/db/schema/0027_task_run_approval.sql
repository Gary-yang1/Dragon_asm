-- Mirrors migrations/000027_add_task_run_approval.up.sql so sqlc sees the same
-- schema the database has.
ALTER TABLE task_run
    ADD COLUMN approved_by     VARCHAR(64)   NOT NULL DEFAULT '',
    ADD COLUMN approval_reason VARCHAR(512)  NOT NULL DEFAULT '';
