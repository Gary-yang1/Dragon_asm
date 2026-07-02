-- Rollback M0-5: drop audit_log (no FK dependencies, can be dropped in one step).

DROP TABLE IF EXISTS audit_log;
