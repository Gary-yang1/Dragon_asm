-- Rollback M0-4: drop project_member first (FK references project), then project.
-- IF EXISTS so the down migration is idempotent against a partial state.

DROP TABLE IF EXISTS project_member;
DROP TABLE IF EXISTS project;
