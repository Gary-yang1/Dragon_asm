-- Rollback M1-1: drop asset (FK references project; dropped before any future
-- child tables that reference asset). IF EXISTS keeps the down migration
-- idempotent against a partial state.

DROP TABLE IF EXISTS asset;
