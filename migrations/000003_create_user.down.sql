-- Rollback M0-6: drop app_user (no FK dependencies, can be dropped in one step).

DROP TABLE IF EXISTS app_user;
