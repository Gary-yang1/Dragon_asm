-- Drain pending/running tasks, then stop API/Worker and restore matching environment settings before rollback.
-- Export encrypted history plus its key first; dropping it removes configuration history.
DROP TABLE IF EXISTS engine_run_settings;
DROP TABLE IF EXISTS engine_settings_head;
DROP TABLE IF EXISTS engine_settings_version;
