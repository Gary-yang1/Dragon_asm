-- Mirrors migrations/000029_extend_task_type_check.up.sql so sqlc sees the same
-- schema the database has. CHECK constraints do not affect generated code.
ALTER TABLE task_template
    DROP CHECK chk_task_template_type;
ALTER TABLE task_template
    ADD CONSTRAINT chk_task_template_type CHECK (task_type IN (
        'dns', 'ct_log', 'port_probe', 'web_probe', 'fingerprint',
        'cloud_sync', 'passive_intel', 'import', 'dirscan', 'org_intel'
    ));
