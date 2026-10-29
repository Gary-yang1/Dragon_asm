-- Remove rows using the newer types first: leaving them would violate the
-- narrower constraint and fail the rollback halfway.
DELETE FROM task_template WHERE task_type IN ('dirscan', 'org_intel');
ALTER TABLE task_template
    DROP CHECK chk_task_template_type;
ALTER TABLE task_template
    ADD CONSTRAINT chk_task_template_type CHECK (task_type IN (
        'dns', 'ct_log', 'port_probe', 'web_probe', 'fingerprint',
        'cloud_sync', 'passive_intel', 'import'
    ));
