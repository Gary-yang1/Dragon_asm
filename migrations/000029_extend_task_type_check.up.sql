-- The task type CHECK constraint predates dirscan and org_intel. Without this,
-- a template for either passes Go validation and then fails on insert, which
-- surfaces as a 500 rather than a clear rejection.
ALTER TABLE task_template
    DROP CHECK chk_task_template_type;
ALTER TABLE task_template
    ADD CONSTRAINT chk_task_template_type CHECK (task_type IN (
        'dns', 'ct_log', 'port_probe', 'web_probe', 'fingerprint',
        'cloud_sync', 'passive_intel', 'import', 'dirscan', 'org_intel'
    ));
