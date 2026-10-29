-- Mirrors migrations/000035_expand_audit_snapshots.up.sql. Config strings inside
-- serialized audit snapshots can exceed TEXT after JSON escaping.
ALTER TABLE audit_log
    MODIFY COLUMN before_json MEDIUMTEXT NULL,
    MODIFY COLUMN after_json MEDIUMTEXT NULL;

ALTER TABLE audit_log_archive
    MODIFY COLUMN before_json MEDIUMTEXT NULL,
    MODIFY COLUMN after_json MEDIUMTEXT NULL;
