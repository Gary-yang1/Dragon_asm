-- Task-template config allows 64 KiB. Recording that JSON as a string inside
-- an audit snapshot adds escaping and surrounding fields, exceeding TEXT's
-- 65,535-byte limit. Keep the complete, redacted snapshot and widen its archive
-- destination as well so retention never reintroduces the same failure.
ALTER TABLE audit_log
    MODIFY COLUMN before_json MEDIUMTEXT NULL,
    MODIFY COLUMN after_json MEDIUMTEXT NULL;

ALTER TABLE audit_log_archive
    MODIFY COLUMN before_json MEDIUMTEXT NULL,
    MODIFY COLUMN after_json MEDIUMTEXT NULL;
