ALTER TABLE scope_target
    DROP CHECK chk_scope_target_coverage,
    DROP COLUMN coverage_mode;

ALTER TABLE scope
    DROP INDEX uk_scope_project_default,
    DROP COLUMN default_marker,
    DROP COLUMN is_default;
