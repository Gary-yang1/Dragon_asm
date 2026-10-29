-- AO-1: make one project Scope discoverable as the preferred authorization
-- context and let domain authorization explicitly cover its subdomains.
--
-- Existing rows stay exact-match. Nothing in this migration broadens a
-- historical authorization decision.
ALTER TABLE scope
    ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT FALSE AFTER valid_until,
    ADD COLUMN default_marker TINYINT
        GENERATED ALWAYS AS (
            CASE
                WHEN is_default = TRUE
                    AND deleted_at = '1970-01-01 00:00:00.000'
                THEN 1
                ELSE NULL
            END
        ) STORED AFTER is_default,
    ADD UNIQUE KEY uk_scope_project_default (project_id, default_marker);

ALTER TABLE scope_target
    ADD COLUMN coverage_mode VARCHAR(16) NOT NULL DEFAULT 'exact' AFTER match_mode,
    ADD CONSTRAINT chk_scope_target_coverage CHECK (
        coverage_mode = 'exact'
        OR (target_type = 'domain' AND coverage_mode = 'subdomains')
    );
