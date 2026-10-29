-- Stop API/Worker before rollback. Disable scopes with structured URL rules
-- so removing the rule cannot accidentally broaden authorization.
UPDATE scope SET status = 'inactive', is_default = FALSE
WHERE id IN (SELECT scope_id FROM scope_target WHERE url_rule IS NOT NULL AND deleted_at = '1970-01-01 00:00:00.000');
ALTER TABLE scope_target DROP CHECK chk_scope_target_url_rule, DROP COLUMN url_rule;
