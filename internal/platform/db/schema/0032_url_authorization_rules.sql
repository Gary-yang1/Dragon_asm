ALTER TABLE scope_target
    ADD COLUMN url_rule JSON NULL,
    ADD CONSTRAINT chk_scope_target_url_rule CHECK (url_rule IS NULL OR target_type = 'url');
