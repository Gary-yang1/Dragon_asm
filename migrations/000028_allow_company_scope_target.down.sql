-- Rolling back drops company targets first; leaving them would violate the
-- narrower constraint and make the migration fail halfway.
DELETE FROM scope_target WHERE target_type = 'company';
ALTER TABLE scope_target
    DROP CHECK chk_scope_target_type;
ALTER TABLE scope_target
    ADD CONSTRAINT chk_scope_target_type CHECK (target_type IN ('domain', 'ip', 'cidr', 'url'));
