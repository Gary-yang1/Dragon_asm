-- org_intel scopes are authorised by company name, not by a network address, so
-- the scope target type has to admit one.
ALTER TABLE scope_target
    DROP CHECK chk_scope_target_type;
ALTER TABLE scope_target
    ADD CONSTRAINT chk_scope_target_type CHECK (target_type IN ('domain', 'ip', 'cidr', 'url', 'company'));
