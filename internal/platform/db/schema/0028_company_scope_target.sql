-- Mirrors migrations/000028_allow_company_scope_target.up.sql so sqlc sees the
-- same schema the database has. CHECK constraints do not affect generated code.
ALTER TABLE scope_target
    DROP CHECK chk_scope_target_type;
ALTER TABLE scope_target
    ADD CONSTRAINT chk_scope_target_type CHECK (target_type IN ('domain', 'ip', 'cidr', 'url', 'company'));
