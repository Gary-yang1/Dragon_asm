DROP TABLE IF EXISTS icp_filing_domain;
DROP TABLE IF EXISTS icp_filing;
DROP TABLE IF EXISTS project_domain_profile;
DROP TABLE IF EXISTS project_subject;

UPDATE project SET status = 'suspended' WHERE status = 'draft';
ALTER TABLE project
    DROP KEY uk_project_scope_id,
    DROP CHECK chk_project_status,
    ADD CONSTRAINT chk_project_status CHECK (status IN ('active', 'suspended', 'archived'));
