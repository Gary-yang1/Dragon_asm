-- Active scanning requires a second person to approve the run. Recording the
-- approver on the run itself (rather than only in the audit log) keeps the
-- authorisation attached to the thing it authorised, which is what an operator
-- or auditor asks for after the fact.
ALTER TABLE task_run
    ADD COLUMN approved_by     VARCHAR(64)   NOT NULL DEFAULT '',
    ADD COLUMN approval_reason VARCHAR(512)  NOT NULL DEFAULT '';
