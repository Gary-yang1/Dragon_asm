DROP TABLE risk_decision;

ALTER TABLE risk
    DROP FOREIGN KEY fk_risk_suppression_rule;

DROP TABLE suppression_rule;

ALTER TABLE risk
    DROP KEY idx_risk_suppressed,
    DROP COLUMN suppressed_until,
    DROP COLUMN suppression_rule_id,
    DROP COLUMN suppressed;
