DROP TABLE risk_rule;

ALTER TABLE risk
    DROP CHECK chk_risk_type;

ALTER TABLE risk
    ADD CONSTRAINT chk_risk_type CHECK (risk_type IN ('vulnerability', 'weak_config', 'sensitive_exposure', 'unknown_asset', 'expired_certificate', 'high_risk_port', 'shadow_it', 'vendor_exposure'));
