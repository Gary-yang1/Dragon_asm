-- M3-2: configurable high-risk exposure rule dictionary.

ALTER TABLE risk
    DROP CHECK chk_risk_type;

ALTER TABLE risk
    ADD CONSTRAINT chk_risk_type CHECK (risk_type IN ('vulnerability', 'weak_config', 'sensitive_exposure', 'unknown_asset', 'expired_certificate', 'high_risk_port', 'high_risk_exposure', 'shadow_it', 'vendor_exposure'));

CREATE TABLE risk_rule (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id       VARCHAR(64)   NOT NULL DEFAULT '',
    org_id          VARCHAR(64)   NOT NULL DEFAULT '',
    project_id      BIGINT UNSIGNED NOT NULL,
    rule_id         VARCHAR(128)  NOT NULL,
    name            VARCHAR(255)  NOT NULL DEFAULT '',
    description     VARCHAR(2048) NOT NULL DEFAULT '',
    risk_type       VARCHAR(64)   NOT NULL DEFAULT 'high_risk_exposure',
    severity        VARCHAR(32)   NOT NULL DEFAULT 'high',
    match_type      VARCHAR(32)   NOT NULL,
    match_value     VARCHAR(255)  NOT NULL DEFAULT '',
    remediation     VARCHAR(2048) NOT NULL DEFAULT '',
    source          VARCHAR(64)   NOT NULL DEFAULT '',
    enabled         BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by      VARCHAR(64)   NOT NULL DEFAULT '',
    updated_by      VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at      DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_risk_rule_rule (project_id, rule_id, deleted_at),
    KEY idx_risk_rule_enabled (project_id, enabled),
    CONSTRAINT fk_risk_rule_project FOREIGN KEY (project_id) REFERENCES project (id) ON DELETE CASCADE,
    CONSTRAINT chk_risk_rule_type CHECK (risk_type IN ('weak_config', 'sensitive_exposure', 'unknown_asset', 'expired_certificate', 'high_risk_port', 'high_risk_exposure', 'shadow_it', 'vendor_exposure')),
    CONSTRAINT chk_risk_rule_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT chk_risk_rule_match_type CHECK (match_type IN ('port', 'service', 'web', 'fingerprint'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
