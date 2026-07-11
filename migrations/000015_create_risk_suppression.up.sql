-- M3-5: risk suppression rules and acceptance / false-positive decisions.

ALTER TABLE risk
    ADD COLUMN suppressed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN suppression_rule_id BIGINT UNSIGNED NULL,
    ADD COLUMN suppressed_until DATETIME(3) NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    ADD KEY idx_risk_suppressed (project_id, suppressed, suppressed_until);

CREATE TABLE suppression_rule (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id   VARCHAR(64)   NOT NULL DEFAULT '',
    org_id      VARCHAR(64)   NOT NULL DEFAULT '',
    project_id  BIGINT UNSIGNED NOT NULL,
    name        VARCHAR(255)  NOT NULL DEFAULT '',
    risk_type   VARCHAR(64)   NOT NULL DEFAULT '',
    rule_id     VARCHAR(128)  NOT NULL DEFAULT '',
    asset_id    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    reason      VARCHAR(1024) NOT NULL DEFAULT '',
    expires_at  DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    enabled     BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at  DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at  DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by  VARCHAR(64)   NOT NULL DEFAULT '',
    updated_by  VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at  DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    KEY idx_suppression_rule_match (project_id, enabled, risk_type, rule_id, asset_id, expires_at),
    CONSTRAINT fk_suppression_rule_project FOREIGN KEY (project_id) REFERENCES project (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE risk
    ADD CONSTRAINT fk_risk_suppression_rule FOREIGN KEY (suppression_rule_id)
        REFERENCES suppression_rule (id) ON DELETE SET NULL;

CREATE TABLE risk_decision (
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id          VARCHAR(64)   NOT NULL DEFAULT '',
    org_id             VARCHAR(64)   NOT NULL DEFAULT '',
    project_id         BIGINT UNSIGNED NOT NULL,
    risk_id            BIGINT UNSIGNED NOT NULL,
    decision           VARCHAR(32)   NOT NULL,
    reason             VARCHAR(1024) NOT NULL DEFAULT '',
    approved_by        VARCHAR(64)   NOT NULL DEFAULT '',
    expires_at         DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    review_required_at DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    created_at         DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    created_by         VARCHAR(64)   NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    KEY idx_risk_decision_risk (project_id, risk_id, created_at),
    KEY idx_risk_decision_review (project_id, decision, review_required_at, expires_at),
    CONSTRAINT fk_risk_decision_risk FOREIGN KEY (project_id, risk_id)
        REFERENCES risk (project_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_risk_decision_decision CHECK (decision IN ('risk_accepted', 'false_positive'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
