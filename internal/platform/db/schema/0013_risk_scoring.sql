-- sqlc schema for explainable risk scoring and score history.

ALTER TABLE risk
    ADD COLUMN score_level VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN score_model_version VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN score_factors_json JSON NULL,
    ADD COLUMN scored_at DATETIME(3) NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    ADD UNIQUE KEY uk_risk_project_id (project_id, id);

CREATE TABLE risk_score_history (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id           VARCHAR(64)   NOT NULL DEFAULT '',
    org_id              VARCHAR(64)   NOT NULL DEFAULT '',
    project_id          BIGINT UNSIGNED NOT NULL,
    risk_id             BIGINT UNSIGNED NOT NULL,
    score               TINYINT UNSIGNED NOT NULL DEFAULT 0,
    score_level         VARCHAR(32)   NOT NULL DEFAULT '',
    score_model_version VARCHAR(64)   NOT NULL DEFAULT '',
    score_factors_json  JSON          NULL,
    reason              VARCHAR(255)  NOT NULL DEFAULT '',
    scored_at           DATETIME(3)   NOT NULL,
    created_at          DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    created_by          VARCHAR(64)   NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    KEY idx_risk_score_history_risk (project_id, risk_id, scored_at),
    CONSTRAINT fk_risk_score_history_risk FOREIGN KEY (project_id, risk_id)
        REFERENCES risk (project_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_risk_score_history_score CHECK (score <= 100),
    CONSTRAINT chk_risk_score_history_level CHECK (score_level IN ('info', 'low', 'medium', 'high', 'critical'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
