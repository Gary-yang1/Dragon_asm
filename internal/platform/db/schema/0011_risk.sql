-- sqlc schema for vulnerability definitions and risk instances.

ALTER TABLE exposure
    ADD UNIQUE KEY uk_exposure_project_id (project_id, id);

CREATE TABLE vulnerability_definition (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id       VARCHAR(64)   NOT NULL DEFAULT '',
    org_id          VARCHAR(64)   NOT NULL DEFAULT '',
    project_id      BIGINT UNSIGNED NOT NULL,
    rule_id         VARCHAR(128)  NOT NULL,
    cve_id          VARCHAR(32)   NOT NULL DEFAULT '',
    title           VARCHAR(255)  NOT NULL DEFAULT '',
    description     VARCHAR(2048) NOT NULL DEFAULT '',
    severity        VARCHAR(32)   NOT NULL DEFAULT 'medium',
    cpe_pattern     VARCHAR(255)  NOT NULL DEFAULT '',
    remediation     VARCHAR(2048) NOT NULL DEFAULT '',
    source          VARCHAR(64)   NOT NULL DEFAULT '',
    enabled         BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by      VARCHAR(64)   NOT NULL DEFAULT '',
    updated_by      VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at      DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_vuln_definition_rule (project_id, rule_id, deleted_at),
    KEY idx_vuln_definition_cpe (project_id, cpe_pattern),
    CONSTRAINT fk_vuln_definition_project FOREIGN KEY (project_id) REFERENCES project (id) ON DELETE CASCADE,
    CONSTRAINT chk_vuln_definition_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE risk (
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id          VARCHAR(64)   NOT NULL DEFAULT '',
    org_id             VARCHAR(64)   NOT NULL DEFAULT '',
    project_id         BIGINT UNSIGNED NOT NULL,
    asset_id           BIGINT UNSIGNED NOT NULL,
    exposure_id        BIGINT UNSIGNED NULL,
    vuln_definition_id BIGINT UNSIGNED NULL,
    risk_key           VARCHAR(512)  NOT NULL,
    risk_type          VARCHAR(64)   NOT NULL,
    title              VARCHAR(255)  NOT NULL DEFAULT '',
    severity           VARCHAR(32)   NOT NULL DEFAULT 'medium',
    score              TINYINT UNSIGNED NOT NULL DEFAULT 0,
    rule_id            VARCHAR(128)  NOT NULL DEFAULT '',
    source             VARCHAR(64)   NOT NULL DEFAULT '',
    evidence_summary   VARCHAR(2048) NOT NULL DEFAULT '',
    evidence_ref       VARCHAR(512)  NOT NULL DEFAULT '',
    status             VARCHAR(32)   NOT NULL DEFAULT 'new',
    owner              VARCHAR(64)   NOT NULL DEFAULT '',
    business_unit      VARCHAR(128)  NOT NULL DEFAULT '',
    sla_due_at         DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    first_seen         DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_seen          DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    confirmed_at       DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    fixed_at           DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    created_at         DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at         DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by         VARCHAR(64)   NOT NULL DEFAULT '',
    updated_by         VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at         DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_risk_key (project_id, risk_key, deleted_at),
    KEY idx_risk_project_status (project_id, status),
    KEY idx_risk_project_severity (project_id, severity),
    KEY idx_risk_asset (project_id, asset_id),
    KEY idx_risk_exposure (project_id, exposure_id),
    CONSTRAINT fk_risk_asset FOREIGN KEY (tenant_id, org_id, project_id, asset_id)
        REFERENCES asset (tenant_id, org_id, project_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_risk_exposure_project FOREIGN KEY (project_id, exposure_id)
        REFERENCES exposure (project_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_risk_vuln_definition FOREIGN KEY (vuln_definition_id)
        REFERENCES vulnerability_definition (id) ON DELETE SET NULL,
    CONSTRAINT chk_risk_type CHECK (risk_type IN ('vulnerability', 'weak_config', 'sensitive_exposure', 'unknown_asset', 'expired_certificate', 'high_risk_port', 'high_risk_exposure', 'shadow_it', 'vendor_exposure')),
    CONSTRAINT chk_risk_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT chk_risk_score CHECK (score <= 100),
    CONSTRAINT chk_risk_status CHECK (status IN ('new', 'confirmed', 'assigned', 'fixing', 'risk_accepted', 'false_positive', 'fixed', 'reopened'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
