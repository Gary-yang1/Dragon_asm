-- sqlc schema for configurable SLA policies.

CREATE TABLE sla_policy (
    id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id        VARCHAR(64)   NOT NULL DEFAULT '',
    org_id           VARCHAR(64)   NOT NULL DEFAULT '',
    project_id       BIGINT UNSIGNED NOT NULL,
    severity         VARCHAR(32)   NOT NULL,
    business_unit    VARCHAR(128)  NOT NULL DEFAULT '',
    response_hours   INT UNSIGNED  NOT NULL DEFAULT 0,
    resolution_hours INT UNSIGNED  NOT NULL DEFAULT 0,
    enabled          BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by       VARCHAR(64)   NOT NULL DEFAULT '',
    updated_by       VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at       DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_sla_policy (project_id, severity, business_unit, deleted_at),
    KEY idx_sla_policy_enabled (project_id, enabled),
    CONSTRAINT fk_sla_policy_project FOREIGN KEY (project_id) REFERENCES project (id) ON DELETE CASCADE,
    CONSTRAINT chk_sla_policy_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT chk_sla_policy_resolution CHECK (resolution_hours > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
