-- sqlc schema for remediation tickets and many-to-many risk links.

CREATE TABLE ticket (
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id          VARCHAR(64)   NOT NULL DEFAULT '',
    org_id             VARCHAR(64)   NOT NULL DEFAULT '',
    project_id         BIGINT UNSIGNED NOT NULL,
    title              VARCHAR(255)  NOT NULL DEFAULT '',
    description        VARCHAR(2048) NOT NULL DEFAULT '',
    assignee           VARCHAR(64)   NOT NULL DEFAULT '',
    business_unit      VARCHAR(128)  NOT NULL DEFAULT '',
    status             VARCHAR(32)   NOT NULL DEFAULT 'open',
    priority           VARCHAR(32)   NOT NULL DEFAULT 'medium',
    due_at             DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    resolution         VARCHAR(2048) NOT NULL DEFAULT '',
    retest_result      VARCHAR(2048) NOT NULL DEFAULT '',
    external_ticket_id VARCHAR(128)  NOT NULL DEFAULT '',
    closed_at          DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    created_at         DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at         DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by         VARCHAR(64)   NOT NULL DEFAULT '',
    updated_by         VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at         DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_ticket_project_id (project_id, id),
    KEY idx_ticket_project_status (project_id, status),
    KEY idx_ticket_project_assignee (project_id, assignee),
    CONSTRAINT fk_ticket_project FOREIGN KEY (project_id) REFERENCES project (id) ON DELETE CASCADE,
    CONSTRAINT chk_ticket_status CHECK (status IN ('open', 'assigned', 'in_progress', 'pending_retest', 'resolved', 'closed', 'rejected', 'extended', 'cancelled')),
    CONSTRAINT chk_ticket_priority CHECK (priority IN ('urgent', 'high', 'medium', 'low'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE ticket_risk (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id  VARCHAR(64)   NOT NULL DEFAULT '',
    org_id     VARCHAR(64)   NOT NULL DEFAULT '',
    project_id BIGINT UNSIGNED NOT NULL,
    ticket_id  BIGINT UNSIGNED NOT NULL,
    risk_id    BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    created_by VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_ticket_risk (project_id, ticket_id, risk_id, deleted_at),
    KEY idx_ticket_risk_risk (project_id, risk_id),
    CONSTRAINT fk_ticket_risk_ticket FOREIGN KEY (project_id, ticket_id)
        REFERENCES ticket (project_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_ticket_risk_risk FOREIGN KEY (project_id, risk_id)
        REFERENCES risk (project_id, id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
