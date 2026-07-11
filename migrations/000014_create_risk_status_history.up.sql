-- M3-4: auditable risk status transitions.

CREATE TABLE risk_status_history (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id  VARCHAR(64)   NOT NULL DEFAULT '',
    org_id     VARCHAR(64)   NOT NULL DEFAULT '',
    project_id BIGINT UNSIGNED NOT NULL,
    risk_id    BIGINT UNSIGNED NOT NULL,
    action     VARCHAR(32)   NOT NULL,
    old_status VARCHAR(32)   NOT NULL,
    new_status VARCHAR(32)   NOT NULL,
    actor_id   VARCHAR(64)   NOT NULL DEFAULT '',
    reason     VARCHAR(1024) NOT NULL DEFAULT '',
    request_id VARCHAR(128)  NOT NULL DEFAULT '',
    created_at DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    KEY idx_risk_status_history_risk (project_id, risk_id, created_at),
    CONSTRAINT fk_risk_status_history_risk FOREIGN KEY (project_id, risk_id)
        REFERENCES risk (project_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_risk_status_history_action CHECK (action IN ('confirm', 'assign', 'start_fix', 'mark_fixed', 'reopen', 'accept', 'false_positive')),
    CONSTRAINT chk_risk_status_history_old CHECK (old_status IN ('new', 'confirmed', 'assigned', 'fixing', 'risk_accepted', 'false_positive', 'fixed', 'reopened')),
    CONSTRAINT chk_risk_status_history_new CHECK (new_status IN ('new', 'confirmed', 'assigned', 'fixing', 'risk_accepted', 'false_positive', 'fixed', 'reopened'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
