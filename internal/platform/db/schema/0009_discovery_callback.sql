-- sqlc schema for discovery engine callback idempotency ledger.

CREATE TABLE discovery_callback (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id      VARCHAR(64)   NOT NULL DEFAULT '',
    org_id         VARCHAR(64)   NOT NULL DEFAULT '',
    project_id     BIGINT UNSIGNED NOT NULL,
    run_id         BIGINT UNSIGNED NOT NULL,
    seq            BIGINT UNSIGNED NOT NULL,
    phase          VARCHAR(32)   NOT NULL DEFAULT '',
    status         VARCHAR(32)   NOT NULL DEFAULT '',
    payload_hash   CHAR(64)      NOT NULL DEFAULT '',
    result_count   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    error_summary  VARCHAR(1024) NOT NULL DEFAULT '',
    received_at    DATETIME(3)   NOT NULL,
    enqueued_at    DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    created_at     DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at     DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at     DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_discovery_callback_run_seq (project_id, run_id, seq, deleted_at),
    KEY idx_discovery_callback_run (project_id, run_id),
    CONSTRAINT fk_discovery_callback_run_project FOREIGN KEY (project_id, run_id) REFERENCES task_run (project_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_discovery_callback_phase CHECK (phase IN ('started', 'progress', 'completed', 'failed', '')),
    CONSTRAINT chk_discovery_callback_status CHECK (status IN ('running', 'success', 'partial_success', 'failed', 'cancelled', ''))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
