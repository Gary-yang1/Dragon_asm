-- sqlc schema for notification rules and throttled delivery ledger.

CREATE TABLE notification_rule (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id       VARCHAR(64)   NOT NULL DEFAULT '',
    org_id          VARCHAR(64)   NOT NULL DEFAULT '',
    project_id      BIGINT UNSIGNED NOT NULL,
    name            VARCHAR(255)  NOT NULL DEFAULT '',
    trigger_name    VARCHAR(64)   NOT NULL,
    condition_json  JSON          NULL,
    channel         VARCHAR(32)   NOT NULL,
    recipients_json JSON          NULL,
    throttle_window INT UNSIGNED  NOT NULL DEFAULT 0,
    enabled         BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by      VARCHAR(64)   NOT NULL DEFAULT '',
    updated_by      VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at      DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    KEY idx_notification_rule_trigger (project_id, trigger_name, enabled),
    CONSTRAINT fk_notification_rule_project FOREIGN KEY (project_id) REFERENCES project (id) ON DELETE CASCADE,
    CONSTRAINT chk_notification_trigger CHECK (trigger_name IN ('new_critical_exposure', 'new_high_risk', 'sla_due_soon', 'cert_expiring')),
    CONSTRAINT chk_notification_channel CHECK (channel IN ('email', 'webhook'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE notification_delivery (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id      VARCHAR(64)   NOT NULL DEFAULT '',
    org_id         VARCHAR(64)   NOT NULL DEFAULT '',
    project_id     BIGINT UNSIGNED NOT NULL,
    rule_id        BIGINT UNSIGNED NOT NULL,
    trigger_name   VARCHAR(64)   NOT NULL,
    channel        VARCHAR(32)   NOT NULL,
    throttle_key   VARCHAR(255)  NOT NULL DEFAULT '',
    dedupe_key     VARCHAR(255)  NOT NULL DEFAULT '',
    status         VARCHAR(32)   NOT NULL DEFAULT 'sent',
    subject        VARCHAR(255)  NOT NULL DEFAULT '',
    payload_json   JSON          NULL,
    sent_at        DATETIME(3)   NOT NULL,
    created_at     DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_notification_throttle (project_id, rule_id, throttle_key),
    KEY idx_notification_delivery_project (project_id, trigger_name, sent_at),
    CONSTRAINT fk_notification_delivery_rule FOREIGN KEY (rule_id) REFERENCES notification_rule (id) ON DELETE CASCADE,
    CONSTRAINT chk_notification_delivery_status CHECK (status IN ('sent', 'throttled', 'failed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
