-- M0-5: audit_log table (append-only, no update, no soft-delete).
-- project_id = 0 denotes a platform-level event (login, system ops) with no project context.

CREATE TABLE audit_log (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id     VARCHAR(64)  NOT NULL DEFAULT '',
    org_id        VARCHAR(64)  NOT NULL DEFAULT '',
    project_id    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    actor_id      VARCHAR(64)  NOT NULL DEFAULT '',
    actor_type    VARCHAR(32)  NOT NULL DEFAULT 'user',
    action        VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64)  NOT NULL DEFAULT '',
    resource_id   VARCHAR(64)  NOT NULL DEFAULT '',
    result        VARCHAR(16)  NOT NULL DEFAULT 'success',
    ip            VARCHAR(64)  NOT NULL DEFAULT '',
    user_agent    VARCHAR(512) NOT NULL DEFAULT '',
    request_id    VARCHAR(64)  NOT NULL DEFAULT '',
    before_json   TEXT         NULL,
    after_json    TEXT         NULL,
    metadata_json TEXT         NULL,
    error_code    VARCHAR(64)  NOT NULL DEFAULT '',
    error_message VARCHAR(512) NOT NULL DEFAULT '',
    created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    KEY idx_audit_tenant  (tenant_id),
    KEY idx_audit_actor   (actor_id),
    KEY idx_audit_project (project_id),
    KEY idx_audit_action  (action),
    KEY idx_audit_created (created_at),
    CONSTRAINT chk_audit_result   CHECK (result    IN ('success', 'failure')),
    CONSTRAINT chk_audit_actor_tp CHECK (actor_type IN ('user', 'system', 'service'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
