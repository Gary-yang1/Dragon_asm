-- M2-1: discovery scope base model and include/exclude target table.
-- Scope status defaults to inactive; callers must activate explicitly.

CREATE TABLE scope (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id     VARCHAR(64)   NOT NULL DEFAULT '',
    org_id        VARCHAR(64)   NOT NULL DEFAULT '',
    project_id    BIGINT UNSIGNED NOT NULL,
    name          VARCHAR(128)  NOT NULL DEFAULT '',
    status        VARCHAR(16)   NOT NULL DEFAULT 'inactive',
    authorized_by VARCHAR(64)   NOT NULL DEFAULT '',
    valid_from    DATETIME(3)   NOT NULL,
    valid_until   DATETIME(3)   NOT NULL,
    created_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by    VARCHAR(64)   NOT NULL DEFAULT '',
    updated_by    VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at    DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_scope_project_id (project_id, id),
    UNIQUE KEY uk_scope_project_name (project_id, name, deleted_at),
    KEY idx_scope_project (project_id, status),
    CONSTRAINT fk_scope_project FOREIGN KEY (project_id) REFERENCES project (id) ON DELETE CASCADE,
    CONSTRAINT chk_scope_status CHECK (status IN ('active', 'inactive')),
    CONSTRAINT chk_scope_valid_window CHECK (valid_until >= valid_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE scope_target (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id     VARCHAR(64)   NOT NULL DEFAULT '',
    org_id        VARCHAR(64)   NOT NULL DEFAULT '',
    project_id    BIGINT UNSIGNED NOT NULL,
    scope_id      BIGINT UNSIGNED NOT NULL,
    target_type   VARCHAR(16)   NOT NULL,
    match_mode    VARCHAR(16)   NOT NULL,
    target_value  VARCHAR(512)  NOT NULL DEFAULT '',
    created_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by    VARCHAR(64)   NOT NULL DEFAULT '',
    updated_by    VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at    DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_scope_target (scope_id, target_type, match_mode, target_value, deleted_at),
    KEY idx_scope_target_project (project_id, scope_id),
    CONSTRAINT fk_scope_target_scope_scope_project FOREIGN KEY (project_id, scope_id) REFERENCES scope (project_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_scope_target_type CHECK (target_type IN ('domain', 'ip', 'cidr', 'url')),
    CONSTRAINT chk_scope_target_match_mode CHECK (match_mode IN ('include', 'exclude')),
    CONSTRAINT chk_scope_target_value_len CHECK (CHAR_LENGTH(target_value) <= 512)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
