-- M0-4: project + project_member tables (MySQL 8).
--
-- Soft-delete convention: deleted_at is NOT NULL with a sentinel default of
-- '1970-01-01 00:00:00.000'. A row is "live" while deleted_at equals that
-- sentinel. Unique keys include deleted_at so that a soft-deleted row never
-- blocks re-creating a row with the same natural key.

CREATE TABLE project (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id     VARCHAR(64)  NOT NULL,
    org_id        VARCHAR(64)  NOT NULL,
    project_code  VARCHAR(64)  NOT NULL,
    name          VARCHAR(255) NOT NULL,
    owner         VARCHAR(64)  NOT NULL,
    business_unit VARCHAR(128) NOT NULL DEFAULT '',
    criticality   VARCHAR(32)  NOT NULL DEFAULT 'medium',
    status        VARCHAR(32)  NOT NULL DEFAULT 'active',
    description   TEXT         NULL,
    created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by    VARCHAR(64)  NOT NULL DEFAULT '',
    updated_by    VARCHAR(64)  NOT NULL DEFAULT '',
    deleted_at    DATETIME(3)  NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_project_code (tenant_id, project_code, deleted_at),
    KEY idx_project_status (status),
    KEY idx_project_tenant (tenant_id),
    CONSTRAINT chk_project_status CHECK (status IN ('active', 'suspended', 'archived'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE project_member (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    user_id    VARCHAR(64) NOT NULL,
    role       VARCHAR(64) NOT NULL DEFAULT 'viewer',
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by VARCHAR(64) NOT NULL DEFAULT '',
    updated_by VARCHAR(64) NOT NULL DEFAULT '',
    deleted_at DATETIME(3) NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_project_member (project_id, user_id, deleted_at),
    KEY idx_member_user (user_id),
    CONSTRAINT fk_member_project FOREIGN KEY (project_id) REFERENCES project (id) ON DELETE CASCADE,
    CONSTRAINT chk_member_role CHECK (role IN ('system_admin', 'security_admin', 'project_owner', 'security_ops', 'developer', 'viewer'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
