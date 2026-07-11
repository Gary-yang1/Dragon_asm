-- sqlc schema for tenant-level global roles (platform global roles).

CREATE TABLE tenant_user_role (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id     VARCHAR(64) NOT NULL,
    user_id       BIGINT UNSIGNED NOT NULL,
    role          VARCHAR(64) NOT NULL,
    created_at    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by    VARCHAR(64) NOT NULL DEFAULT '',
    updated_by    VARCHAR(64) NOT NULL DEFAULT '',
    deleted_at    DATETIME(3) NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_tenant_user_role (tenant_id, user_id, deleted_at),
    KEY idx_tenant_user_role_user (user_id),
    CONSTRAINT fk_tenant_user_role_user FOREIGN KEY (user_id) REFERENCES app_user (id) ON DELETE RESTRICT,
    CONSTRAINT chk_tenant_user_role_role CHECK (role IN ('system_admin', 'security_admin'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
