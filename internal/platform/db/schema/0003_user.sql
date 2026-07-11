-- sqlc schema for the auth domain. Kept in sync with
-- migrations/000003_create_user.up.sql. sqlc reads this to generate types.

CREATE TABLE app_user (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id     VARCHAR(64)  NOT NULL,
    org_id        VARCHAR(64)  NOT NULL,
    username      VARCHAR(128) NOT NULL,
    display_name  VARCHAR(255) NOT NULL DEFAULT '',
    email         VARCHAR(255) NULL,
    phone         VARCHAR(32)  NULL,
    department    VARCHAR(128) NOT NULL DEFAULT '',
    password_hash VARCHAR(255) NOT NULL,
    status        VARCHAR(32)  NOT NULL DEFAULT 'active',
    last_login_at DATETIME(3)  NULL,
    must_change_password TINYINT(1) NOT NULL DEFAULT 0,
    auth_version  INT UNSIGNED NOT NULL DEFAULT 1,
    created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by    VARCHAR(64)  NOT NULL DEFAULT '',
    updated_by    VARCHAR(64)  NOT NULL DEFAULT '',
    deleted_at    DATETIME(3)  NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_user_username (username, deleted_at),
    KEY idx_user_status (status),
    KEY idx_user_tenant (tenant_id),
    CONSTRAINT chk_user_status CHECK (status IN ('active', 'disabled'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
