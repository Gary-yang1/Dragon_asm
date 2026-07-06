-- M0-6: app_user table (MySQL 8). Named app_user rather than `user` to avoid
-- the MySQL reserved word and the mysql.user system table.
--
-- Soft-delete convention matches project/000001: deleted_at is NOT NULL with a
-- sentinel default of '1970-01-01 00:00:00.000'; a row is "live" while deleted_at
-- equals that sentinel, and unique keys include deleted_at so a soft-deleted row
-- never blocks re-creating one with the same natural key.
--
-- username is UNIQUE across the platform (not per-tenant) so login-by-username is
-- unambiguous without a tenant selector. tenant_id / org_id still record the
-- user's tenancy. password_hash stores a bcrypt hash (60 bytes); the column is
-- sized to also fit argon2id encodings.

CREATE TABLE app_user (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id     VARCHAR(64)  NOT NULL,
    org_id        VARCHAR(64)  NOT NULL,
    username      VARCHAR(128) NOT NULL,
    display_name  VARCHAR(255) NOT NULL DEFAULT '',
    password_hash VARCHAR(255) NOT NULL,
    status        VARCHAR(32)  NOT NULL DEFAULT 'active',
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
