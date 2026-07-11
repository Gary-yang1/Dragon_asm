-- M2-2: tenant-level global roles and auth profile extensions.
-- This migration introduces platform-wide roles via tenant_user_role and adds
-- user profile fields needed by auth-session invalidation/audit logic.

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

ALTER TABLE app_user
    ADD COLUMN email VARCHAR(255) NULL,
    ADD COLUMN phone VARCHAR(32) NULL,
    ADD COLUMN department VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN last_login_at DATETIME(3) NULL,
    ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 0,
    ADD COLUMN auth_version INT UNSIGNED NOT NULL DEFAULT 1;

INSERT INTO tenant_user_role (
    tenant_id, user_id, role, created_by, updated_by
)
SELECT source.tenant_id, source.user_id, source.role, source.created_by, source.updated_by
FROM (
    SELECT
        p.tenant_id,
        CAST(pm.user_id AS UNSIGNED) AS user_id,
        pm.role,
        pm.created_by,
        pm.updated_by,
        ROW_NUMBER() OVER (
            PARTITION BY p.tenant_id, CAST(pm.user_id AS UNSIGNED)
            ORDER BY FIELD(pm.role, 'system_admin', 'security_admin')
        ) AS rn
    FROM project_member pm
    INNER JOIN project p
        ON p.id = pm.project_id
    INNER JOIN app_user u
        ON u.id = CAST(pm.user_id AS UNSIGNED)
       AND u.tenant_id = p.tenant_id
    WHERE pm.role IN ('system_admin', 'security_admin')
      AND pm.user_id REGEXP '^[1-9][0-9]*$'
      AND pm.deleted_at = '1970-01-01 00:00:00.000'
      AND p.deleted_at = '1970-01-01 00:00:00.000'
      AND u.deleted_at = '1970-01-01 00:00:00.000'
) AS source
WHERE source.rn = 1;

UPDATE project_member pm
SET pm.role = 'viewer'
WHERE pm.role IN ('system_admin', 'security_admin')
  AND pm.deleted_at = '1970-01-01 00:00:00.000';

ALTER TABLE project_member
    DROP CHECK chk_member_role,
    ADD CONSTRAINT chk_member_role CHECK (
        role IN ('project_owner', 'security_ops', 'developer', 'viewer')
        OR (
            role IN ('system_admin', 'security_admin')
            AND deleted_at <> '1970-01-01 00:00:00.000'
        )
    );
