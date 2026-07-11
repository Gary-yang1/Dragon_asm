-- Rollback M2-2: tenant-level global roles and auth profile extensions.
-- Operational prerequisite: rotate both JWT signing secrets before starting an
-- old binary, because the old binary does not understand auth_version.

-- Old binaries resolve global roles through project_member. Refuse to roll back
-- when a tenant-level role has no live project that can carry a compatibility
-- membership; silently dropping that role would lock the tenant out.
CREATE TEMPORARY TABLE tenant_role_rollback_guard (id INT PRIMARY KEY);
INSERT INTO tenant_role_rollback_guard (id) VALUES (1);
INSERT INTO tenant_role_rollback_guard (id)
SELECT 1
FROM tenant_user_role tur
WHERE tur.deleted_at = '1970-01-01 00:00:00.000'
  AND NOT EXISTS (
      SELECT 1
      FROM project p
      WHERE p.tenant_id = tur.tenant_id
        AND p.deleted_at = '1970-01-01 00:00:00.000'
  )
LIMIT 1;
DROP TEMPORARY TABLE tenant_role_rollback_guard;

ALTER TABLE project_member
    DROP CHECK chk_member_role,
    ADD CONSTRAINT chk_member_role CHECK (role IN ('system_admin', 'security_admin', 'project_owner', 'security_ops', 'developer', 'viewer'));

-- Restore one deterministic legacy membership per tenant role. The old model
-- cannot represent a tenant role independently from a project membership.
INSERT INTO project_member (
    project_id, user_id, role, created_by, updated_by
)
SELECT
    MIN(p.id),
    (CAST(tur.user_id AS CHAR) COLLATE utf8mb4_unicode_ci),
    tur.role,
    tur.created_by,
    tur.updated_by
FROM tenant_user_role tur
INNER JOIN project p
    ON p.tenant_id = tur.tenant_id
   AND p.deleted_at = '1970-01-01 00:00:00.000'
WHERE tur.deleted_at = '1970-01-01 00:00:00.000'
GROUP BY tur.tenant_id, tur.user_id, tur.role, tur.created_by, tur.updated_by
ON DUPLICATE KEY UPDATE
    role = VALUES(role),
    updated_by = VALUES(updated_by),
    updated_at = CURRENT_TIMESTAMP(3);

DROP TABLE IF EXISTS tenant_user_role;

ALTER TABLE app_user
    DROP COLUMN last_login_at,
    DROP COLUMN must_change_password,
    DROP COLUMN auth_version,
    DROP COLUMN email,
    DROP COLUMN phone,
    DROP COLUMN department;
