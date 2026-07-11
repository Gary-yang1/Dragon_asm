-- sqlc queries for the auth (app_user) domain.
-- Every read filters on the soft-delete sentinel so soft-deleted rows are
-- excluded by default; callers never need to remember to add the filter.

-- name: GetUserByUsername :one
-- Login lookup. username is globally unique, so this returns at most one live row.
SELECT * FROM app_user
WHERE username = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetUserByID :one
SELECT * FROM app_user
WHERE id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: UpdateUserLastLoginAt :exec
UPDATE app_user
SET last_login_at = CURRENT_TIMESTAMP(3), updated_at = updated_at
WHERE id = ?
  AND status = 'active'
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetDefaultProjectMembershipByUserID :one
-- Returns the user's first live project membership, used by the web shell as
-- the default project context after login.
SELECT pm.project_id, pm.role
FROM project_member pm
INNER JOIN app_user u
  ON pm.user_id = (CAST(u.id AS CHAR) COLLATE utf8mb4_unicode_ci)
INNER JOIN project p ON p.id = pm.project_id
WHERE pm.user_id = sqlc.arg(user_id)
  AND pm.deleted_at = '1970-01-01 00:00:00.000'
  AND u.status = 'active'
  AND u.deleted_at = '1970-01-01 00:00:00.000'
  AND p.tenant_id = u.tenant_id
  AND p.deleted_at = '1970-01-01 00:00:00.000'
ORDER BY pm.project_id ASC
LIMIT 1;

-- name: GetGlobalRoleByUserID :one
-- Legacy compatibility path: global role is temporarily cached in project_member
-- during migration. This query remains for backward compatibility and should
-- be removed after migration cut-over.
SELECT pm.role
FROM app_user u
INNER JOIN project_member pm
  ON pm.user_id = (CAST(u.id AS CHAR) COLLATE utf8mb4_unicode_ci)
INNER JOIN project p ON p.id = pm.project_id
WHERE u.id = sqlc.arg(user_id)
  AND u.status = 'active'
  AND u.deleted_at = '1970-01-01 00:00:00.000'
  AND pm.role IN ('system_admin', 'security_admin')
  AND pm.deleted_at = '1970-01-01 00:00:00.000'
  AND p.tenant_id = u.tenant_id
  AND p.deleted_at = '1970-01-01 00:00:00.000'
ORDER BY CASE pm.role WHEN 'system_admin' THEN 0 ELSE 1 END
LIMIT 1;

-- name: GetGlobalRoleByUserIDFromTenantRole :one
-- Authoritative role source after platform-user migration.
SELECT tur.role
FROM app_user u
INNER JOIN tenant_user_role tur
  ON tur.user_id = u.id
WHERE u.id = sqlc.arg(user_id)
  AND u.status = 'active'
  AND u.deleted_at = '1970-01-01 00:00:00.000'
  AND tur.deleted_at = '1970-01-01 00:00:00.000'
  AND tur.role IN ('system_admin', 'security_admin')
  AND tur.tenant_id = u.tenant_id
LIMIT 1;

-- name: CreateUser :execresult
-- Provisioning helper (used by seeding/tests; no public registration endpoint in M0-6).
INSERT INTO app_user (
    tenant_id, org_id, username, display_name, password_hash, status, created_by, updated_by
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListPlatformUsers :many
SELECT
    u.id,
    u.tenant_id,
    u.org_id,
    u.username,
    u.display_name,
    u.email,
    u.phone,
    u.department,
    u.status,
    u.last_login_at,
    u.must_change_password,
    u.created_at,
    u.updated_at,
    CAST(COALESCE((
        SELECT tur.role
        FROM tenant_user_role tur
        WHERE tur.tenant_id = u.tenant_id
          AND tur.user_id = u.id
          AND tur.deleted_at = '1970-01-01 00:00:00.000'
        LIMIT 1
    ), '') AS CHAR) AS tenant_role,
    (
        SELECT COUNT(DISTINCT pm.project_id)
        FROM project_member pm
        INNER JOIN project p ON p.id = pm.project_id
        WHERE pm.user_id = (CAST(u.id AS CHAR) COLLATE utf8mb4_unicode_ci)
          AND pm.deleted_at = '1970-01-01 00:00:00.000'
          AND p.tenant_id = u.tenant_id
          AND p.deleted_at = '1970-01-01 00:00:00.000'
    ) AS project_count
FROM app_user u
WHERE u.tenant_id = sqlc.arg(tenant_id)
  AND u.deleted_at = '1970-01-01 00:00:00.000'
  AND (
      sqlc.arg(search) = ''
      OR u.username LIKE CONCAT('%', sqlc.arg(search), '%')
      OR u.display_name LIKE CONCAT('%', sqlc.arg(search), '%')
      OR COALESCE(u.email, '') LIKE CONCAT('%', sqlc.arg(search), '%')
      OR COALESCE(u.phone, '') LIKE CONCAT('%', sqlc.arg(search), '%')
      OR u.department LIKE CONCAT('%', sqlc.arg(search), '%')
  )
  AND (sqlc.arg(status_filter) = '' OR u.status = sqlc.arg(status_filter))
  AND (
      sqlc.arg(role_filter) = ''
      OR (
          sqlc.arg(role_filter) = 'none'
          AND NOT EXISTS (
              SELECT 1 FROM tenant_user_role no_role
              WHERE no_role.tenant_id = u.tenant_id
                AND no_role.user_id = u.id
                AND no_role.deleted_at = '1970-01-01 00:00:00.000'
          )
      )
      OR EXISTS (
          SELECT 1 FROM tenant_user_role role_match
          WHERE role_match.tenant_id = u.tenant_id
            AND role_match.user_id = u.id
            AND role_match.role = sqlc.arg(role_filter)
            AND role_match.deleted_at = '1970-01-01 00:00:00.000'
      )
  )
ORDER BY u.updated_at DESC, u.id DESC
LIMIT ? OFFSET ?;

-- name: CountPlatformUsers :one
SELECT COUNT(*)
FROM app_user u
WHERE u.tenant_id = sqlc.arg(tenant_id)
  AND u.deleted_at = '1970-01-01 00:00:00.000'
  AND (
      sqlc.arg(search) = ''
      OR u.username LIKE CONCAT('%', sqlc.arg(search), '%')
      OR u.display_name LIKE CONCAT('%', sqlc.arg(search), '%')
      OR COALESCE(u.email, '') LIKE CONCAT('%', sqlc.arg(search), '%')
      OR COALESCE(u.phone, '') LIKE CONCAT('%', sqlc.arg(search), '%')
      OR u.department LIKE CONCAT('%', sqlc.arg(search), '%')
  )
  AND (sqlc.arg(status_filter) = '' OR u.status = sqlc.arg(status_filter))
  AND (
      sqlc.arg(role_filter) = ''
      OR (
          sqlc.arg(role_filter) = 'none'
          AND NOT EXISTS (
              SELECT 1 FROM tenant_user_role no_role
              WHERE no_role.tenant_id = u.tenant_id
                AND no_role.user_id = u.id
                AND no_role.deleted_at = '1970-01-01 00:00:00.000'
          )
      )
      OR EXISTS (
          SELECT 1 FROM tenant_user_role role_match
          WHERE role_match.tenant_id = u.tenant_id
            AND role_match.user_id = u.id
            AND role_match.role = sqlc.arg(role_filter)
            AND role_match.deleted_at = '1970-01-01 00:00:00.000'
      )
  );

-- name: GetPlatformUserByTenantID :one
SELECT
    u.id,
    u.tenant_id,
    u.org_id,
    u.username,
    u.display_name,
    u.email,
    u.phone,
    u.department,
    u.status,
    u.last_login_at,
    u.must_change_password,
    u.created_at,
    u.updated_at,
    CAST(COALESCE((
        SELECT tur.role
        FROM tenant_user_role tur
        WHERE tur.tenant_id = u.tenant_id
          AND tur.user_id = u.id
          AND tur.deleted_at = '1970-01-01 00:00:00.000'
        LIMIT 1
    ), '') AS CHAR) AS tenant_role,
    (
        SELECT COUNT(DISTINCT pm.project_id)
        FROM project_member pm
        INNER JOIN project p ON p.id = pm.project_id
        WHERE pm.user_id = (CAST(u.id AS CHAR) COLLATE utf8mb4_unicode_ci)
          AND pm.deleted_at = '1970-01-01 00:00:00.000'
          AND p.tenant_id = u.tenant_id
          AND p.deleted_at = '1970-01-01 00:00:00.000'
    ) AS project_count
FROM app_user u
WHERE u.tenant_id = sqlc.arg(tenant_id)
  AND u.id = sqlc.arg(user_id)
  AND u.deleted_at = '1970-01-01 00:00:00.000'
LIMIT 1;

-- name: CreatePlatformUser :execresult
INSERT INTO app_user (
    tenant_id,
    org_id,
    username,
    display_name,
    email,
    phone,
    department,
    password_hash,
    status,
    must_change_password,
    auth_version,
    created_by,
    updated_by
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE, 1, ?, ?);

-- name: UpdatePlatformUserProfile :execresult
UPDATE app_user
SET display_name = sqlc.arg(display_name),
    email = sqlc.narg(email),
    phone = sqlc.narg(phone),
    department = sqlc.arg(department),
    updated_by = sqlc.arg(updated_by)
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(user_id)
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: TransitionPlatformUserStatus :execresult
UPDATE app_user
SET status = sqlc.arg(next_status),
    auth_version = auth_version + 1,
    updated_by = sqlc.arg(updated_by)
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(user_id)
  AND status = sqlc.arg(previous_status)
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ResetPlatformUserPassword :execresult
UPDATE app_user
SET password_hash = sqlc.arg(password_hash),
    must_change_password = TRUE,
    auth_version = auth_version + 1,
    updated_by = sqlc.arg(updated_by)
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(user_id)
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ChangeCurrentUserPassword :execresult
UPDATE app_user
SET password_hash = sqlc.arg(password_hash),
    must_change_password = FALSE,
    auth_version = auth_version + 1,
    updated_by = sqlc.arg(updated_by)
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(user_id)
  AND status = 'active'
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: IncrementPlatformUserAuthVersion :execresult
UPDATE app_user
SET auth_version = auth_version + 1,
    updated_by = sqlc.arg(updated_by)
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(user_id)
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: UpsertTenantUserRole :exec
INSERT INTO tenant_user_role (
    tenant_id, user_id, role, created_by, updated_by
) VALUES (?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    role = VALUES(role),
    updated_by = VALUES(updated_by),
    updated_at = CURRENT_TIMESTAMP(3);

-- name: SoftDeleteTenantUserRole :exec
UPDATE tenant_user_role
SET deleted_at = CURRENT_TIMESTAMP(3),
    updated_by = sqlc.arg(updated_by),
    updated_at = CURRENT_TIMESTAMP(3)
WHERE tenant_id = sqlc.arg(tenant_id)
  AND user_id = sqlc.arg(user_id)
  AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListActiveSystemAdminIDsForUpdate :many
-- Lock the active system-admin rows so concurrent disable/downgrade operations
-- cannot both pass the "last administrator" guard.
SELECT u.id
FROM tenant_user_role tur
INNER JOIN app_user u
    ON u.id = tur.user_id
   AND u.tenant_id = tur.tenant_id
WHERE tur.tenant_id = ?
  AND tur.role = 'system_admin'
  AND tur.deleted_at = '1970-01-01 00:00:00.000'
  AND u.status = 'active'
  AND u.deleted_at = '1970-01-01 00:00:00.000'
FOR UPDATE;

-- name: ListPlatformUserProjects :many
SELECT
    p.id,
    p.project_code,
    p.name,
    pm.role,
    p.status,
    pm.updated_at
FROM app_user u
INNER JOIN project_member pm
    ON pm.user_id = (CAST(u.id AS CHAR) COLLATE utf8mb4_unicode_ci)
INNER JOIN project p
    ON p.id = pm.project_id
   AND p.tenant_id = u.tenant_id
WHERE u.tenant_id = sqlc.arg(tenant_id)
  AND u.id = sqlc.arg(user_id)
  AND u.deleted_at = '1970-01-01 00:00:00.000'
  AND pm.deleted_at = '1970-01-01 00:00:00.000'
  AND p.deleted_at = '1970-01-01 00:00:00.000'
ORDER BY p.name ASC, p.id ASC;
