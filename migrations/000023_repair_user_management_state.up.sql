-- Repair databases that applied the original 000022 during development.
-- Existing accounts did not receive a temporary password, so only accounts
-- created through the audited platform-user flow should retain the flag.

ALTER TABLE app_user
    ALTER COLUMN must_change_password SET DEFAULT 0;

UPDATE app_user u
SET u.must_change_password = FALSE,
    u.updated_by = CASE
        WHEN u.updated_by = '' THEN 'migration:000023'
        ELSE u.updated_by
    END
WHERE u.must_change_password = TRUE
  AND NOT EXISTS (
      SELECT 1
      FROM audit_log a
      WHERE a.tenant_id = u.tenant_id
        AND a.action = 'platform.user.create'
        AND a.resource_type = 'platform_user'
        AND a.resource_id = (CAST(u.id AS CHAR) COLLATE utf8mb4_unicode_ci)
        AND a.result = 'success'
  );
