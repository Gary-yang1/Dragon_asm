-- sqlc queries for the project domain.
-- Every read filters on the soft-delete sentinel so soft-deleted rows are
-- excluded by default; callers never need to remember to add the filter.

-- name: GetProjectByID :one
SELECT * FROM project
WHERE id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetProjectByCode :one
SELECT * FROM project
WHERE tenant_id = ? AND project_code = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetProjectMemberRole :one
-- Returns the member's role, or sql.ErrNoRows when the user is not a member.
SELECT role FROM project_member
WHERE project_id = ? AND user_id = ? AND deleted_at = '1970-01-01 00:00:00.000';
