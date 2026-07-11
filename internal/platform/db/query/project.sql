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

-- name: GetProjectActorScope :one
SELECT tenant_id, org_id FROM app_user
WHERE id = ? AND status = 'active' AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListProjectsForMember :many
SELECT p.* FROM project p
INNER JOIN project_member pm ON pm.project_id = p.id
WHERE pm.user_id = ?
  AND p.tenant_id = ?
  AND pm.deleted_at = '1970-01-01 00:00:00.000'
  AND p.deleted_at = '1970-01-01 00:00:00.000'
ORDER BY p.updated_at DESC, p.id DESC
LIMIT ? OFFSET ?;

-- name: CountProjectsForMember :one
SELECT COUNT(*) FROM project p
INNER JOIN project_member pm ON pm.project_id = p.id
WHERE pm.user_id = ?
  AND p.tenant_id = ?
  AND pm.deleted_at = '1970-01-01 00:00:00.000'
  AND p.deleted_at = '1970-01-01 00:00:00.000';

-- name: ListProjectsByTenant :many
SELECT * FROM project
WHERE tenant_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY updated_at DESC, id DESC
LIMIT ? OFFSET ?;

-- name: CountProjectsByTenant :one
SELECT COUNT(*) FROM project
WHERE tenant_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: GetWorkspaceSummaryForMember :one
WITH visible_projects AS (
    SELECT p.id, p.status
    FROM project p
    WHERE p.tenant_id = sqlc.arg(tenant_id)
      AND p.deleted_at = '1970-01-01 00:00:00.000'
      AND EXISTS (
          SELECT 1
          FROM project_member pm
          WHERE pm.project_id = p.id
            AND pm.user_id = sqlc.arg(user_id)
            AND pm.deleted_at = '1970-01-01 00:00:00.000'
      )
)
SELECT
    (SELECT COUNT(*) FROM visible_projects) AS project_total,
    (SELECT COUNT(*) FROM visible_projects WHERE status = 'active') AS project_active,
    (SELECT COUNT(*) FROM visible_projects WHERE status = 'draft') AS project_draft,
    (SELECT COUNT(*) FROM visible_projects WHERE status = 'suspended') AS project_suspended,
    (SELECT COUNT(*) FROM asset a
        INNER JOIN visible_projects vp ON vp.id = a.project_id
        WHERE a.deleted_at = '1970-01-01 00:00:00.000') AS asset_total,
    (SELECT COUNT(*) FROM risk r
        INNER JOIN visible_projects vp ON vp.id = r.project_id
        WHERE r.status NOT IN ('risk_accepted', 'false_positive', 'fixed')
          AND r.deleted_at = '1970-01-01 00:00:00.000') AS risk_open,
    (SELECT COUNT(*) FROM risk r
        INNER JOIN visible_projects vp ON vp.id = r.project_id
        WHERE r.status NOT IN ('risk_accepted', 'false_positive', 'fixed')
          AND r.severity IN ('critical', 'high')
          AND r.deleted_at = '1970-01-01 00:00:00.000') AS risk_critical_high,
    (SELECT COUNT(*) FROM risk r
        INNER JOIN visible_projects vp ON vp.id = r.project_id
        WHERE r.status NOT IN ('risk_accepted', 'false_positive', 'fixed')
          AND r.sla_due_at <> '1970-01-01 00:00:00.000'
          AND r.sla_due_at < CURRENT_TIMESTAMP(3)
          AND r.deleted_at = '1970-01-01 00:00:00.000') AS risk_overdue,
    (SELECT COUNT(*) FROM ticket t
        INNER JOIN visible_projects vp ON vp.id = t.project_id
        WHERE t.status NOT IN ('closed', 'cancelled')
          AND t.deleted_at = '1970-01-01 00:00:00.000') AS ticket_open,
    (SELECT COUNT(*) FROM ticket t
        INNER JOIN visible_projects vp ON vp.id = t.project_id
        WHERE t.status NOT IN ('closed', 'cancelled')
          AND t.due_at <> '1970-01-01 00:00:00.000'
          AND t.due_at < CURRENT_TIMESTAMP(3)
          AND t.deleted_at = '1970-01-01 00:00:00.000') AS ticket_overdue;

-- name: GetWorkspaceSummaryByTenant :one
WITH visible_projects AS (
    SELECT p.id, p.status
    FROM project p
    WHERE p.tenant_id = sqlc.arg(tenant_id)
      AND p.deleted_at = '1970-01-01 00:00:00.000'
)
SELECT
    (SELECT COUNT(*) FROM visible_projects) AS project_total,
    (SELECT COUNT(*) FROM visible_projects WHERE status = 'active') AS project_active,
    (SELECT COUNT(*) FROM visible_projects WHERE status = 'draft') AS project_draft,
    (SELECT COUNT(*) FROM visible_projects WHERE status = 'suspended') AS project_suspended,
    (SELECT COUNT(*) FROM asset a
        INNER JOIN visible_projects vp ON vp.id = a.project_id
        WHERE a.deleted_at = '1970-01-01 00:00:00.000') AS asset_total,
    (SELECT COUNT(*) FROM risk r
        INNER JOIN visible_projects vp ON vp.id = r.project_id
        WHERE r.status NOT IN ('risk_accepted', 'false_positive', 'fixed')
          AND r.deleted_at = '1970-01-01 00:00:00.000') AS risk_open,
    (SELECT COUNT(*) FROM risk r
        INNER JOIN visible_projects vp ON vp.id = r.project_id
        WHERE r.status NOT IN ('risk_accepted', 'false_positive', 'fixed')
          AND r.severity IN ('critical', 'high')
          AND r.deleted_at = '1970-01-01 00:00:00.000') AS risk_critical_high,
    (SELECT COUNT(*) FROM risk r
        INNER JOIN visible_projects vp ON vp.id = r.project_id
        WHERE r.status NOT IN ('risk_accepted', 'false_positive', 'fixed')
          AND r.sla_due_at <> '1970-01-01 00:00:00.000'
          AND r.sla_due_at < CURRENT_TIMESTAMP(3)
          AND r.deleted_at = '1970-01-01 00:00:00.000') AS risk_overdue,
    (SELECT COUNT(*) FROM ticket t
        INNER JOIN visible_projects vp ON vp.id = t.project_id
        WHERE t.status NOT IN ('closed', 'cancelled')
          AND t.deleted_at = '1970-01-01 00:00:00.000') AS ticket_open,
    (SELECT COUNT(*) FROM ticket t
        INNER JOIN visible_projects vp ON vp.id = t.project_id
        WHERE t.status NOT IN ('closed', 'cancelled')
          AND t.due_at <> '1970-01-01 00:00:00.000'
          AND t.due_at < CURRENT_TIMESTAMP(3)
          AND t.deleted_at = '1970-01-01 00:00:00.000') AS ticket_overdue;

-- name: ListRecentWorkspaceProjectsForMember :many
SELECT p.*
FROM project p
WHERE p.tenant_id = sqlc.arg(tenant_id)
  AND p.deleted_at = '1970-01-01 00:00:00.000'
  AND EXISTS (
      SELECT 1
      FROM project_member pm
      WHERE pm.project_id = p.id
        AND pm.user_id = sqlc.arg(user_id)
        AND pm.deleted_at = '1970-01-01 00:00:00.000'
  )
ORDER BY p.updated_at DESC, p.id DESC
LIMIT 5;

-- name: ListRecentWorkspaceProjectsByTenant :many
SELECT *
FROM project
WHERE tenant_id = ?
  AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY updated_at DESC, id DESC
LIMIT 5;

-- name: CreateProject :execresult
INSERT INTO project (
    tenant_id, org_id, project_code, name, owner, business_unit,
    criticality, status, description, created_by, updated_by
) VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?);

-- name: CreateProjectMember :execresult
INSERT INTO project_member (project_id, user_id, role, created_by, updated_by)
VALUES (?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE role = VALUES(role), updated_by = VALUES(updated_by);

-- name: UpdateProject :exec
UPDATE project
SET name = ?, owner = ?, business_unit = ?, criticality = ?, description = ?, updated_by = ?
WHERE id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: TransitionProjectStatus :execresult
UPDATE project
SET status = ?, updated_by = ?
WHERE id = ? AND status = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ClearPrimaryProjectSubjects :exec
UPDATE project_subject SET is_primary = FALSE, updated_by = ?
WHERE project_id = ? AND is_primary = TRUE AND deleted_at = '1970-01-01 00:00:00.000';

-- name: CreateProjectSubject :execresult
INSERT INTO project_subject (
    tenant_id, org_id, project_id, subject_key, subject_name, subject_type,
    registration_code, country_code, region, is_primary, verification_status,
    source, verified_at, evidence_summary, created_by, updated_by
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetProjectSubject :one
SELECT * FROM project_subject
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListProjectSubjects :many
SELECT * FROM project_subject
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY is_primary DESC, id;

-- name: UpdateProjectSubject :exec
UPDATE project_subject
SET subject_key = ?, subject_name = ?, subject_type = ?, registration_code = ?,
    country_code = ?, region = ?, is_primary = ?, verification_status = ?,
    source = ?, verified_at = ?, evidence_summary = ?, updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ClearPrimaryProjectDomains :exec
UPDATE project_domain_profile SET is_primary = FALSE, updated_by = ?
WHERE project_id = ? AND is_primary = TRUE AND deleted_at = '1970-01-01 00:00:00.000';

-- name: CreateProjectDomainProfile :execresult
INSERT INTO project_domain_profile (
    tenant_id, org_id, project_id, asset_id, subject_id, is_primary,
    ownership_status, source, evidence_summary, created_by, updated_by
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    subject_id = VALUES(subject_id), is_primary = VALUES(is_primary),
    ownership_status = VALUES(ownership_status), source = VALUES(source),
    evidence_summary = VALUES(evidence_summary), updated_by = VALUES(updated_by);

-- name: GetProjectDomainProfileByAsset :one
SELECT pdp.*, a.value AS domain FROM project_domain_profile pdp
INNER JOIN asset a ON a.id = pdp.asset_id AND a.project_id = pdp.project_id
WHERE pdp.project_id = ? AND pdp.asset_id = ?
  AND pdp.deleted_at = '1970-01-01 00:00:00.000'
  AND a.deleted_at = '1970-01-01 00:00:00.000';

-- name: GetProjectDomainProfile :one
SELECT pdp.*, a.value AS domain FROM project_domain_profile pdp
INNER JOIN asset a ON a.id = pdp.asset_id AND a.project_id = pdp.project_id
WHERE pdp.id = ? AND pdp.project_id = ?
  AND pdp.deleted_at = '1970-01-01 00:00:00.000'
  AND a.deleted_at = '1970-01-01 00:00:00.000';

-- name: ListProjectDomainProfiles :many
SELECT pdp.*, a.value AS domain FROM project_domain_profile pdp
INNER JOIN asset a ON a.id = pdp.asset_id AND a.project_id = pdp.project_id
WHERE pdp.project_id = ?
  AND pdp.deleted_at = '1970-01-01 00:00:00.000'
  AND a.deleted_at = '1970-01-01 00:00:00.000'
ORDER BY pdp.is_primary DESC, pdp.id;

-- name: UpdateProjectDomainProfile :exec
UPDATE project_domain_profile
SET subject_id = ?, is_primary = ?, ownership_status = ?, source = ?,
    evidence_summary = ?, updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: CreateICPFilings :execresult
INSERT INTO icp_filing (
    tenant_id, org_id, project_id, subject_id, filing_no, filing_type,
    website_name, status, approved_at, source, verified_at, evidence_summary,
    created_by, updated_by
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetICPFiling :one
SELECT * FROM icp_filing
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ListICPFilings :many
SELECT * FROM icp_filing
WHERE project_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY id;

-- name: UpdateICPFiling :exec
UPDATE icp_filing
SET subject_id = ?, filing_no = ?, filing_type = ?, website_name = ?, status = ?,
    approved_at = ?, source = ?, verified_at = ?, evidence_summary = ?, updated_by = ?
WHERE id = ? AND project_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: ClearICPFilingDomains :exec
UPDATE icp_filing_domain
SET deleted_at = CURRENT_TIMESTAMP(3), updated_by = ?
WHERE project_id = ? AND filing_id = ? AND deleted_at = '1970-01-01 00:00:00.000';

-- name: CreateICPFilingDomain :execresult
INSERT INTO icp_filing_domain (
    tenant_id, org_id, project_id, filing_id, domain_profile_id, created_by, updated_by
) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListICPFilingDomainIDs :many
SELECT domain_profile_id FROM icp_filing_domain
WHERE project_id = ? AND filing_id = ? AND deleted_at = '1970-01-01 00:00:00.000'
ORDER BY domain_profile_id;

-- name: GetProjectOnboardingCounts :one
SELECT
    (SELECT COUNT(*) FROM project_member pm
      WHERE pm.project_id = sqlc.arg(project_id) AND pm.role = 'project_owner'
        AND pm.deleted_at = '1970-01-01 00:00:00.000') AS owner_count,
    (SELECT COUNT(*) FROM project_subject ps
      WHERE ps.project_id = sqlc.arg(project_id) AND ps.is_primary = TRUE
        AND ps.deleted_at = '1970-01-01 00:00:00.000') AS primary_subject_count,
    (SELECT COUNT(*) FROM project_domain_profile pdp
      WHERE pdp.project_id = sqlc.arg(project_id) AND pdp.is_primary = TRUE
        AND pdp.deleted_at = '1970-01-01 00:00:00.000') AS primary_domain_count,
    (SELECT COUNT(*) FROM scope s
      WHERE s.project_id = sqlc.arg(project_id) AND s.status = 'active'
        AND s.valid_from <= CURRENT_TIMESTAMP(3) AND s.valid_until > CURRENT_TIMESTAMP(3)
        AND s.deleted_at = '1970-01-01 00:00:00.000'
        AND EXISTS (SELECT 1 FROM scope_target st WHERE st.project_id = s.project_id
            AND st.scope_id = s.id AND st.match_mode = 'include'
            AND st.deleted_at = '1970-01-01 00:00:00.000')) AS valid_scope_count;
