package project

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Workspace repository errors normalized across SQL driver failures.
var (
	ErrConflict      = errors.New("project: conflict")
	ErrInvalidActor  = errors.New("project: invalid actor")
	ErrWriteNotFound = errors.New("project: write target not found")
)

// OnboardingCounts contains aggregate activation prerequisites for a project.
type OnboardingCounts struct {
	OwnerCount          int64
	PrimarySubjectCount int64
	PrimaryDomainCount  int64
	ValidScopeCount     int64
}

// WorkspaceRepository persists projects and their profile resources.
type WorkspaceRepository interface {
	ActorScope(ctx context.Context, actorID string) (ActorScope, error)
	ListForMember(ctx context.Context, tenantID, actorID string, limit, offset int32) ([]*Project, int64, error)
	ListForTenant(ctx context.Context, tenantID string, limit, offset int32) ([]*Project, int64, error)
	WorkspaceSummaryForMember(ctx context.Context, tenantID, actorID string) (WorkspaceSummary, error)
	WorkspaceSummaryForTenant(ctx context.Context, tenantID string) (WorkspaceSummary, error)
	CreateProject(ctx context.Context, in CreateProjectParams) (uint64, error)
	CreateMember(ctx context.Context, projectID uint64, userID, role, actorID string) error
	UpdateProject(ctx context.Context, in UpdateProjectParams) error
	TransitionStatus(ctx context.Context, projectID uint64, from, to, actorID string) (bool, error)

	CreateSubject(ctx context.Context, scope ActorScope, in SubjectInput, subjectKey string) (uint64, error)
	GetSubject(ctx context.Context, projectID, subjectID uint64) (*Subject, error)
	ListSubjects(ctx context.Context, projectID uint64) ([]*Subject, error)
	UpdateSubject(ctx context.Context, in SubjectInput, subjectKey string) error

	UpsertRootDomainAsset(ctx context.Context, p *Project, domain, actorID string) (uint64, error)
	CreateDomainProfile(ctx context.Context, scope ActorScope, assetID uint64, in DomainInput) error
	GetDomainProfile(ctx context.Context, projectID, profileID uint64) (*DomainProfile, error)
	GetDomainProfileByAsset(ctx context.Context, projectID, assetID uint64) (*DomainProfile, error)
	ListDomainProfiles(ctx context.Context, projectID uint64) ([]*DomainProfile, error)
	UpdateDomainProfile(ctx context.Context, in DomainInput) error

	CreateICP(ctx context.Context, scope ActorScope, in ICPInput) (uint64, error)
	GetICP(ctx context.Context, projectID, filingID uint64) (*ICPFilings, error)
	ListICPs(ctx context.Context, projectID uint64) ([]*ICPFilings, error)
	UpdateICP(ctx context.Context, in ICPInput) error
	ReplaceICPDomainLinks(ctx context.Context, scope ActorScope, projectID, filingID uint64, domainIDs []uint64, actorID string) error
	OnboardingCounts(ctx context.Context, projectID uint64) (OnboardingCounts, error)
}

func (r *sqlcRepository) ActorScope(ctx context.Context, actorID string) (ActorScope, error) {
	id, err := strconv.ParseUint(actorID, 10, 64)
	if err != nil || id == 0 {
		return ActorScope{}, ErrInvalidActor
	}
	row, err := r.q.GetProjectActorScope(ctx, id)
	if err != nil {
		return ActorScope{}, mapWorkspaceErr(err)
	}
	return ActorScope{TenantID: row.TenantID, OrgID: row.OrgID}, nil
}

func (r *sqlcRepository) ListForMember(ctx context.Context, tenantID, actorID string, limit, offset int32) ([]*Project, int64, error) {
	rows, err := r.q.ListProjectsForMember(ctx, dbgen.ListProjectsForMemberParams{UserID: actorID, TenantID: tenantID, Limit: limit, Offset: offset})
	if err != nil {
		return nil, 0, err
	}
	total, err := r.q.CountProjectsForMember(ctx, dbgen.CountProjectsForMemberParams{UserID: actorID, TenantID: tenantID})
	return mapProjects(rows), total, err
}

func (r *sqlcRepository) ListForTenant(ctx context.Context, tenantID string, limit, offset int32) ([]*Project, int64, error) {
	rows, err := r.q.ListProjectsByTenant(ctx, dbgen.ListProjectsByTenantParams{TenantID: tenantID, Limit: limit, Offset: offset})
	if err != nil {
		return nil, 0, err
	}
	total, err := r.q.CountProjectsByTenant(ctx, tenantID)
	return mapProjects(rows), total, err
}

func (r *sqlcRepository) WorkspaceSummaryForMember(ctx context.Context, tenantID, actorID string) (WorkspaceSummary, error) {
	row, err := r.q.GetWorkspaceSummaryForMember(ctx, dbgen.GetWorkspaceSummaryForMemberParams{
		TenantID: tenantID,
		UserID:   actorID,
	})
	if err != nil {
		return WorkspaceSummary{}, err
	}
	recent, err := r.q.ListRecentWorkspaceProjectsForMember(ctx, dbgen.ListRecentWorkspaceProjectsForMemberParams{
		TenantID: tenantID,
		UserID:   actorID,
	})
	if err != nil {
		return WorkspaceSummary{}, err
	}
	return workspaceSummary(
		row.ProjectTotal, row.ProjectActive, row.ProjectDraft, row.ProjectSuspended,
		row.AssetTotal, row.RiskOpen, row.RiskCriticalHigh, row.RiskOverdue,
		row.TicketOpen, row.TicketOverdue, recent,
	), nil
}

func (r *sqlcRepository) WorkspaceSummaryForTenant(ctx context.Context, tenantID string) (WorkspaceSummary, error) {
	row, err := r.q.GetWorkspaceSummaryByTenant(ctx, tenantID)
	if err != nil {
		return WorkspaceSummary{}, err
	}
	recent, err := r.q.ListRecentWorkspaceProjectsByTenant(ctx, tenantID)
	if err != nil {
		return WorkspaceSummary{}, err
	}
	return workspaceSummary(
		row.ProjectTotal, row.ProjectActive, row.ProjectDraft, row.ProjectSuspended,
		row.AssetTotal, row.RiskOpen, row.RiskCriticalHigh, row.RiskOverdue,
		row.TicketOpen, row.TicketOverdue, recent,
	), nil
}

func (r *sqlcRepository) CreateProject(ctx context.Context, in CreateProjectParams) (uint64, error) {
	result, err := r.q.CreateProject(ctx, dbgen.CreateProjectParams{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectCode: in.ProjectCode,
		Name: in.Name, Owner: in.Owner, BusinessUnit: in.BusinessUnit,
		Criticality: in.Criticality, Description: nullString(in.Description),
		CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	})
	if err != nil {
		return 0, mapWorkspaceErr(err)
	}
	return workspaceResultID(result)
}

func (r *sqlcRepository) CreateMember(ctx context.Context, projectID uint64, userID, role, actorID string) error {
	_, err := r.q.CreateProjectMember(ctx, dbgen.CreateProjectMemberParams{
		ProjectID: projectID, UserID: userID, Role: role, CreatedBy: actorID, UpdatedBy: actorID,
	})
	return mapWorkspaceErr(err)
}

func (r *sqlcRepository) UpdateProject(ctx context.Context, in UpdateProjectParams) error {
	return mapWorkspaceErr(r.q.UpdateProject(ctx, dbgen.UpdateProjectParams{
		Name: in.Name, Owner: in.Owner, BusinessUnit: in.BusinessUnit,
		Criticality: in.Criticality, Description: nullString(in.Description),
		UpdatedBy: in.ActorID, ID: in.ID,
	}))
}

func (r *sqlcRepository) TransitionStatus(ctx context.Context, projectID uint64, from, to, actorID string) (bool, error) {
	result, err := r.q.TransitionProjectStatus(ctx, dbgen.TransitionProjectStatusParams{
		Status: to, UpdatedBy: actorID, ID: projectID, Status_2: from,
	})
	if err != nil {
		return false, mapWorkspaceErr(err)
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (r *sqlcRepository) CreateSubject(ctx context.Context, scope ActorScope, in SubjectInput, subjectKey string) (uint64, error) {
	if in.IsPrimary {
		if err := r.q.ClearPrimaryProjectSubjects(ctx, dbgen.ClearPrimaryProjectSubjectsParams{UpdatedBy: in.ActorID, ProjectID: in.ProjectID}); err != nil {
			return 0, err
		}
	}
	result, err := r.q.CreateProjectSubject(ctx, dbgen.CreateProjectSubjectParams{
		TenantID: scope.TenantID, OrgID: scope.OrgID, ProjectID: in.ProjectID,
		SubjectKey: subjectKey, SubjectName: in.SubjectName, SubjectType: in.SubjectType,
		RegistrationCode: in.RegistrationCode, CountryCode: in.CountryCode, Region: in.Region,
		IsPrimary: in.IsPrimary, VerificationStatus: in.VerificationStatus, Source: in.Source,
		VerifiedAt: nullTime(in.VerifiedAt), EvidenceSummary: in.EvidenceSummary,
		CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	})
	if err != nil {
		return 0, mapWorkspaceErr(err)
	}
	return workspaceResultID(result)
}

func (r *sqlcRepository) GetSubject(ctx context.Context, projectID, subjectID uint64) (*Subject, error) {
	row, err := r.q.GetProjectSubject(ctx, dbgen.GetProjectSubjectParams{ID: subjectID, ProjectID: projectID})
	if err != nil {
		return nil, mapWorkspaceErr(err)
	}
	return mapSubject(row), nil
}

func (r *sqlcRepository) ListSubjects(ctx context.Context, projectID uint64) ([]*Subject, error) {
	rows, err := r.q.ListProjectSubjects(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*Subject, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapSubject(row))
	}
	return out, nil
}

func (r *sqlcRepository) UpdateSubject(ctx context.Context, in SubjectInput, subjectKey string) error {
	if in.IsPrimary {
		if err := r.q.ClearPrimaryProjectSubjects(ctx, dbgen.ClearPrimaryProjectSubjectsParams{UpdatedBy: in.ActorID, ProjectID: in.ProjectID}); err != nil {
			return err
		}
	}
	return mapWorkspaceErr(r.q.UpdateProjectSubject(ctx, dbgen.UpdateProjectSubjectParams{
		SubjectKey: subjectKey, SubjectName: in.SubjectName, SubjectType: in.SubjectType,
		RegistrationCode: in.RegistrationCode, CountryCode: in.CountryCode, Region: in.Region,
		IsPrimary: in.IsPrimary, VerificationStatus: in.VerificationStatus, Source: in.Source,
		VerifiedAt: nullTime(in.VerifiedAt), EvidenceSummary: in.EvidenceSummary,
		UpdatedBy: in.ActorID, ID: in.SubjectID, ProjectID: in.ProjectID,
	}))
}

func (r *sqlcRepository) UpsertRootDomainAsset(ctx context.Context, p *Project, domain, actorID string) (uint64, error) {
	now := time.Now().UTC()
	_, err := r.q.UpsertAsset(ctx, dbgen.UpsertAssetParams{
		TenantID: p.TenantID, OrgID: p.OrgID, ProjectID: p.ID,
		AssetType: "domain", AssetKey: "domain:" + domain, DisplayName: domain,
		Value: domain, Source: "project_profile", Owner: p.Owner,
		BusinessUnit: p.BusinessUnit, Confidence: 100, Status: "active",
		FirstSeen: now, LastSeen: now, CreatedBy: actorID, UpdatedBy: actorID,
	})
	if err != nil {
		return 0, mapWorkspaceErr(err)
	}
	a, err := r.q.GetAssetByKey(ctx, dbgen.GetAssetByKeyParams{ProjectID: p.ID, AssetKey: "domain:" + domain})
	if err != nil {
		return 0, mapWorkspaceErr(err)
	}
	return a.ID, nil
}

func (r *sqlcRepository) CreateDomainProfile(ctx context.Context, scope ActorScope, assetID uint64, in DomainInput) error {
	if in.IsPrimary {
		if err := r.q.ClearPrimaryProjectDomains(ctx, dbgen.ClearPrimaryProjectDomainsParams{UpdatedBy: in.ActorID, ProjectID: in.ProjectID}); err != nil {
			return err
		}
	}
	_, err := r.q.CreateProjectDomainProfile(ctx, dbgen.CreateProjectDomainProfileParams{
		TenantID: scope.TenantID, OrgID: scope.OrgID, ProjectID: in.ProjectID,
		AssetID: assetID, SubjectID: nullUint64(in.SubjectID), IsPrimary: in.IsPrimary,
		OwnershipStatus: in.OwnershipStatus, Source: in.Source, EvidenceSummary: in.EvidenceSummary,
		CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	})
	return mapWorkspaceErr(err)
}

func (r *sqlcRepository) GetDomainProfile(ctx context.Context, projectID, profileID uint64) (*DomainProfile, error) {
	row, err := r.q.GetProjectDomainProfile(ctx, dbgen.GetProjectDomainProfileParams{ID: profileID, ProjectID: projectID})
	if err != nil {
		return nil, mapWorkspaceErr(err)
	}
	return mapDomainProfile(row), nil
}

func (r *sqlcRepository) GetDomainProfileByAsset(ctx context.Context, projectID, assetID uint64) (*DomainProfile, error) {
	row, err := r.q.GetProjectDomainProfileByAsset(ctx, dbgen.GetProjectDomainProfileByAssetParams{ProjectID: projectID, AssetID: assetID})
	if err != nil {
		return nil, mapWorkspaceErr(err)
	}
	return mapDomainProfileByAsset(row), nil
}

func (r *sqlcRepository) ListDomainProfiles(ctx context.Context, projectID uint64) ([]*DomainProfile, error) {
	rows, err := r.q.ListProjectDomainProfiles(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*DomainProfile, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapDomainProfileList(row))
	}
	return out, nil
}

func (r *sqlcRepository) UpdateDomainProfile(ctx context.Context, in DomainInput) error {
	if in.IsPrimary {
		if err := r.q.ClearPrimaryProjectDomains(ctx, dbgen.ClearPrimaryProjectDomainsParams{UpdatedBy: in.ActorID, ProjectID: in.ProjectID}); err != nil {
			return err
		}
	}
	return mapWorkspaceErr(r.q.UpdateProjectDomainProfile(ctx, dbgen.UpdateProjectDomainProfileParams{
		SubjectID: nullUint64(in.SubjectID), IsPrimary: in.IsPrimary,
		OwnershipStatus: in.OwnershipStatus, Source: in.Source, EvidenceSummary: in.EvidenceSummary,
		UpdatedBy: in.ActorID, ID: in.DomainProfileID, ProjectID: in.ProjectID,
	}))
}

func (r *sqlcRepository) CreateICP(ctx context.Context, scope ActorScope, in ICPInput) (uint64, error) {
	result, err := r.q.CreateICPFilings(ctx, dbgen.CreateICPFilingsParams{
		TenantID: scope.TenantID, OrgID: scope.OrgID, ProjectID: in.ProjectID,
		SubjectID: in.SubjectID, FilingNo: in.FilingNo, FilingType: in.FilingType,
		WebsiteName: in.WebsiteName, Status: in.Status, ApprovedAt: nullTime(in.ApprovedAt),
		Source: in.Source, VerifiedAt: nullTime(in.VerifiedAt), EvidenceSummary: in.EvidenceSummary,
		CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	})
	if err != nil {
		return 0, mapWorkspaceErr(err)
	}
	return workspaceResultID(result)
}

func (r *sqlcRepository) GetICP(ctx context.Context, projectID, filingID uint64) (*ICPFilings, error) {
	row, err := r.q.GetICPFiling(ctx, dbgen.GetICPFilingParams{ID: filingID, ProjectID: projectID})
	if err != nil {
		return nil, mapWorkspaceErr(err)
	}
	ids, err := r.q.ListICPFilingDomainIDs(ctx, dbgen.ListICPFilingDomainIDsParams{ProjectID: projectID, FilingID: filingID})
	if err != nil {
		return nil, err
	}
	return mapICP(row, ids), nil
}

func (r *sqlcRepository) ListICPs(ctx context.Context, projectID uint64) ([]*ICPFilings, error) {
	rows, err := r.q.ListICPFilings(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*ICPFilings, 0, len(rows))
	for _, row := range rows {
		ids, err := r.q.ListICPFilingDomainIDs(ctx, dbgen.ListICPFilingDomainIDsParams{ProjectID: projectID, FilingID: row.ID})
		if err != nil {
			return nil, err
		}
		out = append(out, mapICP(row, ids))
	}
	return out, nil
}

func (r *sqlcRepository) UpdateICP(ctx context.Context, in ICPInput) error {
	return mapWorkspaceErr(r.q.UpdateICPFiling(ctx, dbgen.UpdateICPFilingParams{
		SubjectID: in.SubjectID, FilingNo: in.FilingNo, FilingType: in.FilingType,
		WebsiteName: in.WebsiteName, Status: in.Status, ApprovedAt: nullTime(in.ApprovedAt),
		Source: in.Source, VerifiedAt: nullTime(in.VerifiedAt), EvidenceSummary: in.EvidenceSummary,
		UpdatedBy: in.ActorID, ID: in.FilingID, ProjectID: in.ProjectID,
	}))
}

func (r *sqlcRepository) ReplaceICPDomainLinks(ctx context.Context, scope ActorScope, projectID, filingID uint64, domainIDs []uint64, actorID string) error {
	if err := r.q.ClearICPFilingDomains(ctx, dbgen.ClearICPFilingDomainsParams{UpdatedBy: actorID, ProjectID: projectID, FilingID: filingID}); err != nil {
		return err
	}
	for _, domainID := range domainIDs {
		_, err := r.q.GetProjectDomainProfile(ctx, dbgen.GetProjectDomainProfileParams{ID: domainID, ProjectID: projectID})
		if err != nil {
			return mapWorkspaceErr(err)
		}
		_, err = r.q.CreateICPFilingDomain(ctx, dbgen.CreateICPFilingDomainParams{
			TenantID: scope.TenantID, OrgID: scope.OrgID, ProjectID: projectID,
			FilingID: filingID, DomainProfileID: domainID, CreatedBy: actorID, UpdatedBy: actorID,
		})
		if err != nil {
			return mapWorkspaceErr(err)
		}
	}
	return nil
}

func (r *sqlcRepository) OnboardingCounts(ctx context.Context, projectID uint64) (OnboardingCounts, error) {
	row, err := r.q.GetProjectOnboardingCounts(ctx, dbgen.GetProjectOnboardingCountsParams{ProjectID: projectID})
	return OnboardingCounts(row), err
}

func mapWorkspaceErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var mysqlErr *mysqlDriver.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		return ErrConflict
	}
	return err
}

func mapProjects(rows []dbgen.Project) []*Project {
	out := make([]*Project, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomain(row))
	}
	return out
}

func workspaceSummary(
	projectTotal, projectActive, projectDraft, projectSuspended,
	assetTotal, riskOpen, riskCriticalHigh, riskOverdue,
	ticketOpen, ticketOverdue int64,
	recent []dbgen.Project,
) WorkspaceSummary {
	projects := make([]WorkspaceProject, 0, len(recent))
	for _, row := range recent {
		projects = append(projects, WorkspaceProject{
			ID: row.ID, ProjectCode: row.ProjectCode, Name: row.Name, OwnerUserID: row.Owner,
			BusinessUnit: row.BusinessUnit, Criticality: row.Criticality, Status: row.Status,
			UpdatedAt: row.UpdatedAt,
		})
	}
	return WorkspaceSummary{
		Projects:       WorkspaceProjectStats{Total: projectTotal, Active: projectActive, Draft: projectDraft, Suspended: projectSuspended},
		Assets:         WorkspaceAssetStats{Total: assetTotal},
		Risks:          WorkspaceRiskStats{Open: riskOpen, CriticalHigh: riskCriticalHigh, Overdue: riskOverdue},
		Tickets:        WorkspaceTicketStats{Open: ticketOpen, Overdue: ticketOverdue},
		RecentProjects: projects,
	}
}

func mapSubject(row dbgen.ProjectSubject) *Subject {
	return &Subject{ID: row.ID, ProjectID: row.ProjectID, SubjectName: row.SubjectName,
		SubjectType: row.SubjectType, RegistrationCode: row.RegistrationCode, CountryCode: row.CountryCode,
		Region: row.Region, IsPrimary: row.IsPrimary, VerificationStatus: row.VerificationStatus,
		Source: row.Source, VerifiedAt: timePtr(row.VerifiedAt), EvidenceSummary: row.EvidenceSummary,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func mapDomainProfile(row dbgen.GetProjectDomainProfileRow) *DomainProfile {
	return &DomainProfile{ID: row.ID, ProjectID: row.ProjectID, AssetID: row.AssetID,
		Domain: row.Domain, SubjectID: uint64FromNull(row.SubjectID), IsPrimary: row.IsPrimary,
		OwnershipStatus: row.OwnershipStatus, Source: row.Source, EvidenceSummary: row.EvidenceSummary,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func mapDomainProfileByAsset(row dbgen.GetProjectDomainProfileByAssetRow) *DomainProfile {
	return &DomainProfile{ID: row.ID, ProjectID: row.ProjectID, AssetID: row.AssetID,
		Domain: row.Domain, SubjectID: uint64FromNull(row.SubjectID), IsPrimary: row.IsPrimary,
		OwnershipStatus: row.OwnershipStatus, Source: row.Source, EvidenceSummary: row.EvidenceSummary,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func mapDomainProfileList(row dbgen.ListProjectDomainProfilesRow) *DomainProfile {
	return &DomainProfile{ID: row.ID, ProjectID: row.ProjectID, AssetID: row.AssetID,
		Domain: row.Domain, SubjectID: uint64FromNull(row.SubjectID), IsPrimary: row.IsPrimary,
		OwnershipStatus: row.OwnershipStatus, Source: row.Source, EvidenceSummary: row.EvidenceSummary,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func mapICP(row dbgen.IcpFiling, ids []uint64) *ICPFilings {
	return &ICPFilings{ID: row.ID, ProjectID: row.ProjectID, SubjectID: row.SubjectID,
		FilingNo: row.FilingNo, FilingType: row.FilingType, WebsiteName: row.WebsiteName,
		Status: row.Status, ApprovedAt: timePtr(row.ApprovedAt), Source: row.Source,
		VerifiedAt: timePtr(row.VerifiedAt), EvidenceSummary: row.EvidenceSummary,
		DomainProfileIDs: ids, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func nullString(v string) sql.NullString { return sql.NullString{String: v, Valid: v != ""} }
func nullTime(v *time.Time) sql.NullTime {
	if v == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: v.UTC(), Valid: true}
}
func timePtr(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time.UTC()
	return &t
}
func nullUint64(v uint64) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(v), Valid: true} //nolint:gosec // IDs originate from MySQL signed driver values.
}
func uint64FromNull(v sql.NullInt64) uint64 {
	if !v.Valid || v.Int64 <= 0 {
		return 0
	}
	return uint64(v.Int64)
}

func workspaceResultID(result sql.Result) (uint64, error) {
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if id <= 0 {
		return 0, fmt.Errorf("project: invalid insert id %d", id)
	}
	return uint64(id), nil
}
