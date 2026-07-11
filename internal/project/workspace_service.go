package project

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Project workspace audit action and resource type names.
const (
	ActionWorkspaceSummaryRead = "workspace.summary.read"
	ActionProjectListRead      = "project.list.read"
	ActionProjectCreate        = "project.create"
	ActionProjectUpdate        = "project.update"
	ActionProjectTransition    = "project.transition"
	ActionSubjectCreate        = "project.subject.create"
	ActionSubjectUpdate        = "project.subject.update"
	ActionDomainSave           = "project.domain.save"
	ActionDomainUpdate         = "project.domain.update"
	ActionICPCreate            = "project.icp.create"
	ActionICPUpdate            = "project.icp.update"
	ResourceTypeProject        = "project"
	ResourceTypeSubject        = "project_subject"
	ResourceTypeDomain         = "project_domain_profile"
	ResourceTypeICP            = "icp_filing"
	ResourceTypeWorkspace      = "workspace"
)

// Project workspace service errors.
var (
	ErrWorkspaceUnavailable = errors.New("project: workspace repository unavailable")
	ErrInvalidInput         = errors.New("project: invalid input")
	ErrInvalidStatus        = errors.New("project: invalid status transition")
	ErrNotReady             = errors.New("project: not ready to activate")
	ErrCrossTenantOwner     = errors.New("project: owner is outside tenant or organization")
	ErrInvalidRootDomain    = errors.New("project: invalid registrable root domain")
	ErrInvalidProfile       = errors.New("project: invalid profile")
)

var projectCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type auditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
}

// ServiceOption configures project workspace transactional dependencies.
type ServiceOption func(*Service)

// WithDB enables atomic workspace writes using database transactions.
func WithDB(db *sql.DB) ServiceOption { return func(s *Service) { s.db = db } }

// WithAuditSink supplies the audit recorder used when transactions are unavailable in tests.
func WithAuditSink(sink auditRecorder) ServiceOption { return func(s *Service) { s.auditSink = sink } }

// WithGlobalRoleResolver wires authoritative tenant-scoped global role lookup.
func WithGlobalRoleResolver(resolver GlobalRoleResolver) ServiceOption {
	return func(s *Service) { s.globalRoles = resolver }
}

func (s *Service) runWorkspaceTx(ctx context.Context, fn func(context.Context, Repository, WorkspaceRepository, auditRecorder) error) error {
	if s.workspace == nil {
		return ErrWorkspaceUnavailable
	}
	if s.db == nil {
		return fn(ctx, s.repo, s.workspace, s.auditSink)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txRepo := NewRepository(dbgen.New(tx))
	txAudit := audit.NewService(audit.NewRepository(dbgen.New(tx)))
	if err := fn(ctx, txRepo, txRepo, txAudit); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ListProjects returns projects visible through membership or tenant-global access.
func (s *Service) ListProjects(ctx context.Context, actorID string, global bool, limit, offset int32, meta AuditMeta) (List, error) {
	if s.workspace == nil {
		return List{}, ErrWorkspaceUnavailable
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	scope, err := s.workspace.ActorScope(ctx, actorID)
	if err != nil {
		return List{}, err
	}
	if !global {
		items, total, err := s.workspace.ListForMember(ctx, scope.TenantID, actorID, limit, offset)
		return List{Items: items, Total: total}, err
	}
	items, total, err := s.workspace.ListForTenant(ctx, scope.TenantID, limit, offset)
	if err != nil {
		return List{}, err
	}
	if s.auditSink == nil {
		return List{}, ErrWorkspaceUnavailable
	}
	err = s.auditSink.Record(ctx, audit.Event{
		TenantID: scope.TenantID, OrgID: scope.OrgID, ActorID: actorID,
		ActorType: audit.ActorUser, Action: ActionProjectListRead,
		ResourceType: ResourceTypeWorkspace, ResourceID: scope.TenantID,
		Result: audit.ResultSuccess, IP: meta.IP, UserAgent: meta.UserAgent,
		RequestID: meta.RequestID,
		Metadata:  map[string]any{"scope": "tenant", "tenant_id": scope.TenantID},
	})
	if err != nil {
		return List{}, err
	}
	return List{Items: items, Total: total}, nil
}

// CreateProject creates a draft project, owner membership, and audit record atomically.
func (s *Service) CreateProject(ctx context.Context, in CreateProjectInput) (*Project, error) {
	if err := normalizeCreateProject(&in); err != nil {
		return nil, err
	}
	scope, err := s.workspace.ActorScope(ctx, in.ActorID)
	if err != nil {
		return nil, err
	}
	ownerScope, err := s.workspace.ActorScope(ctx, in.OwnerUserID)
	if err != nil {
		return nil, err
	}
	if ownerScope != scope {
		return nil, ErrCrossTenantOwner
	}

	var projectID uint64
	err = s.runWorkspaceTx(ctx, func(ctx context.Context, repo Repository, ws WorkspaceRepository, sink auditRecorder) error {
		var err error
		projectID, err = ws.CreateProject(ctx, CreateProjectParams{
			ActorScope: scope, ProjectCode: in.ProjectCode, Name: in.Name, Owner: in.OwnerUserID,
			BusinessUnit: in.BusinessUnit, Criticality: in.Criticality,
			Description: in.Description, ActorID: in.ActorID,
		})
		if err != nil {
			return err
		}
		if err := ws.CreateMember(ctx, projectID, in.OwnerUserID, asmcasbin.RoleProjectOwner, in.ActorID); err != nil {
			return err
		}
		created, err := repo.GetByID(ctx, projectID)
		if err != nil {
			return err
		}
		return recordProjectAudit(ctx, sink, created, in.ActorID, ActionProjectCreate, ResourceTypeProject, fmt.Sprint(projectID), nil, created, in.Meta, nil)
	})
	if err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, projectID)
}

// UpdateProject applies an audited partial project update.
func (s *Service) UpdateProject(ctx context.Context, in UpdateProjectInput) (*Project, error) {
	before, err := s.repo.GetByID(ctx, in.ProjectID)
	if err != nil {
		return nil, err
	}
	after := *before
	if in.Name != nil {
		after.Name = strings.TrimSpace(*in.Name)
	}
	if in.OwnerUserID != nil {
		after.Owner = strings.TrimSpace(*in.OwnerUserID)
	}
	if in.BusinessUnit != nil {
		after.BusinessUnit = strings.TrimSpace(*in.BusinessUnit)
	}
	if in.Criticality != nil {
		after.Criticality = strings.TrimSpace(*in.Criticality)
	}
	if in.Description != nil {
		after.Description = strings.TrimSpace(*in.Description)
	}
	if err := validateProjectFields(after.Name, after.Owner, after.BusinessUnit, after.Criticality, after.Description); err != nil {
		return nil, err
	}
	ownerScope, err := s.workspace.ActorScope(ctx, after.Owner)
	if err != nil {
		return nil, err
	}
	if ownerScope.TenantID != before.TenantID || ownerScope.OrgID != before.OrgID {
		return nil, ErrCrossTenantOwner
	}

	err = s.runWorkspaceTx(ctx, func(ctx context.Context, repo Repository, ws WorkspaceRepository, sink auditRecorder) error {
		if err := ws.UpdateProject(ctx, UpdateProjectParams{ID: after.ID, Name: after.Name, Owner: after.Owner,
			BusinessUnit: after.BusinessUnit, Criticality: after.Criticality, Description: after.Description, ActorID: in.ActorID}); err != nil {
			return err
		}
		if err := ws.CreateMember(ctx, after.ID, after.Owner, asmcasbin.RoleProjectOwner, in.ActorID); err != nil {
			return err
		}
		stored, err := repo.GetByID(ctx, after.ID)
		if err != nil {
			return err
		}
		return recordProjectAudit(ctx, sink, stored, in.ActorID, ActionProjectUpdate, ResourceTypeProject, fmt.Sprint(after.ID), before, stored, in.Meta, nil)
	})
	if err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, in.ProjectID)
}

// TransitionProject validates readiness and applies an audited state transition.
func (s *Service) TransitionProject(ctx context.Context, in TransitionProjectInput) (*Project, error) {
	before, err := s.repo.GetByID(ctx, in.ProjectID)
	if err != nil {
		return nil, err
	}
	in.Status = strings.TrimSpace(in.Status)
	in.Reason = strings.TrimSpace(in.Reason)
	if !validTransition(before.Status, in.Status) || len(in.Reason) > 512 {
		return nil, ErrInvalidStatus
	}
	if (in.Status == StatusSuspended || in.Status == StatusArchived) && in.Reason == "" {
		return nil, ErrInvalidInput
	}

	err = s.runWorkspaceTx(ctx, func(ctx context.Context, repo Repository, ws WorkspaceRepository, sink auditRecorder) error {
		if in.Status == StatusActive {
			counts, err := ws.OnboardingCounts(ctx, in.ProjectID)
			if err != nil {
				return err
			}
			if !onboardingStatus(counts).ReadyToActivate {
				return ErrNotReady
			}
		}
		changed, err := ws.TransitionStatus(ctx, in.ProjectID, before.Status, in.Status, in.ActorID)
		if err != nil {
			return err
		}
		if !changed {
			return ErrInvalidStatus
		}
		after, err := repo.GetByID(ctx, in.ProjectID)
		if err != nil {
			return err
		}
		return recordProjectAudit(ctx, sink, after, in.ActorID, ActionProjectTransition, ResourceTypeProject,
			fmt.Sprint(in.ProjectID), before, after, in.Meta, map[string]any{"reason": in.Reason})
	})
	if err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, in.ProjectID)
}

// OnboardingStatus evaluates the activation prerequisites for a project.
func (s *Service) OnboardingStatus(ctx context.Context, projectID uint64) (OnboardingStatus, error) {
	counts, err := s.workspace.OnboardingCounts(ctx, projectID)
	if err != nil {
		return OnboardingStatus{}, err
	}
	return onboardingStatus(counts), nil
}

func onboardingStatus(c OnboardingCounts) OnboardingStatus {
	out := OnboardingStatus{
		OwnerConfigured: c.OwnerCount > 0, PrimarySubjectConfigured: c.PrimarySubjectCount > 0,
		PrimaryDomainConfigured: c.PrimaryDomainCount > 0, ValidScopeConfigured: c.ValidScopeCount > 0,
	}
	if !out.OwnerConfigured {
		out.Missing = append(out.Missing, "project_owner")
	}
	if !out.PrimarySubjectConfigured {
		out.Missing = append(out.Missing, "primary_subject")
	}
	if !out.ValidScopeConfigured {
		out.Missing = append(out.Missing, "valid_scope")
	}
	if !out.PrimaryDomainConfigured && !out.ValidScopeConfigured {
		out.Missing = append(out.Missing, "primary_domain_or_seed_scope")
	}
	out.ReadyToActivate = out.OwnerConfigured && out.PrimarySubjectConfigured && out.ValidScopeConfigured &&
		(out.PrimaryDomainConfigured || out.ValidScopeConfigured)
	return out
}

// CreateSubject creates an audited subject profile.
func (s *Service) CreateSubject(ctx context.Context, in SubjectInput) (*Subject, error) {
	p, err := s.repo.GetByID(ctx, in.ProjectID)
	if err != nil {
		return nil, err
	}
	key, err := normalizeSubject(&in)
	if err != nil {
		return nil, err
	}
	var id uint64
	err = s.runWorkspaceTx(ctx, func(ctx context.Context, _ Repository, ws WorkspaceRepository, sink auditRecorder) error {
		var err error
		id, err = ws.CreateSubject(ctx, ActorScope{TenantID: p.TenantID, OrgID: p.OrgID}, in, key)
		if err != nil {
			return err
		}
		after, err := ws.GetSubject(ctx, in.ProjectID, id)
		if err != nil {
			return err
		}
		return recordProjectAudit(ctx, sink, p, in.ActorID, ActionSubjectCreate, ResourceTypeSubject, fmt.Sprint(id), nil, after, in.Meta, nil)
	})
	if err != nil {
		return nil, err
	}
	return s.workspace.GetSubject(ctx, in.ProjectID, id)
}

// UpdateSubject replaces editable subject profile fields with an audit record.
func (s *Service) UpdateSubject(ctx context.Context, in SubjectInput) (*Subject, error) {
	p, err := s.repo.GetByID(ctx, in.ProjectID)
	if err != nil {
		return nil, err
	}
	before, err := s.workspace.GetSubject(ctx, in.ProjectID, in.SubjectID)
	if err != nil {
		return nil, err
	}
	key, err := normalizeSubject(&in)
	if err != nil {
		return nil, err
	}
	err = s.runWorkspaceTx(ctx, func(ctx context.Context, _ Repository, ws WorkspaceRepository, sink auditRecorder) error {
		if err := ws.UpdateSubject(ctx, in, key); err != nil {
			return err
		}
		after, err := ws.GetSubject(ctx, in.ProjectID, in.SubjectID)
		if err != nil {
			return err
		}
		return recordProjectAudit(ctx, sink, p, in.ActorID, ActionSubjectUpdate, ResourceTypeSubject, fmt.Sprint(in.SubjectID), before, after, in.Meta, nil)
	})
	if err != nil {
		return nil, err
	}
	return s.workspace.GetSubject(ctx, in.ProjectID, in.SubjectID)
}

// ListSubjects returns live subject profiles for a project.
func (s *Service) ListSubjects(ctx context.Context, projectID uint64) ([]*Subject, error) {
	return s.workspace.ListSubjects(ctx, projectID)
}

// CreateDomain materializes a root domain asset and saves its project profile.
func (s *Service) CreateDomain(ctx context.Context, in DomainInput) (*DomainProfile, error) {
	p, err := s.repo.GetByID(ctx, in.ProjectID)
	if err != nil {
		return nil, err
	}
	domain, err := normalizeRootDomain(in.Domain)
	if err != nil {
		return nil, err
	}
	in.Domain = domain
	if err := normalizeDomainInput(&in); err != nil {
		return nil, err
	}
	if in.SubjectID != 0 {
		if _, err := s.workspace.GetSubject(ctx, in.ProjectID, in.SubjectID); err != nil {
			return nil, err
		}
	}
	var assetID uint64
	err = s.runWorkspaceTx(ctx, func(ctx context.Context, _ Repository, ws WorkspaceRepository, sink auditRecorder) error {
		var err error
		assetID, err = ws.UpsertRootDomainAsset(ctx, p, domain, in.ActorID)
		if err != nil {
			return err
		}
		if err := ws.CreateDomainProfile(ctx, ActorScope{TenantID: p.TenantID, OrgID: p.OrgID}, assetID, in); err != nil {
			return err
		}
		after, err := ws.GetDomainProfileByAsset(ctx, in.ProjectID, assetID)
		if err != nil {
			return err
		}
		return recordProjectAudit(ctx, sink, p, in.ActorID, ActionDomainSave, ResourceTypeDomain, fmt.Sprint(after.ID), nil, after, in.Meta, nil)
	})
	if err != nil {
		return nil, err
	}
	return s.workspace.GetDomainProfileByAsset(ctx, in.ProjectID, assetID)
}

// UpdateDomain updates mutable domain profile metadata without changing the asset fact.
func (s *Service) UpdateDomain(ctx context.Context, in DomainInput) (*DomainProfile, error) {
	p, err := s.repo.GetByID(ctx, in.ProjectID)
	if err != nil {
		return nil, err
	}
	before, err := s.workspace.GetDomainProfile(ctx, in.ProjectID, in.DomainProfileID)
	if err != nil {
		return nil, err
	}
	if err := normalizeDomainInput(&in); err != nil {
		return nil, err
	}
	if in.SubjectID != 0 {
		if _, err := s.workspace.GetSubject(ctx, in.ProjectID, in.SubjectID); err != nil {
			return nil, err
		}
	}
	err = s.runWorkspaceTx(ctx, func(ctx context.Context, _ Repository, ws WorkspaceRepository, sink auditRecorder) error {
		if err := ws.UpdateDomainProfile(ctx, in); err != nil {
			return err
		}
		after, err := ws.GetDomainProfile(ctx, in.ProjectID, in.DomainProfileID)
		if err != nil {
			return err
		}
		return recordProjectAudit(ctx, sink, p, in.ActorID, ActionDomainUpdate, ResourceTypeDomain, fmt.Sprint(in.DomainProfileID), before, after, in.Meta, nil)
	})
	if err != nil {
		return nil, err
	}
	return s.workspace.GetDomainProfile(ctx, in.ProjectID, in.DomainProfileID)
}

// ListDomains returns live root domain profiles for a project.
func (s *Service) ListDomains(ctx context.Context, projectID uint64) ([]*DomainProfile, error) {
	return s.workspace.ListDomainProfiles(ctx, projectID)
}

// CreateICP creates an audited filing profile and its domain links atomically.
func (s *Service) CreateICP(ctx context.Context, in ICPInput) (*ICPFilings, error) {
	p, err := s.repo.GetByID(ctx, in.ProjectID)
	if err != nil {
		return nil, err
	}
	if err := s.validateICP(ctx, &in); err != nil {
		return nil, err
	}
	var id uint64
	err = s.runWorkspaceTx(ctx, func(ctx context.Context, _ Repository, ws WorkspaceRepository, sink auditRecorder) error {
		var err error
		id, err = ws.CreateICP(ctx, ActorScope{TenantID: p.TenantID, OrgID: p.OrgID}, in)
		if err != nil {
			return err
		}
		if err := ws.ReplaceICPDomainLinks(ctx, ActorScope{TenantID: p.TenantID, OrgID: p.OrgID}, in.ProjectID, id, in.DomainProfileIDs, in.ActorID); err != nil {
			return err
		}
		after, err := ws.GetICP(ctx, in.ProjectID, id)
		if err != nil {
			return err
		}
		return recordProjectAudit(ctx, sink, p, in.ActorID, ActionICPCreate, ResourceTypeICP, fmt.Sprint(id), nil, after, in.Meta, nil)
	})
	if err != nil {
		return nil, err
	}
	return s.workspace.GetICP(ctx, in.ProjectID, id)
}

// UpdateICP replaces filing fields and domain links atomically with an audit record.
func (s *Service) UpdateICP(ctx context.Context, in ICPInput) (*ICPFilings, error) {
	p, err := s.repo.GetByID(ctx, in.ProjectID)
	if err != nil {
		return nil, err
	}
	before, err := s.workspace.GetICP(ctx, in.ProjectID, in.FilingID)
	if err != nil {
		return nil, err
	}
	if err := s.validateICP(ctx, &in); err != nil {
		return nil, err
	}
	err = s.runWorkspaceTx(ctx, func(ctx context.Context, _ Repository, ws WorkspaceRepository, sink auditRecorder) error {
		if err := ws.UpdateICP(ctx, in); err != nil {
			return err
		}
		if err := ws.ReplaceICPDomainLinks(ctx, ActorScope{TenantID: p.TenantID, OrgID: p.OrgID}, in.ProjectID, in.FilingID, in.DomainProfileIDs, in.ActorID); err != nil {
			return err
		}
		after, err := ws.GetICP(ctx, in.ProjectID, in.FilingID)
		if err != nil {
			return err
		}
		return recordProjectAudit(ctx, sink, p, in.ActorID, ActionICPUpdate, ResourceTypeICP, fmt.Sprint(in.FilingID), before, after, in.Meta, nil)
	})
	if err != nil {
		return nil, err
	}
	return s.workspace.GetICP(ctx, in.ProjectID, in.FilingID)
}

// ListICPs returns live ICP filing profiles for a project.
func (s *Service) ListICPs(ctx context.Context, projectID uint64) ([]*ICPFilings, error) {
	return s.workspace.ListICPs(ctx, projectID)
}

func (s *Service) validateICP(ctx context.Context, in *ICPInput) error {
	in.FilingNo = strings.ToUpper(strings.Join(strings.Fields(in.FilingNo), ""))
	in.FilingType = defaultString(strings.TrimSpace(in.FilingType), "filing")
	in.WebsiteName = strings.TrimSpace(in.WebsiteName)
	in.Status = defaultString(strings.TrimSpace(in.Status), VerificationUnverified)
	in.Source = defaultString(strings.TrimSpace(in.Source), "manual")
	in.EvidenceSummary = strings.TrimSpace(in.EvidenceSummary)
	if in.SubjectID == 0 || len(in.FilingNo) == 0 || len(in.FilingNo) > 128 || len(in.WebsiteName) > 255 ||
		len(in.Source) > 64 || len(in.EvidenceSummary) > 1024 ||
		(in.FilingType != "filing" && in.FilingType != "license") ||
		(in.Status != VerificationUnverified && in.Status != FilingStatusValid && in.Status != FilingStatusInvalid && in.Status != FilingStatusCancelled) {
		return ErrInvalidProfile
	}
	if _, err := s.workspace.GetSubject(ctx, in.ProjectID, in.SubjectID); err != nil {
		return err
	}
	sort.Slice(in.DomainProfileIDs, func(i, j int) bool { return in.DomainProfileIDs[i] < in.DomainProfileIDs[j] })
	unique := in.DomainProfileIDs[:0]
	for _, id := range in.DomainProfileIDs {
		if id == 0 {
			return ErrInvalidProfile
		}
		if len(unique) > 0 && unique[len(unique)-1] == id {
			continue
		}
		if _, err := s.workspace.GetDomainProfile(ctx, in.ProjectID, id); err != nil {
			return err
		}
		unique = append(unique, id)
	}
	in.DomainProfileIDs = unique
	return nil
}

func normalizeCreateProject(in *CreateProjectInput) error {
	in.ProjectCode = strings.ToLower(strings.TrimSpace(in.ProjectCode))
	in.Name = strings.TrimSpace(in.Name)
	in.OwnerUserID = defaultString(strings.TrimSpace(in.OwnerUserID), in.ActorID)
	in.BusinessUnit = strings.TrimSpace(in.BusinessUnit)
	in.Criticality = defaultString(strings.TrimSpace(in.Criticality), CriticalityMedium)
	in.Description = strings.TrimSpace(in.Description)
	if !projectCodePattern.MatchString(in.ProjectCode) {
		return ErrInvalidInput
	}
	return validateProjectFields(in.Name, in.OwnerUserID, in.BusinessUnit, in.Criticality, in.Description)
}

func validateProjectFields(name, owner, businessUnit, criticality, description string) error {
	if name == "" || len(name) > 255 || owner == "" || len(owner) > 64 || len(businessUnit) > 128 || len(description) > 65535 {
		return ErrInvalidInput
	}
	switch criticality {
	case CriticalityLow, CriticalityMedium, CriticalityHigh, CriticalityCritical:
		return nil
	default:
		return ErrInvalidInput
	}
}

func normalizeSubject(in *SubjectInput) (string, error) {
	in.SubjectName = strings.TrimSpace(in.SubjectName)
	in.SubjectType = defaultString(strings.TrimSpace(in.SubjectType), "company")
	in.RegistrationCode = strings.ToUpper(strings.Join(strings.Fields(in.RegistrationCode), ""))
	in.CountryCode = strings.ToUpper(defaultString(strings.TrimSpace(in.CountryCode), "CN"))
	in.Region = strings.TrimSpace(in.Region)
	in.VerificationStatus = defaultString(strings.TrimSpace(in.VerificationStatus), VerificationUnverified)
	in.Source = defaultString(strings.TrimSpace(in.Source), "manual")
	in.EvidenceSummary = strings.TrimSpace(in.EvidenceSummary)
	validType := in.SubjectType == "company" || in.SubjectType == "government" || in.SubjectType == "institution" || in.SubjectType == "individual" || in.SubjectType == "other"
	validVerification := in.VerificationStatus == VerificationUnverified || in.VerificationStatus == VerificationVerified || in.VerificationStatus == VerificationMismatch
	if in.SubjectName == "" || len(in.SubjectName) > 255 || len(in.RegistrationCode) > 64 || len(in.CountryCode) != 2 ||
		len(in.Region) > 128 || len(in.Source) > 64 || len(in.EvidenceSummary) > 1024 || !validType || !validVerification {
		return "", ErrInvalidProfile
	}
	keyPart := strings.ToLower(in.SubjectName)
	if in.RegistrationCode != "" {
		keyPart = in.RegistrationCode
	}
	return in.SubjectType + ":" + keyPart, nil
}

func normalizeRootDomain(raw string) (string, error) {
	raw = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if raw == "" || len(raw) > 253 || strings.ContainsAny(raw, "/:*") {
		return "", ErrInvalidRootDomain
	}
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil {
		return "", ErrInvalidRootDomain
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil || registrable != ascii {
		return "", ErrInvalidRootDomain
	}
	for _, r := range ascii {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", ErrInvalidRootDomain
		}
	}
	return ascii, nil
}

func normalizeDomainInput(in *DomainInput) error {
	in.OwnershipStatus = defaultString(strings.TrimSpace(in.OwnershipStatus), VerificationUnverified)
	in.Source = defaultString(strings.TrimSpace(in.Source), "manual")
	in.EvidenceSummary = strings.TrimSpace(in.EvidenceSummary)
	if (in.OwnershipStatus != VerificationUnverified && in.OwnershipStatus != VerificationVerified && in.OwnershipStatus != VerificationMismatch) ||
		len(in.Source) > 64 || len(in.EvidenceSummary) > 1024 {
		return ErrInvalidProfile
	}
	return nil
}

func validTransition(from, to string) bool {
	switch from {
	case StatusDraft:
		return to == StatusActive || to == StatusArchived
	case StatusActive:
		return to == StatusSuspended || to == StatusArchived
	case StatusSuspended:
		return to == StatusActive || to == StatusArchived
	default:
		return false
	}
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func recordProjectAudit(ctx context.Context, sink auditRecorder, p *Project, actorID, action, resourceType, resourceID string,
	before, after any, meta AuditMeta, metadata map[string]any) error {
	if sink == nil {
		return nil
	}
	return sink.Record(ctx, audit.Event{TenantID: p.TenantID, OrgID: p.OrgID, ProjectID: p.ID,
		ActorID: actorID, ActorType: audit.ActorUser, Action: action, ResourceType: resourceType,
		ResourceID: resourceID, Result: audit.ResultSuccess, IP: meta.IP, UserAgent: meta.UserAgent,
		RequestID: meta.RequestID, Before: before, After: after, Metadata: metadata})
}
