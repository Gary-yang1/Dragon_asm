package project

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

type workspaceRepoFake struct {
	Repository
	WorkspaceRepository
	projects        map[uint64]*Project
	actorScopes     map[string]ActorScope
	globalRoles     map[uint64]string
	nextProjectID   uint64
	members         map[uint64]map[string]string
	onboarding      OnboardingCounts
	transitionRuns  int
	memberSummary   WorkspaceSummary
	tenantSummary   WorkspaceSummary
	memberTenant    string
	memberActor     string
	tenantQueried   string
	listItems       []*Project
	tenantListItems []*Project
	listTenant      string
	listActor       string
}

func (f *workspaceRepoFake) GetByID(_ context.Context, id uint64) (*Project, error) {
	p, ok := f.projects[id]
	if !ok {
		return nil, ErrNotFound
	}
	copy := *p
	return &copy, nil
}

func (f *workspaceRepoFake) GetByCode(_ context.Context, tenantID, code string) (*Project, error) {
	for _, p := range f.projects {
		if p.TenantID == tenantID && p.ProjectCode == code {
			copy := *p
			return &copy, nil
		}
	}
	return nil, ErrNotFound
}

func (f *workspaceRepoFake) IsMember(_ context.Context, projectID uint64, userID string) (bool, error) {
	_, ok := f.members[projectID][userID]
	return ok, nil
}

func (f *workspaceRepoFake) MemberRole(_ context.Context, projectID uint64, userID string) (string, error) {
	role, ok := f.members[projectID][userID]
	if !ok {
		return "", ErrNotFound
	}
	return role, nil
}

func (f *workspaceRepoFake) ActorScope(_ context.Context, actorID string) (ActorScope, error) {
	scope, ok := f.actorScopes[actorID]
	if !ok {
		return ActorScope{}, ErrInvalidActor
	}
	return scope, nil
}

func (f *workspaceRepoFake) GetGlobalRole(_ context.Context, userID uint64) (string, error) {
	return f.globalRoles[userID], nil
}

func (f *workspaceRepoFake) ListForMember(_ context.Context, tenantID, actorID string, _, _ int32) ([]*Project, int64, error) {
	f.listTenant = tenantID
	f.listActor = actorID
	return f.listItems, int64(len(f.listItems)), nil
}

func (f *workspaceRepoFake) ListForTenant(_ context.Context, tenantID string, _, _ int32) ([]*Project, int64, error) {
	f.tenantQueried = tenantID
	return f.tenantListItems, int64(len(f.tenantListItems)), nil
}

func (f *workspaceRepoFake) WorkspaceSummaryForMember(_ context.Context, tenantID, actorID string) (WorkspaceSummary, error) {
	f.memberTenant = tenantID
	f.memberActor = actorID
	return f.memberSummary, nil
}

func (f *workspaceRepoFake) WorkspaceSummaryForTenant(_ context.Context, tenantID string) (WorkspaceSummary, error) {
	f.tenantQueried = tenantID
	return f.tenantSummary, nil
}

func (f *workspaceRepoFake) CreateProject(_ context.Context, in CreateProjectParams) (uint64, error) {
	f.nextProjectID++
	id := f.nextProjectID
	f.projects[id] = &Project{ID: id, TenantID: in.TenantID, OrgID: in.OrgID, ProjectCode: in.ProjectCode,
		Name: in.Name, Owner: in.Owner, BusinessUnit: in.BusinessUnit, Criticality: in.Criticality,
		Status: StatusDraft, Description: in.Description, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	return id, nil
}

func (f *workspaceRepoFake) CreateMember(_ context.Context, projectID uint64, userID, role, _ string) error {
	if f.members[projectID] == nil {
		f.members[projectID] = make(map[string]string)
	}
	f.members[projectID][userID] = role
	return nil
}

func (f *workspaceRepoFake) TransitionStatus(_ context.Context, projectID uint64, from, to, _ string) (bool, error) {
	p, ok := f.projects[projectID]
	if !ok || p.Status != from {
		return false, nil
	}
	p.Status = to
	f.transitionRuns++
	return true, nil
}

func (f *workspaceRepoFake) OnboardingCounts(context.Context, uint64) (OnboardingCounts, error) {
	return f.onboarding, nil
}

type auditRecorderFake struct {
	events []audit.Event
	err    error
}

func (f *auditRecorderFake) Record(_ context.Context, event audit.Event) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, event)
	return nil
}

func newWorkspaceServiceTest(t *testing.T) (*Service, *workspaceRepoFake, *auditRecorderFake) {
	t.Helper()
	enforcer, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	repo := &workspaceRepoFake{
		projects:      make(map[uint64]*Project),
		actorScopes:   make(map[string]ActorScope),
		globalRoles:   make(map[uint64]string),
		nextProjectID: 40,
		members:       make(map[uint64]map[string]string),
	}
	auditSink := &auditRecorderFake{}
	return NewService(repo, enforcer, WithAuditSink(auditSink), WithGlobalRoleResolver(repo)), repo, auditSink
}

func TestNormalizeRootDomainUsesPublicSuffixRules(t *testing.T) {
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{input: " Example.COM. ", want: "example.com", ok: true},
		{input: "example.com.cn", want: "example.com.cn", ok: true},
		{input: "食狮.com.cn", want: "xn--85x722f.com.cn", ok: true},
		{input: "api.example.com", ok: false},
		{input: "https://example.com", ok: false},
		{input: "localhost", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := normalizeRootDomain(tt.input)
			if !tt.ok {
				require.ErrorIs(t, err, ErrInvalidRootDomain)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProjectTransitionStateMachine(t *testing.T) {
	assert.True(t, validTransition(StatusDraft, StatusActive))
	assert.True(t, validTransition(StatusActive, StatusSuspended))
	assert.True(t, validTransition(StatusSuspended, StatusActive))
	assert.True(t, validTransition(StatusActive, StatusArchived))
	assert.False(t, validTransition(StatusArchived, StatusActive))
	assert.False(t, validTransition(StatusDraft, StatusSuspended))
}

func TestOnboardingStatusRequiresOwnerSubjectAndScope(t *testing.T) {
	incomplete := onboardingStatus(OnboardingCounts{OwnerCount: 1, PrimarySubjectCount: 1, PrimaryDomainCount: 1})
	assert.False(t, incomplete.ReadyToActivate)
	assert.Contains(t, incomplete.Missing, "valid_scope")

	ready := onboardingStatus(OnboardingCounts{OwnerCount: 1, PrimarySubjectCount: 1, ValidScopeCount: 1})
	assert.True(t, ready.ReadyToActivate, "a valid non-domain seed scope may activate a project")
}

func TestWorkspaceSummaryUsesLiveMembershipScopeForOrdinaryActor(t *testing.T) {
	svc, repo, _ := newWorkspaceServiceTest(t)
	repo.actorScopes["7"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.memberSummary = WorkspaceSummary{
		Projects: WorkspaceProjectStats{Total: 1, Active: 1},
		Assets:   WorkspaceAssetStats{Total: 12},
	}

	got, err := svc.WorkspaceSummary(context.Background(), "7", AuditMeta{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), got.Projects.Total)
	assert.Equal(t, int64(12), got.Assets.Total)
	assert.Equal(t, "tenant-a", repo.memberTenant)
	assert.Equal(t, "7", repo.memberActor)
	assert.Empty(t, repo.tenantQueried, "ordinary actors must never use the tenant-wide aggregate")
}

func TestListProjectsUsesActorTenantForMemberScope(t *testing.T) {
	svc, repo, _ := newWorkspaceServiceTest(t)
	repo.actorScopes["7"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.listItems = []*Project{{ID: 1, TenantID: "tenant-a", Name: "Alpha"}}

	got, err := svc.ListProjects(context.Background(), "7", false, 20, 0, AuditMeta{})
	require.NoError(t, err)
	require.Len(t, got.Items, 1)
	assert.Equal(t, "tenant-a", repo.listTenant)
	assert.Equal(t, "7", repo.listActor)
}

func TestListProjectsAuditsTenantWideRead(t *testing.T) {
	svc, repo, auditSink := newWorkspaceServiceTest(t)
	repo.actorScopes["9"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.tenantListItems = []*Project{{ID: 1, TenantID: "tenant-a", Name: "Alpha"}}

	got, err := svc.ListProjects(context.Background(), "9", true, 20, 0, AuditMeta{RequestID: "req-list"})
	require.NoError(t, err)
	require.Len(t, got.Items, 1)
	assert.Equal(t, "tenant-a", repo.tenantQueried)
	require.Len(t, auditSink.events, 1)
	assert.Equal(t, ActionProjectListRead, auditSink.events[0].Action)
	assert.Equal(t, "req-list", auditSink.events[0].RequestID)
}

func TestListProjectsFailsClosedWhenTenantAuditFails(t *testing.T) {
	svc, repo, auditSink := newWorkspaceServiceTest(t)
	repo.actorScopes["9"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.tenantListItems = []*Project{{ID: 1, TenantID: "tenant-a", Name: "Alpha"}}
	auditSink.err = errors.New("audit unavailable")

	got, err := svc.ListProjects(context.Background(), "9", true, 20, 0, AuditMeta{})
	require.ErrorContains(t, err, "audit unavailable")
	assert.Empty(t, got.Items)
}

func TestWorkspaceSummaryGlobalReadStaysWithinActorTenant(t *testing.T) {
	svc, repo, auditSink := newWorkspaceServiceTest(t)
	repo.actorScopes["9"] = ActorScope{TenantID: "tenant-a", OrgID: "org-admin"}
	repo.tenantSummary = WorkspaceSummary{Projects: WorkspaceProjectStats{Total: 3, Active: 2, Draft: 1}}
	repo.globalRoles[9] = asmcasbin.RoleSecurityAdmin

	got, err := svc.WorkspaceSummary(context.Background(), "9", AuditMeta{
		IP: "203.0.113.9", UserAgent: "workspace-test", RequestID: "req-summary",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(3), got.Projects.Total)
	assert.Equal(t, "tenant-a", repo.tenantQueried)
	assert.Empty(t, repo.memberActor, "global project:read must select the tenant-wide repository path")
	require.Len(t, auditSink.events, 1)
	event := auditSink.events[0]
	assert.Equal(t, ActionWorkspaceSummaryRead, event.Action)
	assert.Equal(t, "tenant-a", event.TenantID)
	assert.Equal(t, "9", event.ActorID)
	assert.Equal(t, "req-summary", event.RequestID)
	assert.Equal(t, "203.0.113.9", event.IP)
	assert.Equal(t, "workspace-test", event.UserAgent)
}

func TestCapabilitiesViewerIsReadOnlyAndCannotActivate(t *testing.T) {
	svc, repo, _ := newWorkspaceServiceTest(t)
	repo.projects[1] = &Project{ID: 1, TenantID: "tenant-a", OrgID: "org-a", Status: StatusDraft}
	repo.actorScopes["7"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.members[1] = map[string]string{"7": asmcasbin.RoleViewer}
	repo.onboarding = OnboardingCounts{OwnerCount: 1, PrimarySubjectCount: 1, PrimaryDomainCount: 1, ValidScopeCount: 1}

	got, err := svc.Capabilities(context.Background(), "7", 1)
	require.NoError(t, err)
	assert.Equal(t, asmcasbin.RoleViewer, got.Role)
	assert.Contains(t, got.Permissions, asmcasbin.PermProjectRead)
	assert.Contains(t, got.Permissions, asmcasbin.PermAssetRead)
	assert.NotContains(t, got.Permissions, asmcasbin.PermProjectWrite)
	assert.NotContains(t, got.Permissions, asmcasbin.PermAssetWrite)
	assert.False(t, got.CanActivate)
	assert.Empty(t, got.OnboardingMissing)
}

func TestCapabilitiesOwnerCanActivateReadyDraft(t *testing.T) {
	svc, repo, _ := newWorkspaceServiceTest(t)
	repo.projects[1] = &Project{ID: 1, TenantID: "tenant-a", OrgID: "org-a", Status: StatusDraft}
	repo.actorScopes["7"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.members[1] = map[string]string{"7": asmcasbin.RoleProjectOwner}
	repo.onboarding = OnboardingCounts{OwnerCount: 1, PrimarySubjectCount: 1, PrimaryDomainCount: 1, ValidScopeCount: 1}

	got, err := svc.Capabilities(context.Background(), "7", 1)
	require.NoError(t, err)
	assert.Equal(t, asmcasbin.RoleProjectOwner, got.Role)
	assert.Contains(t, got.Permissions, asmcasbin.PermProjectWrite)
	assert.True(t, got.CanActivate)
}

func TestCapabilitiesOwnerCanReactivateReadySuspendedProject(t *testing.T) {
	svc, repo, _ := newWorkspaceServiceTest(t)
	repo.projects[1] = &Project{ID: 1, TenantID: "tenant-a", OrgID: "org-a", Status: StatusSuspended}
	repo.actorScopes["7"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.members[1] = map[string]string{"7": asmcasbin.RoleProjectOwner}
	repo.onboarding = OnboardingCounts{OwnerCount: 1, PrimarySubjectCount: 1, PrimaryDomainCount: 1, ValidScopeCount: 1}

	got, err := svc.Capabilities(context.Background(), "7", 1)
	require.NoError(t, err)
	assert.True(t, got.CanActivate)
}

func TestCapabilitiesCannotReactivateSuspendedProjectWithExpiredScope(t *testing.T) {
	svc, repo, _ := newWorkspaceServiceTest(t)
	repo.projects[1] = &Project{ID: 1, TenantID: "tenant-a", OrgID: "org-a", Status: StatusSuspended}
	repo.actorScopes["7"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.members[1] = map[string]string{"7": asmcasbin.RoleProjectOwner}
	repo.onboarding = OnboardingCounts{OwnerCount: 1, PrimarySubjectCount: 1, PrimaryDomainCount: 1}

	got, err := svc.Capabilities(context.Background(), "7", 1)
	require.NoError(t, err)
	assert.False(t, got.CanActivate)
	assert.Contains(t, got.OnboardingMissing, "valid_scope")
}

func TestSuspendedTransitionUsesSameReadinessGateAsCapabilities(t *testing.T) {
	svc, repo, _ := newWorkspaceServiceTest(t)
	repo.projects[1] = &Project{ID: 1, TenantID: "tenant-a", OrgID: "org-a", Status: StatusSuspended}
	repo.actorScopes["7"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.members[1] = map[string]string{"7": asmcasbin.RoleProjectOwner}
	repo.onboarding = OnboardingCounts{OwnerCount: 1, PrimarySubjectCount: 1, PrimaryDomainCount: 1}

	capabilities, err := svc.Capabilities(context.Background(), "7", 1)
	require.NoError(t, err)
	assert.False(t, capabilities.CanActivate)
	_, err = svc.TransitionProject(context.Background(), TransitionProjectInput{ProjectID: 1, Status: StatusActive, ActorID: "7"})
	require.ErrorIs(t, err, ErrNotReady)

	repo.onboarding.ValidScopeCount = 1
	capabilities, err = svc.Capabilities(context.Background(), "7", 1)
	require.NoError(t, err)
	assert.True(t, capabilities.CanActivate)
	updated, err := svc.TransitionProject(context.Background(), TransitionProjectInput{ProjectID: 1, Status: StatusActive, ActorID: "7"})
	require.NoError(t, err)
	assert.Equal(t, StatusActive, updated.Status)
}

func TestWorkspaceSummaryFailsClosedWhenTenantAuditFails(t *testing.T) {
	svc, repo, auditSink := newWorkspaceServiceTest(t)
	repo.actorScopes["9"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.globalRoles[9] = asmcasbin.RoleSystemAdmin
	auditSink.err = errors.New("audit unavailable")

	_, err := svc.WorkspaceSummary(context.Background(), "9", AuditMeta{})
	require.ErrorContains(t, err, "audit unavailable")
}

func TestCapabilitiesPreservesProjectAccessErrors(t *testing.T) {
	svc, repo, _ := newWorkspaceServiceTest(t)
	repo.projects[1] = &Project{ID: 1, TenantID: "tenant-a", OrgID: "org-a", Status: StatusActive}

	_, err := svc.Capabilities(context.Background(), "7", 1)
	require.ErrorIs(t, err, ErrForbidden)
	_, err = svc.Capabilities(context.Background(), "7", 999)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestWorkspaceTransactionRollsBackOnAuditFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewRepository(dbgen.New(db))
	enforcer, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)
	svc := NewService(repo, enforcer, WithDB(db))
	auditErr := errors.New("audit unavailable")

	mock.ExpectBegin()
	mock.ExpectRollback()
	err = svc.runWorkspaceTx(context.Background(), func(context.Context, Repository, WorkspaceRepository, auditRecorder) error {
		return auditErr
	})
	require.ErrorIs(t, err, auditErr)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateProjectInitializesDraftOwnerAndAudit(t *testing.T) {
	svc, repo, auditSink := newWorkspaceServiceTest(t)
	scope := ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.actorScopes["7"] = scope
	repo.actorScopes["8"] = scope

	created, err := svc.CreateProject(context.Background(), CreateProjectInput{
		ProjectCode: " APP-ONE ", Name: " Application One ", OwnerUserID: "8",
		BusinessUnit: " Platform ", ActorID: "7", Meta: AuditMeta{RequestID: "req-1"},
	})
	require.NoError(t, err)
	assert.Equal(t, StatusDraft, created.Status)
	assert.Equal(t, "app-one", created.ProjectCode)
	assert.Equal(t, "Application One", created.Name)
	assert.Equal(t, asmcasbin.RoleProjectOwner, repo.members[created.ID]["8"])
	require.Len(t, auditSink.events, 1)
	assert.Equal(t, ActionProjectCreate, auditSink.events[0].Action)
	assert.Equal(t, "req-1", auditSink.events[0].RequestID)
}

func TestCreateProjectRejectsOwnerOutsideActorScope(t *testing.T) {
	svc, repo, auditSink := newWorkspaceServiceTest(t)
	repo.actorScopes["7"] = ActorScope{TenantID: "tenant-a", OrgID: "org-a"}
	repo.actorScopes["8"] = ActorScope{TenantID: "tenant-b", OrgID: "org-b"}

	_, err := svc.CreateProject(context.Background(), CreateProjectInput{
		ProjectCode: "app-one", Name: "Application One", OwnerUserID: "8", ActorID: "7",
	})
	require.ErrorIs(t, err, ErrCrossTenantOwner)
	assert.Empty(t, repo.projects)
	assert.Empty(t, auditSink.events)
}

func TestTransitionProjectEnforcesReadinessAndAuditsSuccess(t *testing.T) {
	svc, repo, auditSink := newWorkspaceServiceTest(t)
	repo.projects[1] = &Project{ID: 1, TenantID: "tenant-a", OrgID: "org-a", Status: StatusDraft}

	_, err := svc.TransitionProject(context.Background(), TransitionProjectInput{ProjectID: 1, Status: StatusActive, ActorID: "7"})
	require.ErrorIs(t, err, ErrNotReady)
	assert.Zero(t, repo.transitionRuns)

	repo.onboarding = OnboardingCounts{OwnerCount: 1, PrimarySubjectCount: 1, PrimaryDomainCount: 1, ValidScopeCount: 1}
	updated, err := svc.TransitionProject(context.Background(), TransitionProjectInput{ProjectID: 1, Status: StatusActive, ActorID: "7"})
	require.NoError(t, err)
	assert.Equal(t, StatusActive, updated.Status)
	assert.Equal(t, 1, repo.transitionRuns)
	require.Len(t, auditSink.events, 1)
	assert.Equal(t, ActionProjectTransition, auditSink.events[0].Action)
}
