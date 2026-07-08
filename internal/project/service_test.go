package project_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/project"
)

// fakeRepo is an in-memory Repository for service-level access tests (no DB).
type fakeRepo struct {
	projects map[uint64]*project.Project
	members  map[string]bool   // key: "<projectID>:<userID>"
	roles    map[string]string // key: "<projectID>:<userID>" -> role
}

func (f *fakeRepo) GetByID(_ context.Context, id uint64) (*project.Project, error) {
	if p, ok := f.projects[id]; ok {
		return p, nil
	}
	return nil, project.ErrNotFound
}

func (f *fakeRepo) GetByCode(_ context.Context, tenantID, code string) (*project.Project, error) {
	for _, p := range f.projects {
		if p.TenantID == tenantID && p.ProjectCode == code {
			return p, nil
		}
	}
	return nil, project.ErrNotFound
}

func (f *fakeRepo) IsMember(_ context.Context, projectID uint64, userID string) (bool, error) {
	return f.members[fmt.Sprintf("%d:%s", projectID, userID)], nil
}

func (f *fakeRepo) MemberRole(_ context.Context, projectID uint64, userID string) (string, error) {
	k := fmt.Sprintf("%d:%s", projectID, userID)
	if role, ok := f.roles[k]; ok {
		return role, nil
	}
	// A member without an explicit role fixture is treated as viewer so the
	// existing membership-only tests keep working under the role-aware path.
	if f.members[k] {
		return "viewer", nil
	}
	return "", project.ErrNotFound
}

// newEnforcer seeds an in-memory Casbin enforcer with one global role
// (system_admin via "*") so global cross-project access can be exercised.
func newEnforcer(t *testing.T) *casbin.Enforcer {
	t.Helper()
	e, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)

	ok, err := e.AddPolicy(asmcasbin.RoleSystemAdmin, asmcasbin.GlobalDomain, project.PermAccess, "allow")
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = e.AddGroupingPolicy("bob", asmcasbin.RoleSystemAdmin, asmcasbin.GlobalDomain)
	require.NoError(t, err)
	require.True(t, ok)
	return e
}

// Acceptance: a project member is granted access to their own project.
func TestAuthorizeAllowsMember(t *testing.T) {
	repo := &fakeRepo{
		projects: map[uint64]*project.Project{1: {ID: 1, Status: project.StatusActive}},
		members:  map[string]bool{"1:alice": true},
	}
	svc := project.NewService(repo, newEnforcer(t))
	require.NoError(t, svc.Authorize(context.Background(), "alice", 1))
}

// Acceptance: a normal user is denied a project they are not a member of
// (project-level isolation).
func TestAuthorizeDeniesNonMember(t *testing.T) {
	repo := &fakeRepo{
		projects: map[uint64]*project.Project{
			1: {ID: 1, Status: project.StatusActive},
			2: {ID: 2, Status: project.StatusActive},
		},
		members: map[string]bool{"1:alice": true}, // alice is only a member of p1
	}
	svc := project.NewService(repo, newEnforcer(t))
	err := svc.Authorize(context.Background(), "alice", 2)
	require.ErrorIs(t, err, project.ErrForbidden)
}

// Acceptance: a global role reaches any project through the explicit Casbin
// path, even with no project_member row.
func TestAuthorizeAllowsGlobalRole(t *testing.T) {
	repo := &fakeRepo{
		projects: map[uint64]*project.Project{2: {ID: 2, Status: project.StatusActive}},
		members:  map[string]bool{}, // bob is not a direct member
	}
	svc := project.NewService(repo, newEnforcer(t))
	require.NoError(t, svc.Authorize(context.Background(), "bob", 2))
}

// A soft-deleted/unknown project is not found (no spurious 403 leak).
func TestAuthorizeUnknownProjectNotFound(t *testing.T) {
	repo := &fakeRepo{projects: map[uint64]*project.Project{}, members: map[string]bool{}}
	svc := project.NewService(repo, newEnforcer(t))
	err := svc.Authorize(context.Background(), "alice", 999)
	require.ErrorIs(t, err, project.ErrNotFound)
}

// Acceptance: suspended/archived projects (and nil) fail RequireActive — the
// reserved "no new work on inactive projects" check.
func TestRequireActive(t *testing.T) {
	svc := project.NewService(&fakeRepo{}, newEnforcer(t))

	require.NoError(t, svc.RequireActive(&project.Project{Status: project.StatusActive}))
	require.ErrorIs(t, svc.RequireActive(&project.Project{Status: project.StatusSuspended}), project.ErrNotActive)
	require.ErrorIs(t, svc.RequireActive(&project.Project{Status: project.StatusArchived}), project.ErrNotActive)
	require.ErrorIs(t, svc.RequireActive(nil), project.ErrNotActive)
}

// Access returns the project plus the member's role in one call.
func TestAccessReturnsProjectAndRole(t *testing.T) {
	repo := &fakeRepo{
		projects: map[uint64]*project.Project{
			1: {ID: 1, TenantID: "t1", OrgID: "o1", Status: project.StatusActive},
		},
		members: map[string]bool{"1:alice": true},
		roles:   map[string]string{"1:alice": "security_ops"},
	}
	svc := project.NewService(repo, newEnforcer(t))

	p, role, err := svc.Access(context.Background(), "alice", 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), p.ID)
	assert.Equal(t, "t1", p.TenantID, "Access returns the project for tenant/org derivation")
	assert.Equal(t, "security_ops", role, "Access returns the membership role")
}

// Access denies a non-member and surfaces the project-not-found case.
func TestAccessDenials(t *testing.T) {
	repo := &fakeRepo{
		projects: map[uint64]*project.Project{
			1: {ID: 1, Status: project.StatusActive},
			2: {ID: 2, Status: project.StatusActive},
		},
		members: map[string]bool{"1:alice": true}, // alice is a member of p1 only
	}
	svc := project.NewService(repo, newEnforcer(t))

	_, _, err := svc.Access(context.Background(), "alice", 2) // alice not a member of p2
	require.ErrorIs(t, err, project.ErrForbidden)

	_, _, err = svc.Access(context.Background(), "alice", 999) // unknown project
	require.ErrorIs(t, err, project.ErrNotFound)
}

func TestGetByIDAndByCode(t *testing.T) {
	repo := &fakeRepo{
		projects: map[uint64]*project.Project{
			1: {ID: 1, TenantID: "t1", ProjectCode: "alpha", Name: "Alpha", Status: project.StatusActive},
		},
	}
	svc := project.NewService(repo, newEnforcer(t))

	p, err := svc.GetByID(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, "Alpha", p.Name)

	p, err = svc.GetByCode(context.Background(), "t1", "alpha")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), p.ID)

	_, err = svc.GetByCode(context.Background(), "t1", "missing")
	require.ErrorIs(t, err, project.ErrNotFound)
}
