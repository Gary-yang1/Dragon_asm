package casbin_test

import (
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
)

// newTestEnforcer returns a fresh in-memory enforcer seeded with a policy that
// exercises both project-scoped roles (domain = project id) and global roles
// (domain = GlobalDomain / "*"). No adapter is attached, so all policy state
// lives in memory for the duration of the test.
func newTestEnforcer(t *testing.T) *casbin.Enforcer {
	t.Helper()
	e, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)

	// Permission policies: p(role, domain, permission, "allow").
	policies := [][]string{
		// project_owner and viewer are scoped to project "p1" only.
		{asmcasbin.RoleProjectOwner, "p1", asmcasbin.PermAssetRead, "allow"},
		{asmcasbin.RoleProjectOwner, "p1", asmcasbin.PermAssetWrite, "allow"},
		{asmcasbin.RoleViewer, "p1", asmcasbin.PermAssetRead, "allow"},
		// system_admin is global: domain "*" lets it cross every project.
		{asmcasbin.RoleSystemAdmin, asmcasbin.GlobalDomain, asmcasbin.PermAssetRead, "allow"},
		{asmcasbin.RoleSystemAdmin, asmcasbin.GlobalDomain, asmcasbin.PermAssetWrite, "allow"},
		{asmcasbin.RoleSystemAdmin, asmcasbin.GlobalDomain, asmcasbin.PermAssetDelete, "allow"},
	}
	for _, p := range policies {
		ok, err := e.AddPolicy(p[0], p[1], p[2], p[3])
		require.NoError(t, err)
		require.True(t, ok, "AddPolicy failed for %v", p)
	}

	// Role assignments: g(user, role, domain).
	assignments := [][]string{
		{"alice", asmcasbin.RoleProjectOwner, "p1"},                // alice owns project p1 only
		{"bob", asmcasbin.RoleSystemAdmin, asmcasbin.GlobalDomain}, // bob is a global admin
	}
	for _, g := range assignments {
		ok, err := e.AddGroupingPolicy(g[0], g[1], g[2])
		require.NoError(t, err)
		require.True(t, ok, "AddGroupingPolicy failed for %v", g)
	}

	return e
}

// TestProjectIsolation verifies that a role granted in one project grants no
// access in another. alice is project_owner in p1 and must not reach into p2.
func TestProjectIsolation(t *testing.T) {
	e := newTestEnforcer(t)

	ok, err := e.Enforce("alice", "p1", asmcasbin.PermAssetRead, "allow")
	require.NoError(t, err)
	assert.True(t, ok, "alice should read assets in her own project p1")

	ok, err = e.Enforce("alice", "p2", asmcasbin.PermAssetRead, "allow")
	require.NoError(t, err)
	assert.False(t, ok, "alice must not reach across into project p2")
}

// TestGlobalRoleCrossesProjects verifies that a role bound to the global domain
// "*" is honored in every project. bob is system_admin globally and must read
// assets in p1, p2, and any other project id.
func TestGlobalRoleCrossesProjects(t *testing.T) {
	e := newTestEnforcer(t)

	for _, project := range []string{"p1", "p2", "other-project"} {
		ok, err := e.Enforce("bob", project, asmcasbin.PermAssetRead, "allow")
		require.NoError(t, err)
		assert.True(t, ok, "global system_admin should read assets in project %q", project)
	}
}

// TestUngrantedPermissionDenied verifies the implicit-deny default: a subject
// may only do what an assigned role's policies explicitly allow.
func TestUngrantedPermissionDenied(t *testing.T) {
	e := newTestEnforcer(t)

	// project_owner in p1 has read/write but no delete policy.
	ok, err := e.Enforce("alice", "p1", asmcasbin.PermAssetDelete, "allow")
	require.NoError(t, err)
	assert.False(t, ok, "permission not granted to the role must be denied")

	// A permission point absent from the policy set entirely.
	ok, err = e.Enforce("alice", "p1", asmcasbin.PermRiskAccept, "allow")
	require.NoError(t, err)
	assert.False(t, ok, "permission absent from policy must be denied")
}

// TestUnknownSubjectDenied verifies that a subject with no role assignment is
// denied.
func TestUnknownSubjectDenied(t *testing.T) {
	e := newTestEnforcer(t)

	ok, err := e.Enforce("carol", "p1", asmcasbin.PermAssetRead, "allow")
	require.NoError(t, err)
	assert.False(t, ok, "a subject without any role assignment must be denied")
}

// TestRolePolicyMatching exercises the matcher directly: a project-scoped role
// grants exactly its allowed permissions, the action dimension is enforced
// (anything other than "allow" is denied), and a newly added role assignment
// takes effect for subsequent requests.
func TestRolePolicyMatching(t *testing.T) {
	e := newTestEnforcer(t)

	// dave starts with no access at all.
	ok, err := e.Enforce("dave", "p1", asmcasbin.PermAssetRead, "allow")
	require.NoError(t, err)
	assert.False(t, ok, "dave has no role yet")

	// Grant viewer in p1: read allowed, write denied (viewer has no write policy).
	ok, err = e.AddGroupingPolicy("dave", asmcasbin.RoleViewer, "p1")
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = e.Enforce("dave", "p1", asmcasbin.PermAssetRead, "allow")
	require.NoError(t, err)
	assert.True(t, ok, "viewer should read in p1")

	ok, err = e.Enforce("dave", "p1", asmcasbin.PermAssetWrite, "allow")
	require.NoError(t, err)
	assert.False(t, ok, "viewer should not write in p1")

	// The action is part of the match: a non-"allow" action never matches.
	ok, err = e.Enforce("dave", "p1", asmcasbin.PermAssetRead, "deny")
	require.NoError(t, err)
	assert.False(t, ok, "only the allow action is permitted")
}
