package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
)

// TestWireEnforcerNoPanic verifies that the project's casbin wrapper
// (asmcasbin.NewEnforcer) constructs an enforcer without panicking when passed
// a nil adapter. The upstream github.com/casbin/casbin/v2.NewEnforcer(nil) has
// a nil-type-assertion panic risk; this test ensures our wrapper avoids it.
func TestWireEnforcerNoPanic(t *testing.T) {
	require.NotPanics(t, func() {
		e, err := asmcasbin.NewEnforcer(nil)
		require.NoError(t, err)
		assert.NotNil(t, e)
	}, "asmcasbin.NewEnforcer(nil) must not panic")
}

// TestWireEnforcerPermissionsEmpty verifies that GetImplicitPermissionsForUser
// returns an empty slice (not an error or panic) for a subject with no role
// assignments. This exercises the same path as GET /auth/permissions for a
// freshly wired enforcer with no policies.
func TestWireEnforcerPermissionsEmpty(t *testing.T) {
	e, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)

	perms, err := e.GetImplicitPermissionsForUser("unknown-user")
	require.NoError(t, err, "GetImplicitPermissionsForUser must not error for unknown subject")
	assert.Empty(t, perms, "unknown subject must have zero permissions")
}

// TestWireEnforcerModelLoaded verifies the embedded RBAC model is loaded and
// functional: adding a policy and checking enforcement works end-to-end.
func TestWireEnforcerModelLoaded(t *testing.T) {
	e, err := asmcasbin.NewEnforcer(nil)
	require.NoError(t, err)

	// Add a single policy: role "viewer" in domain "p1" may read assets.
	ok, err := e.AddPolicy(asmcasbin.RoleViewer, "p1", asmcasbin.PermAssetRead, "allow")
	require.NoError(t, err)
	require.True(t, ok, "AddPolicy must succeed")

	// Assign user "alice" the viewer role in p1.
	ok, err = e.AddGroupingPolicy("alice", asmcasbin.RoleViewer, "p1")
	require.NoError(t, err)
	require.True(t, ok, "AddGroupingPolicy must succeed")

	// Enforce: alice should be allowed to read assets in p1.
	allowed, err := e.Enforce("alice", "p1", asmcasbin.PermAssetRead, "allow")
	require.NoError(t, err)
	assert.True(t, allowed, "alice should have asset:read in p1")

	// Enforce: alice must not write (viewer has no write policy).
	denied, err := e.Enforce("alice", "p1", asmcasbin.PermAssetWrite, "allow")
	require.NoError(t, err)
	assert.False(t, denied, "alice must not have asset:write in p1")
}
