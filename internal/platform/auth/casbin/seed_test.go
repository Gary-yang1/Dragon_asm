package casbin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SeedMVPolicies loads the full role→permission matrix and is idempotent.
func TestSeedMVPoliciesLoadsMatrix(t *testing.T) {
	e, err := NewEnforcer(nil)
	require.NoError(t, err)

	require.NoError(t, SeedMVPolicies(e))

	// Spot-check the asset permissions that the asset handler enforces.
	cases := []struct {
		role string
		perm string
		want bool
	}{
		{RoleSystemAdmin, PermAssetRead, true},
		{RoleSystemAdmin, PermAssetWrite, true},
		{RoleSystemAdmin, PermAdminManage, true},
		{RoleSystemAdmin, PermProjectCreate, true},
		{RoleSystemAdmin, PermProjectArchive, true},
		{RoleSystemAdmin, PermUserRead, true},
		{RoleSystemAdmin, PermUserCredentialReset, true},
		{RoleSecurityAdmin, PermAdminManage, false},
		{RoleSecurityAdmin, PermUserRead, false},
		{RoleSecurityAdmin, PermUserWrite, false},
		{RoleSecurityAdmin, PermAssetWrite, true},
		{RoleSecurityAdmin, PermProjectAccess, true},
		{RoleSecurityAdmin, PermProjectCreate, true},
		{RoleSecurityAdmin, PermProjectArchive, true},
		{RoleProjectOwner, PermProjectAccess, false},
		{RoleProjectOwner, PermProjectRead, true},
		{RoleProjectOwner, PermProjectWrite, true},
		{RoleProjectOwner, PermProjectMemberWrite, true},
		{RoleProjectOwner, PermProjectCreate, false},
		{RoleProjectOwner, PermProjectArchive, false},
		{RoleProjectOwner, PermAssetDelete, true},
		{RoleSecurityOps, PermAssetRead, true},
		{RoleSecurityOps, PermExposureRead, true},
		{RoleSecurityOps, PermAssetWrite, true},
		{RoleSecurityOps, PermAssetDelete, false},
		{RoleDeveloper, PermAssetRead, true},
		{RoleDeveloper, PermAssetWrite, false},
		{RoleViewer, PermAssetRead, true},
		{RoleViewer, PermProjectRead, true},
		{RoleViewer, PermProjectWrite, false},
		{RoleViewer, PermProjectMemberWrite, false},
		{RoleViewer, PermExposureRead, true},
		{RoleViewer, PermAssetWrite, false},
		{RoleViewer, PermReportExport, false},
	}
	for _, tc := range cases {
		got := e.HasPolicy(tc.role, GlobalDomain, tc.perm, "allow")
		assert.Equal(t, tc.want, got, "role=%s perm=%s", tc.role, tc.perm)
	}
}

// Seeding twice is a no-op (idempotent), so no duplicate policies accrue.
func TestSeedMVPoliciesIdempotent(t *testing.T) {
	e, err := NewEnforcer(nil)
	require.NoError(t, err)

	require.NoError(t, SeedMVPolicies(e))
	before := len(e.GetPolicy())
	require.NoError(t, SeedMVPolicies(e))
	after := len(e.GetPolicy())
	assert.Equal(t, before, after, "second seed must not add duplicates")
}

// RoleHasPerm mirrors the matrix for a pure (non-enforcer) reference lookup.
func TestRoleHasPerm(t *testing.T) {
	assert.True(t, RoleHasPerm(RoleViewer, PermAssetRead))
	assert.True(t, RoleHasPerm(RoleViewer, PermExposureRead))
	assert.False(t, RoleHasPerm(RoleViewer, PermAssetWrite))
	assert.False(t, RoleHasPerm("bogus-role", PermAssetRead))
}

// SeedMVPolicies returns an error for a nil enforcer rather than panicking.
func TestSeedMVPoliciesNilEnforcer(t *testing.T) {
	err := SeedMVPolicies(nil)
	require.Error(t, err)
}
