package auth_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

const defaultMembershipQuery = `(?s)FROM project_member pm.*CAST\(u\.id AS CHAR\) COLLATE utf8mb4_unicode_ci.*pm\.deleted_at = '1970-01-01 00:00:00\.000'.*u\.status = 'active'.*u\.deleted_at = '1970-01-01 00:00:00\.000'.*p\.tenant_id = u\.tenant_id.*p\.deleted_at = '1970-01-01 00:00:00\.000'`

const globalRoleFromTenantTableQuery = `(?s)FROM app_user u.*INNER JOIN tenant_user_role tur.*tur\.deleted_at = '1970-01-01 00:00:00\.000'.*tur\.role IN.*tur\.tenant_id = u\.tenant_id`
const globalRoleLegacyQuery = `(?s)FROM app_user u.*CAST\(u\.id AS CHAR\) COLLATE utf8mb4_unicode_ci.*pm\.role IN.*pm\.deleted_at = '1970-01-01 00:00:00\.000'.*p\.tenant_id = u\.tenant_id.*p\.deleted_at = '1970-01-01 00:00:00\.000'`

func TestUserRepositoryDefaultMembershipIsTenantScoped(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer database.Close()

	mock.ExpectQuery(defaultMembershipQuery).
		WithArgs("7").
		WillReturnRows(sqlmock.NewRows([]string{"project_id", "role"}).AddRow(uint64(11), asmcasbin.RoleProjectOwner))

	repo := auth.NewUserRepository(dbgen.New(database))
	membership, err := repo.GetDefaultProjectMembership(context.Background(), "7")
	require.NoError(t, err)
	assert.Equal(t, uint64(11), membership.ProjectID)
	assert.Equal(t, asmcasbin.RoleProjectOwner, membership.Role)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepositoryGlobalRoleIsTenantScopedAndOptional(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer database.Close()

	mock.ExpectQuery(globalRoleFromTenantTableQuery).
		WithArgs(uint64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow(asmcasbin.RoleSecurityAdmin))
	mock.ExpectQuery(globalRoleFromTenantTableQuery).
		WithArgs(uint64(8)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(globalRoleLegacyQuery).
		WithArgs(uint64(8)).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow(asmcasbin.RoleSystemAdmin))

	repo := auth.NewUserRepository(dbgen.New(database))
	role, err := repo.GetGlobalRole(context.Background(), 7)
	require.NoError(t, err)
	assert.Equal(t, asmcasbin.RoleSecurityAdmin, role)
	role, err = repo.GetGlobalRole(context.Background(), 8)
	require.NoError(t, err)
	assert.Equal(t, asmcasbin.RoleSystemAdmin, role)
	require.NoError(t, mock.ExpectationsWereMet())
}
