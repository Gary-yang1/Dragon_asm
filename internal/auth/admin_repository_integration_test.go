//go:build integration

package auth_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// TestAdminUserRepositoryListRealMySQL catches collation and driver-parameter
// behavior that sqlmock cannot reproduce. The target database must be isolated
// and migrated through the latest schema before running this test.
func TestAdminUserRepositoryListRealMySQL(t *testing.T) {
	dsn := os.Getenv("ASM_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("ASM_TEST_MYSQL_DSN is not set")
	}
	database, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	defer database.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, database.PingContext(ctx))

	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()

	suffix := time.Now().UnixNano()
	tenantID := fmt.Sprintf("integration-%d", suffix)
	username := fmt.Sprintf("list_user_%d", suffix)
	result, err := tx.ExecContext(ctx, `
		INSERT INTO app_user (
			tenant_id, org_id, username, display_name, email, phone, department,
			password_hash, status, must_change_password, created_by, updated_by
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', FALSE, 'integration', 'integration')`,
		tenantID, "org-integration", username, "Collation Search", "search@example.test",
		"13800000000", "Security", "$2a$10$integrationplaceholderhash00000000000000000000000000000",
	)
	require.NoError(t, err)
	userID, err := result.LastInsertId()
	require.NoError(t, err)

	repo := auth.NewAdminUserRepository(dbgen.New(tx))
	page, err := repo.List(ctx, tenantID, auth.PlatformUserListFilter{
		Search: "Collation", Limit: 20, Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	assert.Equal(t, uint64(userID), page.Items[0].ID)
	assert.Equal(t, int64(1), page.Total)
}
