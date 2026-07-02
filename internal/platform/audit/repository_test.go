package audit_test

import (
	"context"
	"database/sql/driver"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// anyArgs17 returns 17 wildcard matchers for the columns in InsertAuditLog.
func anyArgs17() []driver.Value {
	args := make([]driver.Value, 17)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	return args
}

// jsonMatcher is a sqlmock argument matcher that asserts:
//   - the JSON string contains every substring in mustHave
//   - the JSON string contains none of the substrings in mustNotHave
type jsonMatcher struct {
	mustHave    []string
	mustNotHave []string
}

func (j jsonMatcher) Match(v driver.Value) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, sub := range j.mustHave {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	for _, sub := range j.mustNotHave {
		if strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

func newMockRepo(t *testing.T) (sqlmock.Sqlmock, audit.Repository) {
	t.Helper()
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	return mock, audit.NewRepository(dbgen.New(sqlDB))
}

// Acceptance: Insert executes the INSERT statement and returns nil on success.
func TestRepoInsertExecutesSQL(t *testing.T) {
	mock, repo := newMockRepo(t)

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).
		WithArgs(anyArgs17()...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Insert(context.Background(), audit.Event{
		TenantID:  "t1",
		OrgID:     "o1",
		ProjectID: 5,
		ActorID:   "user1",
		ActorType: audit.ActorUser,
		Action:    "project.create",
		Result:    audit.ResultSuccess,
	})

	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: DB errors are propagated, not swallowed.
func TestRepoInsertPropagatesDBError(t *testing.T) {
	mock, repo := newMockRepo(t)
	wantErr := errors.New("connection reset by peer")

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).
		WithArgs(anyArgs17()...).
		WillReturnError(wantErr)

	err := repo.Insert(context.Background(), audit.Event{Action: "login"})
	require.ErrorIs(t, err, wantErr)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: nil Before/After/Metadata do not cause errors (stored as NULL).
func TestRepoInsertNilJsonFields(t *testing.T) {
	mock, repo := newMockRepo(t)

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).
		WithArgs(anyArgs17()...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Insert(context.Background(), audit.Event{
		Action: "login",
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: before_json contains [REDACTED] and does NOT contain plaintext —
// map[string]any with "password".
func TestRepoInsertBeforeJSONRedacted_mapStringAny(t *testing.T) {
	mock, repo := newMockRepo(t)

	// Column order: tenant_id(0) org_id(1) project_id(2) actor_id(3) actor_type(4)
	// action(5) resource_type(6) resource_id(7) result(8) ip(9) user_agent(10)
	// request_id(11) before_json(12) after_json(13) metadata_json(14)
	// error_code(15) error_message(16)
	args := anyArgs17()
	args[12] = jsonMatcher{
		mustHave:    []string{"[REDACTED]"},
		mustNotHave: []string{"hunter2"},
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Insert(context.Background(), audit.Event{
		Action: "user.update",
		Before: map[string]any{"password": "hunter2", "username": "alice"},
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: struct payload — before_json must not leak the plaintext secret.
func TestRepoInsertBeforeJSONRedacted_struct(t *testing.T) {
	mock, repo := newMockRepo(t)

	type userUpdate struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	args := anyArgs17()
	args[12] = jsonMatcher{
		mustHave:    []string{"[REDACTED]"},
		mustNotHave: []string{"s3cr3t"},
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Insert(context.Background(), audit.Event{
		Action: "user.update",
		Before: userUpdate{Password: "s3cr3t", Email: "alice@example.com"},
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: map[string]string payload — before_json must not leak the plaintext token.
func TestRepoInsertBeforeJSONRedacted_mapStringString(t *testing.T) {
	mock, repo := newMockRepo(t)

	args := anyArgs17()
	args[12] = jsonMatcher{
		mustHave:    []string{"[REDACTED]"},
		mustNotHave: []string{"old-tok"},
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Insert(context.Background(), audit.Event{
		Action: "token.rotate",
		Before: map[string]string{"token": "old-tok", "name": "mykey"},
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: access_token in before_json must not appear as plaintext.
func TestRepoInsertBeforeJSONRedacted_accessToken(t *testing.T) {
	mock, repo := newMockRepo(t)

	args := anyArgs17()
	args[12] = jsonMatcher{
		mustHave:    []string{"[REDACTED]"},
		mustNotHave: []string{"acc-tok-plain"},
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Insert(context.Background(), audit.Event{
		Action: "oauth.callback",
		Before: map[string]any{"access_token": "acc-tok-plain", "scope": "read"},
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// Acceptance: assert non-sensitive fields survive redaction unmodified.
func TestRepoInsertBeforeJSONPreservesNonSensitive(t *testing.T) {
	mock, repo := newMockRepo(t)

	args := anyArgs17()
	args[12] = jsonMatcher{
		mustHave:    []string{"alice"},
		mustNotHave: []string{"hunter2"},
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_log")).
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Insert(context.Background(), audit.Event{
		Action: "user.update",
		Before: map[string]any{"password": "hunter2", "username": "alice"},
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}
