package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// ErrUserNotFound is returned when no live (non-soft-deleted) user matches.
var ErrUserNotFound = errors.New("auth: user not found")

// UserRepository is the storage interface the auth service depends on. Tests
// inject a fake; production wires the sqlc-backed implementation.
//
// All implementations MUST exclude soft-deleted rows by default.
type UserRepository interface {
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByID(ctx context.Context, id uint64) (*User, error)
	GetDefaultProjectMembership(ctx context.Context, userID string) (*ProjectMembership, error)
	// GetGlobalRole resolves only tenant-scoped system/security administrator
	// assignments. No assignment returns "".
	GetGlobalRole(ctx context.Context, userID uint64) (string, error)
}

type currentPasswordRepository interface {
	ChangeCurrentPassword(ctx context.Context, tenantID string, userID uint64, passwordHash, actorID string) (bool, error)
}

// sqlcUserRepository implements UserRepository over dbgen queries. The
// underlying sqlc SQL filters on the soft-delete sentinel, so soft-deleted rows
// are excluded by default here.
type sqlcUserRepository struct {
	q *dbgen.Queries
}

// NewUserRepository wraps a dbgen.Queries (which holds any dbgen.DBTX, e.g. a
// *sql.DB or a sqlmock-backed DB in tests).
func NewUserRepository(q *dbgen.Queries) UserRepository {
	return &sqlcUserRepository{q: q}
}

func (r *sqlcUserRepository) GetByUsername(ctx context.Context, username string) (*User, error) {
	u, err := r.q.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, mapUserErr(err)
	}
	return toDomainUser(u), nil
}

func (r *sqlcUserRepository) GetByID(ctx context.Context, id uint64) (*User, error) {
	u, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		return nil, mapUserErr(err)
	}
	return toDomainUser(u), nil
}

func (r *sqlcUserRepository) RecordSuccessfulLogin(ctx context.Context, id uint64) error {
	return r.q.UpdateUserLastLoginAt(ctx, id)
}

func (r *sqlcUserRepository) GetDefaultProjectMembership(ctx context.Context, userID string) (*ProjectMembership, error) {
	m, err := r.q.GetDefaultProjectMembershipByUserID(ctx, userID)
	if err != nil {
		return nil, mapUserErr(err)
	}
	return &ProjectMembership{ProjectID: m.ProjectID, Role: m.Role}, nil
}

func (r *sqlcUserRepository) GetGlobalRole(ctx context.Context, userID uint64) (string, error) {
	role, err := r.q.GetGlobalRoleByUserIDFromTenantRole(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		role, err = r.q.GetGlobalRoleByUserID(ctx, userID)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return role, err
}

func (r *sqlcUserRepository) ChangeCurrentPassword(
	ctx context.Context,
	tenantID string,
	userID uint64,
	passwordHash, actorID string,
) (bool, error) {
	result, err := r.q.ChangeCurrentUserPassword(ctx, dbgen.ChangeCurrentUserPasswordParams{
		PasswordHash: passwordHash,
		UpdatedBy:    actorID,
		TenantID:     tenantID,
		UserID:       userID,
	})
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

// mapUserErr converts database/sql's no-rows sentinel into the domain
// ErrUserNotFound.
func mapUserErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	}
	return err
}

func toDomainUser(u dbgen.AppUser) *User {
	var lastLoginAt *time.Time
	if u.LastLoginAt.Valid {
		lt := u.LastLoginAt.Time
		lastLoginAt = &lt
	}

	return &User{
		ID:                 u.ID,
		TenantID:           u.TenantID,
		OrgID:              u.OrgID,
		Username:           u.Username,
		DisplayName:        u.DisplayName,
		Email:              nullableText(u.Email),
		Phone:              nullableText(u.Phone),
		Department:         u.Department,
		LastLoginAt:        lastLoginAt,
		MustChangePassword: u.MustChangePassword,
		AuthVersion:        u.AuthVersion,
		PasswordHash:       u.PasswordHash,
		Status:             u.Status,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
	}
}
