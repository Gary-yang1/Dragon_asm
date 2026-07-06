package auth

import (
	"context"
	"database/sql"
	"errors"

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

// mapUserErr converts database/sql's no-rows sentinel into the domain
// ErrUserNotFound.
func mapUserErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	}
	return err
}

func toDomainUser(u dbgen.AppUser) *User {
	return &User{
		ID:           u.ID,
		TenantID:     u.TenantID,
		OrgID:        u.OrgID,
		Username:     u.Username,
		DisplayName:  u.DisplayName,
		PasswordHash: u.PasswordHash,
		Status:       u.Status,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}
}
