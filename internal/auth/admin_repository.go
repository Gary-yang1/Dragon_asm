package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Platform-user repository errors normalize missing and duplicate-key outcomes.
var (
	ErrAdminUserNotFound = errors.New("auth: platform user not found")
	ErrUsernameConflict  = errors.New("auth: username already exists")
)

// AdminUserRepository persists tenant-scoped account and role changes.
type AdminUserRepository interface {
	List(ctx context.Context, tenantID string, filter PlatformUserListFilter) (PlatformUserList, error)
	GetByTenantID(ctx context.Context, tenantID string, userID uint64) (*PlatformUser, error)
	Create(ctx context.Context, tenantID, orgID string, in CreatePlatformUserInput, passwordHash string) (uint64, error)
	UpdateProfile(ctx context.Context, tenantID string, in UpdatePlatformUserInput, current PlatformUser) (bool, error)
	TransitionStatus(ctx context.Context, tenantID string, userID uint64, from, to, actorID string) (bool, error)
	ResetPassword(ctx context.Context, tenantID string, userID uint64, passwordHash, actorID string) (bool, error)
	IncrementAuthVersion(ctx context.Context, tenantID string, userID uint64, actorID string) (bool, error)
	UpsertTenantRole(ctx context.Context, tenantID string, userID uint64, role, actorID string) error
	RemoveTenantRole(ctx context.Context, tenantID string, userID uint64, actorID string) error
	CountActiveSystemAdmins(ctx context.Context, tenantID string) (int64, error)
	ListProjects(ctx context.Context, tenantID string, userID uint64) ([]PlatformUserProject, error)
}

type sqlcAdminUserRepository struct {
	q *dbgen.Queries
}

// NewAdminUserRepository creates a sqlc-backed platform-user repository.
func NewAdminUserRepository(q *dbgen.Queries) AdminUserRepository {
	return &sqlcAdminUserRepository{q: q}
}

func (r *sqlcAdminUserRepository) List(ctx context.Context, tenantID string, filter PlatformUserListFilter) (PlatformUserList, error) {
	params := dbgen.ListPlatformUsersParams{
		TenantID: tenantID, Search: filter.Search, StatusFilter: filter.Status,
		RoleFilter: filter.Role, Limit: filter.Limit, Offset: filter.Offset,
	}
	rows, err := r.q.ListPlatformUsers(ctx, params)
	if err != nil {
		return PlatformUserList{}, err
	}
	count, err := r.q.CountPlatformUsers(ctx, dbgen.CountPlatformUsersParams{
		TenantID: tenantID, Search: filter.Search, StatusFilter: filter.Status, RoleFilter: filter.Role,
	})
	if err != nil {
		return PlatformUserList{}, err
	}
	items := make([]*PlatformUser, 0, len(rows))
	for _, row := range rows {
		items = append(items, platformUserFromListRow(row))
	}
	return PlatformUserList{Items: items, Total: count}, nil
}

func (r *sqlcAdminUserRepository) GetByTenantID(ctx context.Context, tenantID string, userID uint64) (*PlatformUser, error) {
	row, err := r.q.GetPlatformUserByTenantID(ctx, dbgen.GetPlatformUserByTenantIDParams{TenantID: tenantID, UserID: userID})
	if err != nil {
		return nil, mapAdminUserError(err)
	}
	return platformUserFromGetRow(row), nil
}

func (r *sqlcAdminUserRepository) Create(ctx context.Context, tenantID, orgID string, in CreatePlatformUserInput, passwordHash string) (uint64, error) {
	result, err := r.q.CreatePlatformUser(ctx, dbgen.CreatePlatformUserParams{
		TenantID: tenantID, OrgID: orgID, Username: in.Username, DisplayName: in.DisplayName,
		Email: nullString(in.Email), Phone: nullString(in.Phone), Department: in.Department,
		PasswordHash: passwordHash, Status: in.Status, CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	})
	if err != nil {
		return 0, mapAdminUserError(err)
	}
	id, err := result.LastInsertId()
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("auth: create platform user id: %w", err)
	}
	return uint64(id), nil
}

func (r *sqlcAdminUserRepository) UpdateProfile(ctx context.Context, tenantID string, in UpdatePlatformUserInput, current PlatformUser) (bool, error) {
	result, err := r.q.UpdatePlatformUserProfile(ctx, dbgen.UpdatePlatformUserProfileParams{
		DisplayName: current.DisplayName, Email: nullString(current.Email), Phone: nullString(current.Phone),
		Department: current.Department, UpdatedBy: in.ActorID, TenantID: tenantID, UserID: in.UserID,
	})
	return changed(result, mapAdminUserError(err))
}

func (r *sqlcAdminUserRepository) TransitionStatus(ctx context.Context, tenantID string, userID uint64, from, to, actorID string) (bool, error) {
	result, err := r.q.TransitionPlatformUserStatus(ctx, dbgen.TransitionPlatformUserStatusParams{
		NextStatus: to, UpdatedBy: actorID, TenantID: tenantID, UserID: userID, PreviousStatus: from,
	})
	return changed(result, mapAdminUserError(err))
}

func (r *sqlcAdminUserRepository) ResetPassword(ctx context.Context, tenantID string, userID uint64, passwordHash, actorID string) (bool, error) {
	result, err := r.q.ResetPlatformUserPassword(ctx, dbgen.ResetPlatformUserPasswordParams{
		PasswordHash: passwordHash, UpdatedBy: actorID, TenantID: tenantID, UserID: userID,
	})
	return changed(result, mapAdminUserError(err))
}

func (r *sqlcAdminUserRepository) IncrementAuthVersion(ctx context.Context, tenantID string, userID uint64, actorID string) (bool, error) {
	result, err := r.q.IncrementPlatformUserAuthVersion(ctx, dbgen.IncrementPlatformUserAuthVersionParams{
		UpdatedBy: actorID, TenantID: tenantID, UserID: userID,
	})
	return changed(result, mapAdminUserError(err))
}

func (r *sqlcAdminUserRepository) UpsertTenantRole(ctx context.Context, tenantID string, userID uint64, role, actorID string) error {
	return mapAdminUserError(r.q.UpsertTenantUserRole(ctx, dbgen.UpsertTenantUserRoleParams{
		TenantID: tenantID, UserID: userID, Role: role, CreatedBy: actorID, UpdatedBy: actorID,
	}))
}

func (r *sqlcAdminUserRepository) RemoveTenantRole(ctx context.Context, tenantID string, userID uint64, actorID string) error {
	return mapAdminUserError(r.q.SoftDeleteTenantUserRole(ctx, dbgen.SoftDeleteTenantUserRoleParams{
		UpdatedBy: actorID, TenantID: tenantID, UserID: userID,
	}))
}

func (r *sqlcAdminUserRepository) CountActiveSystemAdmins(ctx context.Context, tenantID string) (int64, error) {
	ids, err := r.q.ListActiveSystemAdminIDsForUpdate(ctx, tenantID)
	return int64(len(ids)), err
}

func (r *sqlcAdminUserRepository) ListProjects(ctx context.Context, tenantID string, userID uint64) ([]PlatformUserProject, error) {
	rows, err := r.q.ListPlatformUserProjects(ctx, dbgen.ListPlatformUserProjectsParams{TenantID: tenantID, UserID: userID})
	if err != nil {
		return nil, err
	}
	items := make([]PlatformUserProject, 0, len(rows))
	for _, row := range rows {
		items = append(items, PlatformUserProject{
			ID: row.ID, ProjectCode: row.ProjectCode, Name: row.Name, Role: row.Role,
			Status: row.Status, UpdatedAt: row.UpdatedAt,
		})
	}
	return items, nil
}

func platformUserFromListRow(row dbgen.ListPlatformUsersRow) *PlatformUser {
	return &PlatformUser{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, Username: row.Username,
		DisplayName: row.DisplayName, Email: nullableText(row.Email), Phone: nullableText(row.Phone),
		Department: row.Department, Role: databaseText(row.TenantRole), Status: row.Status,
		ProjectCount: row.ProjectCount, LastLoginAt: nullableTime(row.LastLoginAt),
		MustChangePassword: row.MustChangePassword, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

func platformUserFromGetRow(row dbgen.GetPlatformUserByTenantIDRow) *PlatformUser {
	return &PlatformUser{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, Username: row.Username,
		DisplayName: row.DisplayName, Email: nullableText(row.Email), Phone: nullableText(row.Phone),
		Department: row.Department, Role: databaseText(row.TenantRole), Status: row.Status,
		ProjectCount: row.ProjectCount, LastLoginAt: nullableTime(row.LastLoginAt),
		MustChangePassword: row.MustChangePassword, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

func nullString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func nullableText(value sql.NullString) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func nullableTime(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time
	return &t
}

func databaseText(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return ""
	}
}

func changed(result sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func mapAdminUserError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAdminUserNotFound
	}
	var mysqlErr *mysqlDriver.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		return ErrUsernameConflict
	}
	return err
}
