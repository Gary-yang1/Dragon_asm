package auth_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
)

type adminUserRepoFake struct {
	users        map[uint64]*auth.PlatformUser
	passwordHash map[uint64]string
	authVersion  map[uint64]uint32
	nextID       uint64
}

func newAdminUserRepoFake(users ...*auth.PlatformUser) *adminUserRepoFake {
	repo := &adminUserRepoFake{
		users: make(map[uint64]*auth.PlatformUser), passwordHash: make(map[uint64]string),
		authVersion: make(map[uint64]uint32), nextID: 100,
	}
	for _, user := range users {
		copy := *user
		repo.users[user.ID] = &copy
		repo.authVersion[user.ID] = 1
		if user.ID >= repo.nextID {
			repo.nextID = user.ID + 1
		}
	}
	return repo
}

func (r *adminUserRepoFake) List(_ context.Context, tenantID string, filter auth.PlatformUserListFilter) (auth.PlatformUserList, error) {
	items := make([]*auth.PlatformUser, 0)
	for _, user := range r.users {
		if user.TenantID != tenantID || (filter.Status != "" && user.Status != filter.Status) {
			continue
		}
		if filter.Role == "none" && user.Role != "" || filter.Role != "" && filter.Role != "none" && user.Role != filter.Role {
			continue
		}
		if filter.Search != "" && !strings.Contains(user.Username, filter.Search) {
			continue
		}
		items = append(items, clonePlatformUser(user))
	}
	return auth.PlatformUserList{Items: items, Total: int64(len(items))}, nil
}

func (r *adminUserRepoFake) GetByTenantID(_ context.Context, tenantID string, userID uint64) (*auth.PlatformUser, error) {
	user, ok := r.users[userID]
	if !ok || user.TenantID != tenantID {
		return nil, auth.ErrAdminUserNotFound
	}
	return clonePlatformUser(user), nil
}

func (r *adminUserRepoFake) Create(_ context.Context, tenantID, orgID string, in auth.CreatePlatformUserInput, passwordHash string) (uint64, error) {
	for _, user := range r.users {
		if user.Username == in.Username {
			return 0, auth.ErrUsernameConflict
		}
	}
	id := r.nextID
	r.nextID++
	now := time.Now().UTC()
	r.users[id] = &auth.PlatformUser{
		ID: id, TenantID: tenantID, OrgID: orgID, Username: in.Username, DisplayName: in.DisplayName,
		Email: in.Email, Phone: in.Phone, Department: in.Department, Status: in.Status,
		MustChangePassword: true, CreatedAt: now, UpdatedAt: now,
	}
	r.passwordHash[id] = passwordHash
	r.authVersion[id] = 1
	return id, nil
}

func (r *adminUserRepoFake) UpdateProfile(_ context.Context, tenantID string, in auth.UpdatePlatformUserInput, current auth.PlatformUser) (bool, error) {
	if _, err := r.GetByTenantID(context.Background(), tenantID, in.UserID); err != nil {
		return false, err
	}
	copy := current
	copy.UpdatedAt = time.Now().UTC()
	r.users[in.UserID] = &copy
	return true, nil
}

func (r *adminUserRepoFake) TransitionStatus(_ context.Context, tenantID string, userID uint64, from, to, _ string) (bool, error) {
	user, err := r.GetByTenantID(context.Background(), tenantID, userID)
	if err != nil || user.Status != from {
		return false, err
	}
	user.Status = to
	user.UpdatedAt = time.Now().UTC()
	r.users[userID] = user
	r.authVersion[userID]++
	return true, nil
}

func (r *adminUserRepoFake) ResetPassword(_ context.Context, tenantID string, userID uint64, passwordHash, _ string) (bool, error) {
	user, err := r.GetByTenantID(context.Background(), tenantID, userID)
	if err != nil {
		return false, err
	}
	user.MustChangePassword = true
	r.users[userID] = user
	r.passwordHash[userID] = passwordHash
	r.authVersion[userID]++
	return true, nil
}

func (r *adminUserRepoFake) IncrementAuthVersion(_ context.Context, tenantID string, userID uint64, _ string) (bool, error) {
	if _, err := r.GetByTenantID(context.Background(), tenantID, userID); err != nil {
		return false, err
	}
	r.authVersion[userID]++
	return true, nil
}

func (r *adminUserRepoFake) UpsertTenantRole(_ context.Context, tenantID string, userID uint64, role, _ string) error {
	user, err := r.GetByTenantID(context.Background(), tenantID, userID)
	if err != nil {
		return err
	}
	user.Role = role
	r.users[userID] = user
	return nil
}

func (r *adminUserRepoFake) RemoveTenantRole(_ context.Context, tenantID string, userID uint64, _ string) error {
	return r.UpsertTenantRole(context.Background(), tenantID, userID, "", "")
}

func (r *adminUserRepoFake) CountActiveSystemAdmins(_ context.Context, tenantID string) (int64, error) {
	var count int64
	for _, user := range r.users {
		if user.TenantID == tenantID && user.Status == auth.UserStatusActive && user.Role == auth.PlatformRoleSystemAdmin {
			count++
		}
	}
	return count, nil
}

func (r *adminUserRepoFake) ListProjects(_ context.Context, tenantID string, userID uint64) ([]auth.PlatformUserProject, error) {
	if _, err := r.GetByTenantID(context.Background(), tenantID, userID); err != nil {
		return nil, err
	}
	return []auth.PlatformUserProject{{ID: 7, ProjectCode: "p7", Name: "Project 7", Role: asmcasbin.RoleViewer, Status: "active"}}, nil
}

type adminActorRepoFake struct {
	users map[uint64]*auth.User
	roles map[uint64]string
}

func (r *adminActorRepoFake) GetByUsername(_ context.Context, username string) (*auth.User, error) {
	for _, user := range r.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, auth.ErrUserNotFound
}

func (r *adminActorRepoFake) GetByID(_ context.Context, id uint64) (*auth.User, error) {
	user, ok := r.users[id]
	if !ok {
		return nil, auth.ErrUserNotFound
	}
	return user, nil
}

func (r *adminActorRepoFake) GetDefaultProjectMembership(context.Context, string) (*auth.ProjectMembership, error) {
	return nil, auth.ErrUserNotFound
}

func (r *adminActorRepoFake) GetGlobalRole(_ context.Context, id uint64) (string, error) {
	return r.roles[id], nil
}

type adminAuditFake struct {
	events []audit.Event
}

func (a *adminAuditFake) Record(_ context.Context, event audit.Event) error {
	a.events = append(a.events, event)
	return nil
}

func activePlatformUser(id uint64, tenantID, role string) *auth.PlatformUser {
	now := time.Now().UTC()
	return &auth.PlatformUser{
		ID: id, TenantID: tenantID, OrgID: "org-1", Username: fmt.Sprintf("user%d", id),
		DisplayName: fmt.Sprintf("User %d", id), Role: role, Status: auth.UserStatusActive,
		CreatedAt: now, UpdatedAt: now,
	}
}

func newAdminService(repo *adminUserRepoFake, actorID uint64, actorRole string) (*auth.AdminUserService, *adminAuditFake) {
	audits := &adminAuditFake{}
	actors := &adminActorRepoFake{
		users: map[uint64]*auth.User{
			actorID: {ID: actorID, TenantID: "tenant-1", OrgID: "org-1", Username: "actor", Status: auth.UserStatusActive},
		},
		roles: map[uint64]string{actorID: actorRole},
	}
	return auth.NewAdminUserService(repo, actors, auth.WithAdminUserAuditSink(audits)), audits
}

func TestAdminUserServiceRejectsSecurityAdmin(t *testing.T) {
	repo := newAdminUserRepoFake(activePlatformUser(2, "tenant-1", ""))
	service, _ := newAdminService(repo, 1, asmcasbin.RoleSecurityAdmin)

	_, err := service.List(context.Background(), "1", auth.PlatformUserListFilter{})
	require.ErrorIs(t, err, auth.ErrAdminForbidden)
}

func TestAdminUserServiceCrossTenantUserLooksMissing(t *testing.T) {
	repo := newAdminUserRepoFake(activePlatformUser(2, "tenant-2", ""))
	service, _ := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)

	_, err := service.Get(context.Background(), "1", 2)
	require.ErrorIs(t, err, auth.ErrAdminUserNotFound)
}

func TestAdminUserServiceCreateNormalizesUsernameAndAudits(t *testing.T) {
	repo := newAdminUserRepoFake()
	service, audits := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)

	created, err := service.Create(context.Background(), auth.CreatePlatformUserInput{
		Username: " Alice.Admin ", DisplayName: " Alice ", Email: "ALICE@example.com",
		Role: auth.PlatformRoleSecurityAdmin, Password: "Temporary-123", ActorID: "1",
	})
	require.NoError(t, err)
	assert.Equal(t, "alice.admin", created.Username)
	assert.Equal(t, "alice@example.com", created.Email)
	assert.Equal(t, auth.PlatformRoleSecurityAdmin, created.Role)
	assert.True(t, created.MustChangePassword)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(repo.passwordHash[created.ID]), []byte("Temporary-123")))
	require.Len(t, audits.events, 1)
	assert.Equal(t, auth.ActionPlatformUserCreate, audits.events[0].Action)
	assert.NotContains(t, fmt.Sprint(audits.events[0].After), "Temporary-123")
}

func TestAdminUserServiceCreateRejectsUsernameConflict(t *testing.T) {
	existing := activePlatformUser(2, "tenant-1", "")
	existing.Username = "alice"
	repo := newAdminUserRepoFake(existing)
	service, _ := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)

	_, err := service.Create(context.Background(), auth.CreatePlatformUserInput{
		Username: "ALICE", DisplayName: "Alice", Password: "Temporary-123", ActorID: "1",
	})
	require.ErrorIs(t, err, auth.ErrUsernameConflict)
}

func TestAdminUserServiceCannotDisableSelf(t *testing.T) {
	repo := newAdminUserRepoFake(activePlatformUser(1, "tenant-1", auth.PlatformRoleSystemAdmin))
	service, audits := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)

	_, err := service.Transition(context.Background(), auth.TransitionPlatformUserInput{
		UserID: 1, Status: auth.UserStatusDisabled, Reason: "leaving", ActorID: "1",
	})
	require.ErrorIs(t, err, auth.ErrAdminSelfDisable)
	assert.Empty(t, audits.events)
}

func TestAdminUserServiceCannotDowngradeLastSystemAdmin(t *testing.T) {
	repo := newAdminUserRepoFake(activePlatformUser(1, "tenant-1", auth.PlatformRoleSystemAdmin))
	service, _ := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)

	_, err := service.UpdateTenantRole(context.Background(), auth.UpdateTenantRoleInput{
		UserID: 1, Role: auth.PlatformRoleSecurityAdmin, ActorID: "1",
	})
	require.ErrorIs(t, err, auth.ErrLastSystemAdmin)
	assert.Equal(t, auth.PlatformRoleSystemAdmin, repo.users[1].Role)
	assert.Equal(t, uint32(1), repo.authVersion[1])
}

func TestAdminUserServiceDisableRevokesSessionsAndAuditsReason(t *testing.T) {
	repo := newAdminUserRepoFake(
		activePlatformUser(1, "tenant-1", auth.PlatformRoleSystemAdmin),
		activePlatformUser(2, "tenant-1", auth.PlatformRoleSystemAdmin),
	)
	service, audits := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)

	updated, err := service.Transition(context.Background(), auth.TransitionPlatformUserInput{
		UserID: 2, Status: auth.UserStatusDisabled, Reason: "employee left", ActorID: "1",
	})
	require.NoError(t, err)
	assert.Equal(t, auth.UserStatusDisabled, updated.Status)
	assert.Equal(t, uint32(2), repo.authVersion[2])
	require.Len(t, audits.events, 1)
	assert.Equal(t, "employee left", audits.events[0].Metadata.(map[string]any)["reason"])
}

func TestAdminUserServiceAuditUsesTargetOrganization(t *testing.T) {
	target := activePlatformUser(2, "tenant-1", auth.PlatformRoleSystemAdmin)
	target.OrgID = "org-target"
	repo := newAdminUserRepoFake(activePlatformUser(1, "tenant-1", auth.PlatformRoleSystemAdmin), target)
	service, audits := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)

	_, err := service.Transition(context.Background(), auth.TransitionPlatformUserInput{
		UserID: 2, Status: auth.UserStatusDisabled, Reason: "organization transfer", ActorID: "1",
	})
	require.NoError(t, err)
	require.Len(t, audits.events, 1)
	assert.Equal(t, "org-target", audits.events[0].OrgID)
	assert.Equal(t, "org-1", audits.events[0].Metadata.(map[string]any)["actor_org_id"])
}

func TestAdminUserServicePasswordResetHashesAndRevokesWithoutAuditSecret(t *testing.T) {
	repo := newAdminUserRepoFake(activePlatformUser(2, "tenant-1", ""))
	service, audits := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)

	err := service.ResetPassword(context.Background(), auth.ResetPlatformUserPasswordInput{
		UserID: 2, TemporaryPassword: "Replacement-123", ActorID: "1",
	})
	require.NoError(t, err)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(repo.passwordHash[2]), []byte("Replacement-123")))
	assert.Equal(t, uint32(2), repo.authVersion[2])
	require.Len(t, audits.events, 1)
	assert.NotContains(t, fmt.Sprint(audits.events[0]), "Replacement-123")
	assert.False(t, strings.Contains(repo.passwordHash[2], "Replacement-123"))
}

func TestAdminUserServiceRoleChangeRevokesExistingSessions(t *testing.T) {
	repo := newAdminUserRepoFake(
		activePlatformUser(1, "tenant-1", auth.PlatformRoleSystemAdmin),
		activePlatformUser(2, "tenant-1", ""),
	)
	service, audits := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)

	updated, err := service.UpdateTenantRole(context.Background(), auth.UpdateTenantRoleInput{
		UserID: 2, Role: auth.PlatformRoleSecurityAdmin, ActorID: "1",
	})
	require.NoError(t, err)
	assert.Equal(t, auth.PlatformRoleSecurityAdmin, updated.Role)
	assert.Equal(t, uint32(2), repo.authVersion[2])
	require.Len(t, audits.events, 1)
	assert.Equal(t, auth.ActionPlatformUserRoleUpdate, audits.events[0].Action)
}

func TestAdminUserServiceRejectsShortTemporaryPassword(t *testing.T) {
	repo := newAdminUserRepoFake(activePlatformUser(2, "tenant-1", ""))
	service, _ := newAdminService(repo, 1, asmcasbin.RoleSystemAdmin)

	err := service.ResetPassword(context.Background(), auth.ResetPlatformUserPasswordInput{
		UserID: 2, TemporaryPassword: "short", ActorID: "1",
	})
	require.True(t, errors.Is(err, auth.ErrAdminInvalidInput))
}

func clonePlatformUser(user *auth.PlatformUser) *auth.PlatformUser {
	copy := *user
	return &copy
}
