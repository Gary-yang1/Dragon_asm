package project

import (
	"context"
	"errors"
	"fmt"

	"github.com/casbin/casbin/v2"

	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
)

// PermAccess is the permission point the project access boundary enforces.
// Project-scoped users satisfy it via project membership; global roles satisfy
// it via an explicit Casbin policy seeded in the MVP matrix (PermProjectAccess).
// It is an alias for the canonical casbin constant so the two never drift.
const PermAccess = asmcasbin.PermProjectAccess

// Sentinel service errors.
var (
	// ErrForbidden means the user has neither project membership nor an
	// explicit Casbin permission for the project.
	ErrForbidden = errors.New("project: access denied")
	// ErrNotActive means the project is suspended or archived and cannot accept
	// new work.
	ErrNotActive = errors.New("project: not active")
)

// Service applies project business rules and the project access boundary.
type Service struct {
	repo     Repository
	enforcer *casbin.Enforcer
}

// NewService builds a Service over the given repository and Casbin enforcer.
func NewService(repo Repository, enforcer *casbin.Enforcer) *Service {
	return &Service{repo: repo, enforcer: enforcer}
}

// GetByID returns the live project, or ErrNotFound (including for soft-deleted
// rows, which the repository excludes by default).
func (s *Service) GetByID(ctx context.Context, id uint64) (*Project, error) {
	return s.repo.GetByID(ctx, id)
}

// GetByCode returns the live project by tenant + code, or ErrNotFound.
func (s *Service) GetByCode(ctx context.Context, tenantID, code string) (*Project, error) {
	return s.repo.GetByCode(ctx, tenantID, code)
}

// RequireActive gates operations that may only run against active projects
// (e.g. creating a new discovery task). Suspended/archived/nil projects yield
// ErrNotActive. This is the reserved "no new work on inactive projects" check.
func (s *Service) RequireActive(p *Project) error {
	if p == nil || !p.IsActive() {
		return ErrNotActive
	}
	return nil
}

// Authorize enforces the project access boundary for (userID, projectID):
//
//  1. The project must exist (ErrNotFound otherwise — soft-deleted projects are
//     treated as not found).
//  2. An EXPLICIT Casbin permission grants access (this is the only path global
//     roles can take — there is no default allow).
//  3. Otherwise the user must be an explicit project member.
//
// Denial yields ErrForbidden.
func (s *Service) Authorize(ctx context.Context, userID string, projectID uint64) error {
	_, _, err := s.Access(ctx, userID, projectID)
	return err
}

// Access resolves the project access boundary for (userID, projectID) and, in
// one call, returns the live project and the user's membership role ("" when
// access was granted via an explicit Casbin permission rather than membership).
// It mirrors Authorize's three steps:
//
//  1. The project must exist (ErrNotFound).
//  2. An explicit Casbin permission grants access; the role is unknown on this
//     path (returns "").
//  3. Otherwise the user must be a member; the role is the project_member role.
//
// Denial yields ErrForbidden. Callers use the returned role to enforce
// action-level RBAC against the seeded role→permission matrix.
func (s *Service) Access(ctx context.Context, userID string, projectID uint64) (*Project, string, error) {
	p, err := s.repo.GetByID(ctx, projectID)
	if err != nil {
		return nil, "", err
	}

	// Step 2: explicit permission judgment (covers global roles via domain "*").
	if ok, err := s.enforcer.Enforce(userID, projectDomain(projectID), PermAccess, "allow"); err == nil && ok {
		return p, "", nil
	}

	// Step 3: project-scoped membership — resolve the role for the caller.
	role, err := s.repo.MemberRole(ctx, projectID, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, "", ErrForbidden
		}
		return nil, "", err
	}
	return p, role, nil
}

// projectDomain renders the numeric project id as the Casbin domain string.
// Casbin domains are opaque strings; global roles use "*".
func projectDomain(id uint64) string { return fmt.Sprintf("%d", id) }
