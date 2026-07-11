package project

import (
	"context"
	"sort"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
)

// projectCapabilityPermissions is the complete set of user-facing permission
// points that can apply inside a project. project:access is intentionally
// omitted because it is an internal boundary permission, not a UI capability.
var projectCapabilityPermissions = []string{
	asmcasbin.PermAdminManage,
	asmcasbin.PermAssetDelete,
	asmcasbin.PermAssetRead,
	asmcasbin.PermAssetWrite,
	asmcasbin.PermAuditRead,
	asmcasbin.PermDiscoveryRead,
	asmcasbin.PermDiscoveryRun,
	asmcasbin.PermExposureRead,
	asmcasbin.PermNotifWrite,
	asmcasbin.PermProjectArchive,
	asmcasbin.PermProjectCreate,
	asmcasbin.PermProjectMemberWrite,
	asmcasbin.PermProjectRead,
	asmcasbin.PermProjectWrite,
	asmcasbin.PermReportExport,
	asmcasbin.PermReportRead,
	asmcasbin.PermRiskAccept,
	asmcasbin.PermRiskRead,
	asmcasbin.PermRiskSuppress,
	asmcasbin.PermRiskWrite,
	asmcasbin.PermScopeRead,
	asmcasbin.PermScopeWrite,
	asmcasbin.PermTicketApprove,
	asmcasbin.PermTicketRead,
	asmcasbin.PermTicketWrite,
}

// WorkspaceSummary returns tenant-safe aggregates for the authenticated actor.
// A backend-resolved global project:read selects the audited tenant-wide path;
// every other actor is restricted to their own live project memberships.
func (s *Service) WorkspaceSummary(ctx context.Context, actorID string, meta AuditMeta) (WorkspaceSummary, error) {
	if s.workspace == nil {
		return WorkspaceSummary{}, ErrWorkspaceUnavailable
	}
	scope, err := s.workspace.ActorScope(ctx, actorID)
	if err != nil {
		return WorkspaceSummary{}, err
	}
	global, err := s.HasGlobalPermission(ctx, actorID, asmcasbin.PermProjectRead)
	if err != nil {
		return WorkspaceSummary{}, err
	}
	if global {
		summary, err := s.workspace.WorkspaceSummaryForTenant(ctx, scope.TenantID)
		if err != nil {
			return WorkspaceSummary{}, err
		}
		if s.auditSink == nil {
			return WorkspaceSummary{}, ErrWorkspaceUnavailable
		}
		err = s.auditSink.Record(ctx, audit.Event{
			TenantID: scope.TenantID, OrgID: scope.OrgID, ActorID: actorID,
			ActorType: audit.ActorUser, Action: ActionWorkspaceSummaryRead,
			ResourceType: ResourceTypeWorkspace, ResourceID: scope.TenantID,
			Result: audit.ResultSuccess, IP: meta.IP, UserAgent: meta.UserAgent,
			RequestID: meta.RequestID,
			Metadata:  map[string]any{"scope": "tenant", "tenant_id": scope.TenantID},
		})
		if err != nil {
			return WorkspaceSummary{}, err
		}
		return summary, nil
	}
	return s.workspace.WorkspaceSummaryForMember(ctx, scope.TenantID, actorID)
}

// HasGlobalPermission resolves a tenant-scoped global role from backend data,
// with explicit Casbin global policies retained for compatibility.
func (s *Service) HasGlobalPermission(ctx context.Context, actorID, permission string) (bool, error) {
	role, err := s.resolveGlobalRole(ctx, actorID)
	if err != nil {
		return false, err
	}
	if asmcasbin.RoleHasPerm(role, permission) {
		return true, nil
	}
	return s.explicitPermission(actorID, asmcasbin.GlobalDomain, permission), nil
}

// Capabilities returns the actor's effective role and permissions after the
// existing project access boundary has admitted the request.
func (s *Service) Capabilities(ctx context.Context, actorID string, projectID uint64) (Capabilities, error) {
	p, memberRole, err := s.Access(ctx, actorID, projectID)
	if err != nil {
		return Capabilities{}, err
	}
	onboarding, err := s.OnboardingStatus(ctx, projectID)
	if err != nil {
		return Capabilities{}, err
	}

	permissions := make([]string, 0, len(projectCapabilityPermissions))
	for _, permission := range projectCapabilityPermissions {
		if asmcasbin.RoleHasPerm(memberRole, permission) || s.explicitPermission(actorID, projectDomain(projectID), permission) {
			permissions = append(permissions, permission)
		}
	}
	sort.Strings(permissions)

	role := s.effectiveRole(actorID, projectID, memberRole)
	missing := append([]string{}, onboarding.Missing...)
	return Capabilities{
		Role: role, Permissions: permissions,
		CanActivate:       canActivate(p.Status, onboarding.ReadyToActivate) && containsPermission(permissions, asmcasbin.PermProjectWrite),
		OnboardingMissing: missing,
	}, nil
}

func canActivate(status string, ready bool) bool {
	return (status == StatusDraft || status == StatusSuspended) && ready
}

func (s *Service) explicitPermission(actorID, domain, permission string) bool {
	if s.enforcer == nil {
		return false
	}
	ok, err := s.enforcer.Enforce(actorID, domain, permission, "allow")
	return err == nil && ok
}

func (s *Service) effectiveRole(actorID string, projectID uint64, memberRole string) string {
	roles := make([]string, 0, 5)
	if memberRole != "" {
		roles = append(roles, memberRole)
	}
	if s.enforcer != nil {
		projectRoles := s.enforcer.GetRolesForUserInDomain(actorID, projectDomain(projectID))
		globalRoles := s.enforcer.GetRolesForUserInDomain(actorID, asmcasbin.GlobalDomain)
		roles = append(roles, projectRoles...)
		roles = append(roles, globalRoles...)
	}

	best := ""
	bestRank := len(rolePrecedence) + 1
	for _, role := range roles {
		rank, known := rolePrecedence[role]
		if known && rank < bestRank {
			best, bestRank = role, rank
		}
	}
	if best != "" {
		return best
	}
	return memberRole
}

var rolePrecedence = map[string]int{
	asmcasbin.RoleSystemAdmin:   0,
	asmcasbin.RoleSecurityAdmin: 1,
	asmcasbin.RoleProjectOwner:  2,
	asmcasbin.RoleSecurityOps:   3,
	asmcasbin.RoleDeveloper:     4,
	asmcasbin.RoleViewer:        5,
}

func containsPermission(permissions []string, wanted string) bool {
	index := sort.SearchStrings(permissions, wanted)
	return index < len(permissions) && permissions[index] == wanted
}
