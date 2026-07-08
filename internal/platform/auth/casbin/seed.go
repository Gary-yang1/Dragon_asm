// Package casbin's seed wires the MVP role→permission matrix into an enforcer.
//
// The platform uses project-scoped roles stored on project_member.role (one of
// the six role constants below). A user's role in a project grants that role's
// permission set for that project; project access itself is gated separately by
// the project access boundary (project.Service.Authorize). The matrix is seeded
// as Casbin policies with the global domain ("*"), so a role's capabilities are
// uniform across projects — what varies per project is whether the user holds
// the role there.
//
// This is the MVP default matrix, derived from design §2.1 (role
// responsibilities) and §2.3 (permission points). It is intentionally conservative
// and documented so it can be reviewed and adjusted as policy; it is NOT a
// secret and NOT a credential. Persisting policies to the DB adapter (M0-3) and
// syncing user→role groupings from project_member is tracked separately.
package casbin

import (
	"fmt"

	"github.com/casbin/casbin/v2"
)

// mvpRolePerms is the MVP role→permission matrix. Each role maps to the set of
// permission points it grants, in every project (domain "*").
//
// Rationale (per design §2.1):
//   - system_admin: platform owner — every permission point, including
//     project:access so it can reach any project without a project_member row.
//   - security_admin: cross-project security management — everything except
//     platform-config administration (admin:manage), including project:access.
//   - project_owner: owns a project's assets/risk/tickets — full asset + risk +
//     ticket + scope + report-read within the project; no cross-project export,
//     audit read, or platform admin. Enters via membership, so no project:access.
//   - security_ops: day-to-day operations — asset read/write, discovery, risk
//     confirm, ticket dispatch, report read; no deletion, no accept/suppress,
//     no approval, no export. Enters via membership.
//   - developer: remediation — read-mostly plus ticket write to submit
//     remediation; no asset writes, no risk mutation. Enters via membership.
//   - viewer: read-only across asset/discovery/risk/ticket/report. Enters via
//     membership.
//
// project:access is seeded only for the two cross-project admin roles; the
// project-scoped roles are granted project entry by their project_member row,
// not by the matrix.
var mvpRolePerms = map[string][]string{
	RoleSystemAdmin: {
		PermProjectAccess,
		PermAssetRead, PermAssetWrite, PermAssetDelete,
		PermScopeRead, PermScopeWrite,
		PermDiscoveryRead, PermDiscoveryRun,
		PermRiskRead, PermRiskWrite, PermRiskAccept, PermRiskSuppress,
		PermTicketRead, PermTicketWrite, PermTicketApprove,
		PermReportRead, PermReportExport,
		PermNotifWrite, PermAdminManage, PermAuditRead,
	},
	RoleSecurityAdmin: {
		PermProjectAccess,
		PermAssetRead, PermAssetWrite, PermAssetDelete,
		PermScopeRead, PermScopeWrite,
		PermDiscoveryRead, PermDiscoveryRun,
		PermRiskRead, PermRiskWrite, PermRiskAccept, PermRiskSuppress,
		PermTicketRead, PermTicketWrite, PermTicketApprove,
		PermReportRead, PermReportExport,
		PermNotifWrite, PermAuditRead,
	},
	RoleProjectOwner: {
		PermAssetRead, PermAssetWrite, PermAssetDelete,
		PermScopeRead, PermScopeWrite,
		PermDiscoveryRead, PermDiscoveryRun,
		PermRiskRead, PermRiskWrite, PermRiskAccept,
		PermTicketRead, PermTicketWrite, PermTicketApprove,
		PermReportRead,
	},
	RoleSecurityOps: {
		PermAssetRead, PermAssetWrite,
		PermScopeRead,
		PermDiscoveryRead, PermDiscoveryRun,
		PermRiskRead, PermRiskWrite,
		PermTicketRead, PermTicketWrite,
		PermReportRead,
	},
	RoleDeveloper: {
		PermAssetRead,
		PermDiscoveryRead,
		PermRiskRead,
		PermTicketRead, PermTicketWrite,
		PermReportRead,
	},
	RoleViewer: {
		PermAssetRead,
		PermDiscoveryRead,
		PermRiskRead,
		PermTicketRead,
		PermReportRead,
	},
}

// SeedMVPolicies loads the MVP role→permission matrix into the enforcer as
// (role, GlobalDomain, permission, "allow") policies. It is idempotent: each
// policy is added only if absent, so calling it on an already-seeded enforcer
// (e.g. one backed by a persistent adapter) is a no-op.
//
// Without this seed (or a persistent policy adapter), action-permission checks
// (asset:read / asset:write / …) deny every request, so business routes would
// return 403 even for project members. Wiring this in main makes the MVP RBAC
// usable in production.
func SeedMVPolicies(enforcer *casbin.Enforcer) error {
	if enforcer == nil {
		return fmt.Errorf("casbin: seed: nil enforcer")
	}
	for role, perms := range mvpRolePerms {
		for _, perm := range perms {
			if enforcer.HasPolicy(role, GlobalDomain, perm, "allow") {
				continue
			}
			if _, err := enforcer.AddPolicy(role, GlobalDomain, perm, "allow"); err != nil {
				return fmt.Errorf("casbin: seed: add %s/%s: %w", role, perm, err)
			}
		}
	}
	return nil
}

// RoleHasPerm reports whether role is granted perm by the MVP matrix. It does
// not touch the enforcer; it is a pure lookup used by tests and as a reference
// for the canonical matrix.
func RoleHasPerm(role, perm string) bool {
	perms, ok := mvpRolePerms[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}
