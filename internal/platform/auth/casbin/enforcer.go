// Package casbin provides the RBAC enforcer used by the ASM platform.
//
// Design:
//   - Two-dimensional policy: (subject, domain, object, action).
//   - domain = project_id for project-scoped roles; "*" for global roles.
//   - Permission points are the 20 strings defined in design §2.3.
//   - Policies are stored in MySQL via a casbin adapter (wired in M0-3).
//   - A Redis pub/sub watcher invalidates the in-process policy cache across
//     replicas when any policy changes.
//
// Usage (once fully wired in M0-3):
//
//	ok, err := enforcer.Enforce(userID, projectID, "asset:read", "allow")
package casbin

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

// Permission points defined in design §2.3.
// All downstream enforcement must use these constants — never raw strings.
const (
	PermAssetRead     = "asset:read"
	PermAssetWrite    = "asset:write"
	PermAssetDelete   = "asset:delete"
	PermScopeRead     = "scope:read"
	PermScopeWrite    = "scope:write"
	PermDiscoveryRead = "discovery:read"
	PermDiscoveryRun  = "discovery:run"
	PermRiskRead      = "risk:read"
	PermRiskWrite     = "risk:write"
	PermRiskAccept    = "risk:accept"
	PermRiskSuppress  = "risk:suppress"
	PermTicketRead    = "ticket:read"
	PermTicketWrite   = "ticket:write"
	PermTicketApprove = "ticket:approve"
	PermReportRead    = "report:read"
	PermReportExport  = "report:export"
	PermNotifWrite    = "notification:write"
	PermAdminManage   = "admin:manage"
	PermAuditRead     = "audit:read"
	// PermProjectAccess is the project-boundary permission: a role holding it
	// reaches a project even without a project_member row (the explicit/global
	// path in project.Service.Access). Only the cross-project admin roles are
	// seeded with it; project-scoped roles enter via membership instead.
	PermProjectAccess = "project:access"
)

// GlobalDomain is the sentinel project_id used by roles that span all projects.
const GlobalDomain = "*"

// Role names match the six roles from design §2.1 / MVP §3.
const (
	RoleSystemAdmin   = "system_admin"
	RoleSecurityAdmin = "security_admin"
	RoleProjectOwner  = "project_owner"
	RoleSecurityOps   = "security_ops"
	RoleDeveloper     = "developer"
	RoleViewer        = "viewer"
)

// NewEnforcer constructs a casbin enforcer using the embedded model.conf.
// adapter must implement casbin's persist.Adapter interface.
// In M0-3 this will be wired with a MySQL adapter and a Redis watcher.
// For tests, pass a file adapter pointing at a fixture policy CSV.
func NewEnforcer(adapter interface{}) (*casbin.Enforcer, error) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("casbin: load model: %w", err)
	}

	// adapter may be nil during unit tests that test the model definition only.
	if adapter == nil {
		e, err := casbin.NewEnforcer(m)
		if err != nil {
			return nil, fmt.Errorf("casbin: new enforcer (no adapter): %w", err)
		}
		return e, nil
	}

	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("casbin: new enforcer: %w", err)
	}
	return e, nil
}

// modelText is the RBAC model embedded directly to avoid file path dependencies.
// Keep in sync with model.conf in this directory.
const modelText = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (g(r.sub, p.sub, r.dom) || g(r.sub, p.sub, "*")) && (r.dom == p.dom || p.dom == "*") && r.obj == p.obj && r.act == p.act
`
