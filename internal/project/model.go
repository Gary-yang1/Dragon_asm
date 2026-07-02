// Package project implements the project domain model and the project-level
// data-isolation boundary used by every downstream business module.
//
// Project-scoped access is enforced by Service.Authorize: a user reaches a
// project only via explicit project membership (project_member) or an explicit
// Casbin permission (global roles). There is no default-allow path.
package project

import "time"

// Project status values.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusArchived  = "archived"
)

// Project is the domain representation of a project. It uses Go-native types
// (no DB driver types) so the service layer and its tests stay storage-agnostic.
type Project struct {
	ID           uint64
	TenantID     string
	OrgID        string
	ProjectCode  string
	Name         string
	Owner        string
	BusinessUnit string
	Criticality  string
	Status       string
	Description  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	CreatedBy    string
	UpdatedBy    string
}

// IsActive reports whether the project can accept new work (e.g. discovery
// tasks). Suspended and archived projects are not active.
func (p *Project) IsActive() bool { return p.Status == StatusActive }
