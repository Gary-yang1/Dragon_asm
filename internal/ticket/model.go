//revive:disable:exported

package ticket

import "time"

const (
	StatusOpen          = "open"
	StatusAssigned      = "assigned"
	StatusInProgress    = "in_progress"
	StatusPendingRetest = "pending_retest"
	StatusResolved      = "resolved"
	StatusClosed        = "closed"
	StatusRejected      = "rejected"
	StatusExtended      = "extended"
	StatusCancelled     = "cancelled"
)

const (
	PriorityUrgent = "urgent"
	PriorityHigh   = "high"
	PriorityMedium = "medium"
	PriorityLow    = "low"
)

const (
	ActionAssign        = "assign"
	ActionStart         = "start"
	ActionSubmitRetest  = "submit_retest"
	ActionRetestPass    = "retest_pass"
	ActionClose         = "close"
	ActionRetestReject  = "retest_reject"
	ActionAcceptRisk    = "accept_risk"
	ActionFalsePositive = "false_positive"
	ActionExtend        = "extend"
	ActionCancel        = "cancel"
)

const (
	ActionTicketCreate       = "ticket.create"
	ActionTicketStatusChange = "ticket.status_change"
	ResourceTypeTicket       = "ticket"
)

type Ticket struct {
	ID               uint64
	TenantID         string
	OrgID            string
	ProjectID        uint64
	Title            string
	Description      string
	Assignee         string
	BusinessUnit     string
	Status           string
	Priority         string
	DueAt            time.Time
	Resolution       string
	RetestResult     string
	ExternalTicketID string
	ClosedAt         time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	CreatedBy        string
	UpdatedBy        string
}

type TicketRisk struct {
	ID        uint64
	TenantID  string
	OrgID     string
	ProjectID uint64
	TicketID  uint64
	RiskID    uint64
	CreatedAt time.Time
	CreatedBy string
}

type CreateInput struct {
	TenantID         string
	OrgID            string
	ProjectID        uint64
	Title            string
	Description      string
	Assignee         string
	BusinessUnit     string
	Priority         string
	DueAt            time.Time
	ExternalTicketID string
	RiskIDs          []uint64
	ActorID          string
}

type TransitionInput struct {
	ProjectID        uint64
	TicketID         uint64
	Action           string
	ActorID          string
	Assignee         string
	DueAt            time.Time
	Resolution       string
	RetestResult     string
	Reason           string
	ApprovedBy       string
	ExpiresAt        time.Time
	ReviewRequiredAt time.Time
}
