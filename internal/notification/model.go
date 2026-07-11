//revive:disable:exported

package notification

import (
	"encoding/json"
	"time"
)

const (
	TriggerNewCriticalExposure = "new_critical_exposure"
	TriggerNewHighRisk         = "new_high_risk"
	TriggerSLADueSoon          = "sla_due_soon"
	TriggerCertExpiring        = "cert_expiring"
)

const (
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"
)

const (
	DeliverySent      = "sent"
	DeliveryThrottled = "throttled"
	DeliveryFailed    = "failed"
)

const (
	ActionNotificationRuleCreate = "notification.rule.create"
	ActionNotificationRuleEnable = "notification.rule.enable"
	ResourceTypeNotificationRule = "notification_rule"
)

type Rule struct {
	ID             uint64
	TenantID       string
	OrgID          string
	ProjectID      uint64
	Name           string
	Trigger        string
	Condition      json.RawMessage
	Channel        string
	Recipients     []string
	ThrottleWindow uint32
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CreatedBy      string
	UpdatedBy      string
}

type Delivery struct {
	ID          uint64
	TenantID    string
	OrgID       string
	ProjectID   uint64
	RuleID      uint64
	Trigger     string
	Channel     string
	ThrottleKey string
	DedupeKey   string
	Status      string
	Subject     string
	Payload     json.RawMessage
	SentAt      time.Time
	CreatedAt   time.Time
}

type CreateRuleInput struct {
	TenantID       string
	OrgID          string
	ProjectID      uint64
	Name           string
	Trigger        string
	Condition      json.RawMessage
	Channel        string
	Recipients     []string
	ThrottleWindow uint32
	Enabled        bool
	ActorID        string
}

type TriggerInput struct {
	TenantID     string
	OrgID        string
	ProjectID    uint64
	Trigger      string
	Severity     string
	EntityType   string
	EntityID     uint64
	BusinessUnit string
	AssetID      uint64
	RiskID       uint64
	TicketID     uint64
	Subject      string
	Summary      string
	DedupeKey    string
	Payload      json.RawMessage
	OccurredAt   time.Time
}

type TriggerResult struct {
	Sent      int
	Throttled int
	Failed    int
}
