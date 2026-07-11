//revive:disable:exported

package notification

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var (
	ErrInvalidProjectID = errors.New("notification: invalid project id")
	ErrInvalidActorID   = errors.New("notification: invalid actor id")
	ErrInvalidTrigger   = errors.New("notification: invalid trigger")
	ErrInvalidChannel   = errors.New("notification: invalid channel")
	ErrInvalidName      = errors.New("notification: invalid name")
	ErrInvalidRecipient = errors.New("notification: invalid recipient")
	ErrFieldTooLong     = errors.New("notification: field too long")
	ErrThrottled        = errors.New("notification: throttled")
)

type Sender interface {
	Send(ctx context.Context, msg Message) error
}

type auditRecorder interface {
	Record(ctx context.Context, e audit.Event) error
}

type Message struct {
	RuleID     uint64
	ProjectID  uint64
	Trigger    string
	Channel    string
	Recipients []string
	Subject    string
	Payload    json.RawMessage
}

type Service struct {
	repo      Repository
	db        *sql.DB
	sender    Sender
	auditSink auditRecorder
	now       func() time.Time
}

type ServiceOption func(*Service)

func WithDB(db *sql.DB) ServiceOption {
	return func(s *Service) { s.db = db }
}

func WithSender(sender Sender) ServiceOption {
	return func(s *Service) { s.sender = sender }
}

func WithAuditSink(sink auditRecorder) ServiceOption {
	return func(s *Service) { s.auditSink = sink }
}

func WithNow(fn func() time.Time) ServiceOption {
	return func(s *Service) {
		if fn != nil {
			s.now = fn
		}
	}
}

func NewService(repo Repository, opts ...ServiceOption) *Service {
	s := &Service{repo: repo, now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Service) CreateRule(ctx context.Context, in CreateRuleInput) (*Rule, error) {
	if err := validateCreateRule(in); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Trigger = strings.TrimSpace(in.Trigger)
	in.Channel = strings.TrimSpace(in.Channel)
	in.Enabled = true
	var id uint64
	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository, sink auditRecorder) error {
		var err error
		id, err = repo.CreateRule(ctx, CreateRuleParams(in))
		if err != nil {
			return err
		}
		rule, err := repo.GetRuleByID(ctx, in.ProjectID, id)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sink, audit.Event{
			TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
			ActorID: in.ActorID, ActorType: audit.ActorUser, Action: ActionNotificationRuleCreate,
			ResourceType: ResourceTypeNotificationRule, ResourceID: strconv.FormatUint(id, 10),
			After: rule, Metadata: map[string]any{"trigger": in.Trigger, "channel": in.Channel},
		})
	}); err != nil {
		return nil, err
	}
	return s.repo.GetRuleByID(ctx, in.ProjectID, id)
}

func (s *Service) ListRules(ctx context.Context, projectID uint64) ([]*Rule, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.ListRules(ctx, projectID)
}

func (s *Service) SetRuleEnabled(ctx context.Context, projectID, id uint64, enabled bool, actorID string) error {
	if projectID == 0 {
		return ErrInvalidProjectID
	}
	if actorID == "" || len(actorID) > 64 {
		return ErrInvalidActorID
	}
	return s.runInTx(ctx, func(ctx context.Context, repo Repository, sink auditRecorder) error {
		before, err := repo.GetRuleByID(ctx, projectID, id)
		if err != nil {
			return err
		}
		if err := repo.SetRuleEnabled(ctx, projectID, id, enabled, actorID); err != nil {
			return err
		}
		after, err := repo.GetRuleByID(ctx, projectID, id)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sink, audit.Event{
			TenantID: before.TenantID, OrgID: before.OrgID, ProjectID: projectID,
			ActorID: actorID, ActorType: audit.ActorUser, Action: ActionNotificationRuleEnable,
			ResourceType: ResourceTypeNotificationRule, ResourceID: strconv.FormatUint(id, 10),
			Before: before, After: after, Metadata: map[string]any{"enabled": enabled},
		})
	})
}

func (s *Service) Trigger(ctx context.Context, in TriggerInput) (TriggerResult, error) {
	if in.ProjectID == 0 {
		return TriggerResult{}, ErrInvalidProjectID
	}
	if !validTrigger(in.Trigger) {
		return TriggerResult{}, ErrInvalidTrigger
	}
	if in.OccurredAt.IsZero() {
		in.OccurredAt = s.now()
	}
	if in.DedupeKey == "" {
		in.DedupeKey = defaultDedupeKey(in)
	}
	rules, err := s.repo.ListEnabledRulesByTrigger(ctx, in.ProjectID, in.Trigger)
	if err != nil {
		return TriggerResult{}, err
	}
	var result TriggerResult
	for _, rule := range rules {
		if !ruleMatches(rule, in) {
			continue
		}
		msg := Message{
			RuleID: rule.ID, ProjectID: in.ProjectID, Trigger: in.Trigger, Channel: rule.Channel,
			Recipients: rule.Recipients, Subject: defaultString(in.Subject, rule.Name), Payload: in.Payload,
		}
		delivery := DeliveryParams{
			TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
			RuleID: rule.ID, Trigger: in.Trigger, Channel: rule.Channel,
			ThrottleKey: throttleKey(rule, in), DedupeKey: in.DedupeKey,
			Status: DeliverySent, Subject: msg.Subject, Payload: in.Payload, SentAt: in.OccurredAt,
		}
		if err := s.repo.InsertDelivery(ctx, delivery); err != nil {
			if errors.Is(err, ErrThrottled) {
				result.Throttled++
				continue
			}
			return result, err
		}
		if s.sender != nil {
			if err := s.sender.Send(ctx, msg); err != nil {
				result.Failed++
				continue
			}
		}
		result.Sent++
	}
	return result, nil
}

func validateCreateRule(in CreateRuleInput) error {
	if in.ProjectID == 0 {
		return ErrInvalidProjectID
	}
	if in.ActorID == "" || len(in.ActorID) > 64 {
		return ErrInvalidActorID
	}
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 255 {
		return ErrInvalidName
	}
	if !validTrigger(strings.TrimSpace(in.Trigger)) {
		return ErrInvalidTrigger
	}
	if !validChannel(strings.TrimSpace(in.Channel)) {
		return ErrInvalidChannel
	}
	if len(in.TenantID) > 64 || len(in.OrgID) > 64 || len(in.Condition) > 4096 {
		return ErrFieldTooLong
	}
	if len(in.Recipients) == 0 {
		return ErrInvalidRecipient
	}
	for _, recipient := range in.Recipients {
		if strings.TrimSpace(recipient) == "" || len(recipient) > 255 {
			return ErrInvalidRecipient
		}
	}
	return nil
}

func validTrigger(v string) bool {
	switch v {
	case TriggerNewCriticalExposure, TriggerNewHighRisk, TriggerSLADueSoon, TriggerCertExpiring:
		return true
	default:
		return false
	}
}

func validChannel(v string) bool {
	switch v {
	case ChannelEmail, ChannelWebhook:
		return true
	default:
		return false
	}
}

type condition struct {
	Severity     string `json:"severity"`
	EntityType   string `json:"entity_type"`
	BusinessUnit string `json:"business_unit"`
	Channel      string `json:"channel"`
}

func ruleMatches(rule *Rule, in TriggerInput) bool {
	if len(rule.Condition) == 0 {
		return true
	}
	var cond condition
	if err := json.Unmarshal(rule.Condition, &cond); err != nil {
		return false
	}
	if cond.Severity != "" && cond.Severity != in.Severity {
		return false
	}
	if cond.EntityType != "" && cond.EntityType != in.EntityType {
		return false
	}
	if cond.BusinessUnit != "" && cond.BusinessUnit != in.BusinessUnit {
		return false
	}
	return true
}

func throttleKey(rule *Rule, in TriggerInput) string {
	if rule.ThrottleWindow == 0 {
		return fmt.Sprintf("%s:%s:%d", in.Trigger, in.DedupeKey, in.OccurredAt.UnixNano())
	}
	window := int64(rule.ThrottleWindow)
	bucket := in.OccurredAt.Unix() / window
	return fmt.Sprintf("%s:%s:%d", in.Trigger, in.DedupeKey, bucket)
}

func defaultDedupeKey(in TriggerInput) string {
	switch {
	case in.RiskID != 0:
		return fmt.Sprintf("risk:%d", in.RiskID)
	case in.TicketID != 0:
		return fmt.Sprintf("ticket:%d", in.TicketID)
	case in.AssetID != 0:
		return fmt.Sprintf("asset:%d", in.AssetID)
	case in.EntityType != "" && in.EntityID != 0:
		return fmt.Sprintf("%s:%d", in.EntityType, in.EntityID)
	default:
		return in.Trigger
	}
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func (s *Service) runInTx(ctx context.Context, fn func(context.Context, Repository, auditRecorder) error) error {
	if s.db == nil {
		return fn(ctx, s.repo, s.auditSink)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txRepo := NewRepository(dbgen.New(tx))
	txAudit := audit.NewService(audit.NewRepository(dbgen.New(tx)))
	if err := fn(ctx, txRepo, txAudit); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Service) recordAudit(ctx context.Context, sink auditRecorder, event audit.Event) error {
	if sink == nil {
		return nil
	}
	return sink.Record(ctx, event)
}
