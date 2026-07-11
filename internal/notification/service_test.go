package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

type fakeRepo struct {
	rules     map[uint64]*Rule
	delivered map[string]DeliveryParams
	nextID    uint64
}

type fakeAudit struct {
	events []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) error {
	f.events = append(f.events, e)
	return nil
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{rules: map[uint64]*Rule{}, delivered: map[string]DeliveryParams{}, nextID: 1}
}

func (f *fakeRepo) CreateRule(_ context.Context, in CreateRuleParams) (uint64, error) {
	id := f.nextID
	f.nextID++
	f.rules[id] = &Rule{
		ID: id, TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		Name: in.Name, Trigger: in.Trigger, Condition: in.Condition,
		Channel: in.Channel, Recipients: append([]string(nil), in.Recipients...),
		ThrottleWindow: in.ThrottleWindow, Enabled: in.Enabled, CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	}
	return id, nil
}

func (f *fakeRepo) GetRuleByID(_ context.Context, projectID, id uint64) (*Rule, error) {
	rule := f.rules[id]
	if rule == nil || rule.ProjectID != projectID {
		return nil, ErrNotFound
	}
	cp := *rule
	cp.Recipients = append([]string(nil), rule.Recipients...)
	return &cp, nil
}

func (f *fakeRepo) ListRules(_ context.Context, projectID uint64) ([]*Rule, error) {
	out := []*Rule{}
	for _, rule := range f.rules {
		if rule.ProjectID == projectID {
			cp := *rule
			cp.Recipients = append([]string(nil), rule.Recipients...)
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeRepo) ListEnabledRulesByTrigger(_ context.Context, projectID uint64, trigger string) ([]*Rule, error) {
	out := []*Rule{}
	for _, rule := range f.rules {
		if rule.ProjectID == projectID && rule.Trigger == trigger && rule.Enabled {
			cp := *rule
			cp.Recipients = append([]string(nil), rule.Recipients...)
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeRepo) SetRuleEnabled(_ context.Context, projectID, id uint64, enabled bool, actorID string) error {
	rule := f.rules[id]
	if rule == nil || rule.ProjectID != projectID {
		return ErrNotFound
	}
	rule.Enabled = enabled
	rule.UpdatedBy = actorID
	return nil
}

func (f *fakeRepo) InsertDelivery(_ context.Context, in DeliveryParams) error {
	key := fmt.Sprintf("%d:%d:%s", in.ProjectID, in.RuleID, in.ThrottleKey)
	if _, ok := f.delivered[key]; ok {
		return ErrThrottled
	}
	f.delivered[key] = in
	return nil
}

type fakeSender struct {
	messages []Message
	err      error
}

func (f *fakeSender) Send(_ context.Context, msg Message) error {
	if f.err != nil {
		return f.err
	}
	f.messages = append(f.messages, msg)
	return nil
}

func TestTriggerSendsMatchingRule(t *testing.T) {
	repo := newFakeRepo()
	sender := &fakeSender{}
	audits := &fakeAudit{}
	svc := NewService(repo, WithSender(sender), WithNow(func() time.Time {
		return time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	}), WithAuditSink(audits))
	condition := json.RawMessage(`{"severity":"critical","entity_type":"exposure"}`)
	_, err := svc.CreateRule(context.Background(), CreateRuleInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Name: "critical exposure",
		Trigger: TriggerNewCriticalExposure, Condition: condition, Channel: ChannelEmail,
		Recipients: []string{"sec@example.test"}, ThrottleWindow: 3600, ActorID: "alice",
	})
	require.NoError(t, err)
	require.Len(t, audits.events, 1)
	assert.Equal(t, ActionNotificationRuleCreate, audits.events[0].Action)
	assert.Equal(t, ResourceTypeNotificationRule, audits.events[0].ResourceType)

	result, err := svc.Trigger(context.Background(), TriggerInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Trigger: TriggerNewCriticalExposure,
		Severity: "critical", EntityType: "exposure", EntityID: 42, Subject: "new critical exposure",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Sent)
	require.Len(t, sender.messages, 1)
	assert.Equal(t, ChannelEmail, sender.messages[0].Channel)
	assert.Equal(t, []string{"sec@example.test"}, sender.messages[0].Recipients)
}

func TestTriggerThrottlesWithinWindow(t *testing.T) {
	repo := newFakeRepo()
	sender := &fakeSender{}
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	svc := NewService(repo, WithSender(sender), WithNow(func() time.Time { return now }))
	_, err := svc.CreateRule(context.Background(), CreateRuleInput{
		ProjectID: 1, Name: "sla due", Trigger: TriggerSLADueSoon, Channel: ChannelWebhook,
		Recipients: []string{"https://hook.example.test"}, ThrottleWindow: 3600, ActorID: "alice",
	})
	require.NoError(t, err)
	input := TriggerInput{ProjectID: 1, Trigger: TriggerSLADueSoon, RiskID: 10, Subject: "sla due soon"}
	first, err := svc.Trigger(context.Background(), input)
	require.NoError(t, err)
	second, err := svc.Trigger(context.Background(), input)
	require.NoError(t, err)

	assert.Equal(t, 1, first.Sent)
	assert.Equal(t, 1, second.Throttled)
	assert.Len(t, sender.messages, 1)
}

func TestTriggerHonorsDisabledRule(t *testing.T) {
	repo := newFakeRepo()
	sender := &fakeSender{}
	audits := &fakeAudit{}
	svc := NewService(repo, WithSender(sender), WithAuditSink(audits))
	rule, err := svc.CreateRule(context.Background(), CreateRuleInput{
		ProjectID: 1, Name: "cert expiring", Trigger: TriggerCertExpiring, Channel: ChannelEmail,
		Recipients: []string{"ops@example.test"}, ActorID: "alice",
	})
	require.NoError(t, err)
	require.NoError(t, svc.SetRuleEnabled(context.Background(), 1, rule.ID, false, "alice"))
	require.Len(t, audits.events, 2)
	assert.Equal(t, ActionNotificationRuleEnable, audits.events[1].Action)
	assert.Equal(t, false, audits.events[1].Metadata.(map[string]any)["enabled"])

	result, err := svc.Trigger(context.Background(), TriggerInput{ProjectID: 1, Trigger: TriggerCertExpiring, EntityType: "certificate", EntityID: 1})
	require.NoError(t, err)
	assert.Zero(t, result.Sent)
	assert.Empty(t, sender.messages)
}

func TestCreateRuleValidatesChannelAndRecipients(t *testing.T) {
	_, err := NewService(newFakeRepo()).CreateRule(context.Background(), CreateRuleInput{
		ProjectID: 1, Name: "bad", Trigger: TriggerNewHighRisk, Channel: "sms", Recipients: []string{"sec"}, ActorID: "alice",
	})
	require.ErrorIs(t, err, ErrInvalidChannel)

	_, err = NewService(newFakeRepo()).CreateRule(context.Background(), CreateRuleInput{
		ProjectID: 1, Name: "bad", Trigger: TriggerNewHighRisk, Channel: ChannelEmail, ActorID: "alice",
	})
	require.ErrorIs(t, err, ErrInvalidRecipient)
}
