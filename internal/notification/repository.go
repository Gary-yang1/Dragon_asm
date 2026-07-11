//revive:disable:exported

package notification

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var ErrNotFound = errors.New("notification: not found")

type Repository interface {
	CreateRule(ctx context.Context, in CreateRuleParams) (uint64, error)
	GetRuleByID(ctx context.Context, projectID, id uint64) (*Rule, error)
	ListRules(ctx context.Context, projectID uint64) ([]*Rule, error)
	ListEnabledRulesByTrigger(ctx context.Context, projectID uint64, trigger string) ([]*Rule, error)
	SetRuleEnabled(ctx context.Context, projectID, id uint64, enabled bool, actorID string) error
	InsertDelivery(ctx context.Context, in DeliveryParams) error
}

type CreateRuleParams struct {
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

type DeliveryParams struct {
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
}

type sqlcRepository struct {
	q *dbgen.Queries
}

func NewRepository(q *dbgen.Queries) Repository {
	return &sqlcRepository{q: q}
}

func (r *sqlcRepository) CreateRule(ctx context.Context, in CreateRuleParams) (uint64, error) {
	recipients, err := json.Marshal(in.Recipients)
	if err != nil {
		return 0, err
	}
	res, err := r.q.CreateNotificationRule(ctx, dbgen.CreateNotificationRuleParams{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		Name: in.Name, TriggerName: in.Trigger, ConditionJson: in.Condition,
		Channel: in.Channel, RecipientsJson: recipients, ThrottleWindow: in.ThrottleWindow,
		Enabled: in.Enabled, CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	})
	if err != nil {
		return 0, err
	}
	return resultID(res)
}

func (r *sqlcRepository) GetRuleByID(ctx context.Context, projectID, id uint64) (*Rule, error) {
	row, err := r.q.GetNotificationRuleByID(ctx, dbgen.GetNotificationRuleByIDParams{ID: id, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toRule(row), nil
}

func (r *sqlcRepository) ListRules(ctx context.Context, projectID uint64) ([]*Rule, error) {
	rows, err := r.q.ListNotificationRulesByProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*Rule, 0, len(rows))
	for _, row := range rows {
		out = append(out, toRule(row))
	}
	return out, nil
}

func (r *sqlcRepository) ListEnabledRulesByTrigger(ctx context.Context, projectID uint64, trigger string) ([]*Rule, error) {
	rows, err := r.q.ListEnabledNotificationRulesByTrigger(ctx, dbgen.ListEnabledNotificationRulesByTriggerParams{ProjectID: projectID, TriggerName: trigger})
	if err != nil {
		return nil, err
	}
	out := make([]*Rule, 0, len(rows))
	for _, row := range rows {
		out = append(out, toRule(row))
	}
	return out, nil
}

func (r *sqlcRepository) SetRuleEnabled(ctx context.Context, projectID, id uint64, enabled bool, actorID string) error {
	res, err := r.q.SetNotificationRuleEnabled(ctx, dbgen.SetNotificationRuleEnabledParams{
		Enabled: enabled, UpdatedBy: actorID, ID: id, ProjectID: projectID,
	})
	return rowsAffectedErr(res, err)
}

func (r *sqlcRepository) InsertDelivery(ctx context.Context, in DeliveryParams) error {
	_, err := r.q.InsertNotificationDelivery(ctx, dbgen.InsertNotificationDeliveryParams{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		RuleID: in.RuleID, TriggerName: in.Trigger, Channel: in.Channel,
		ThrottleKey: in.ThrottleKey, DedupeKey: in.DedupeKey, Status: in.Status,
		Subject: in.Subject, PayloadJson: in.Payload, SentAt: timeForDB(in.SentAt),
	})
	if isDuplicateKey(err) {
		return ErrThrottled
	}
	return err
}

func toRule(row dbgen.NotificationRule) *Rule {
	var recipients []string
	_ = json.Unmarshal(row.RecipientsJson, &recipients)
	return &Rule{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		Name: row.Name, Trigger: row.TriggerName, Condition: row.ConditionJson,
		Channel: row.Channel, Recipients: recipients, ThrottleWindow: row.ThrottleWindow,
		Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		CreatedBy: row.CreatedBy, UpdatedBy: row.UpdatedBy,
	}
}

func resultID(res sql.Result) (uint64, error) {
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if id < 0 {
		return 0, fmt.Errorf("notification: negative insert id %d", id)
	}
	return uint64(id), nil
}

func rowsAffectedErr(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func isDuplicateKey(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1062
}

func timeForDB(t time.Time) time.Time {
	if t.IsZero() {
		return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return t.UTC()
}
