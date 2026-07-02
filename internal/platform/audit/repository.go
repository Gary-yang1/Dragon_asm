package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Repository is the append-only write interface for audit_log rows.
// The implementation is responsible for redacting and marshaling Before/After/
// Metadata; callers pass the raw Event.
type Repository interface {
	Insert(ctx context.Context, e Event) error
}

type sqlcRepository struct {
	q *dbgen.Queries
}

// NewRepository wraps dbgen.Queries for audit log inserts.
func NewRepository(q *dbgen.Queries) Repository {
	return &sqlcRepository{q: q}
}

func (r *sqlcRepository) Insert(ctx context.Context, e Event) error {
	beforeJSON, err := toNullJSON(e.Before)
	if err != nil {
		return fmt.Errorf("audit: marshal before: %w", err)
	}
	afterJSON, err := toNullJSON(e.After)
	if err != nil {
		return fmt.Errorf("audit: marshal after: %w", err)
	}
	metaJSON, err := toNullJSON(e.Metadata)
	if err != nil {
		return fmt.Errorf("audit: marshal metadata: %w", err)
	}

	return r.q.InsertAuditLog(ctx, dbgen.InsertAuditLogParams{
		TenantID:     e.TenantID,
		OrgID:        e.OrgID,
		ProjectID:    e.ProjectID,
		ActorID:      e.ActorID,
		ActorType:    string(e.ActorType),
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		Result:       string(e.Result),
		Ip:           e.IP,
		UserAgent:    e.UserAgent,
		RequestID:    e.RequestID,
		BeforeJson:   beforeJSON,
		AfterJson:    afterJSON,
		MetadataJson: metaJSON,
		ErrorCode:    e.ErrorCode,
		ErrorMessage: e.ErrorMessage,
	})
}

// toNullJSON redacts sensitive keys and marshals v to a JSON string.
// Returns sql.NullString{} when v is nil. Returns an error if marshaling fails
// so callers know a payload was not persisted rather than silently dropped.
func toNullJSON(v any) (sql.NullString, error) {
	if v == nil {
		return sql.NullString{}, nil
	}
	b, err := json.Marshal(Redact(v))
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(b), Valid: true}, nil
}
