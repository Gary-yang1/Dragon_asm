package retention

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

const (
	// ActionRetentionArchive is the audit action for archive/prune runs.
	ActionRetentionArchive = "retention.archive"

	defaultAuditMinRetentionDays       = 365
	defaultAuditArchiveAfterDays       = 365
	defaultChangeEventArchiveAfterDays = 180
	defaultDiscoveryCallbackAfterDays  = 90
	defaultBatchSize                   = 1000
	maxBatchSize                       = 10000
	defaultRetentionActor              = "retention-worker"
	resourceTypeRetention              = "retention_policy"
	resourceIDDefaultPolicy            = "default"
	discoveryResultCompatibilityNote   = "discovery_result is not yet a physical table; discovery_callback is archived as the current discovery result ledger"
)

var (
	// ErrInvalidPolicy means a retention policy has invalid days, batch size, or DB wiring.
	ErrInvalidPolicy = errors.New("retention: invalid policy")
	// ErrAuditRetentionFloor means audit logs would be pruned before their minimum retention.
	ErrAuditRetentionFloor = errors.New("retention: audit retention is below minimum")
)

type auditRecorder interface {
	Record(ctx context.Context, e audit.Event) error
}

// Service runs data retention archival and pruning in one DB transaction.
type Service struct {
	db    *sql.DB
	nowFn func() time.Time
}

// ServiceOption customizes a retention service.
type ServiceOption func(*Service)

// WithNow overrides the service time source for deterministic tests.
func WithNow(now func() time.Time) ServiceOption {
	return func(s *Service) {
		s.nowFn = now
	}
}

// NewService builds a retention service backed by db.
func NewService(db *sql.DB, opts ...ServiceOption) *Service {
	s := &Service{
		db:    db,
		nowFn: func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Policy configures archive cutoffs and batch size for one retention run.
type Policy struct {
	AuditMinRetentionDays       int
	AuditArchiveAfterDays       int
	ChangeEventArchiveAfterDays int
	DiscoveryCallbackAfterDays  int
	BatchSize                   int
	ActorID                     string
}

// Stats reports archived and pruned row counts for one retention run.
type Stats struct {
	AuditLogsArchived          int64 `json:"audit_logs_archived"`
	AuditLogsDeleted           int64 `json:"audit_logs_deleted"`
	ChangeEventsArchived       int64 `json:"change_events_archived"`
	ChangeEventsDeleted        int64 `json:"change_events_deleted"`
	DiscoveryCallbacksArchived int64 `json:"discovery_callbacks_archived"`
	DiscoveryCallbacksDeleted  int64 `json:"discovery_callbacks_deleted"`
}

// DefaultPolicy returns the MVP retention policy.
func DefaultPolicy() Policy {
	return Policy{
		AuditMinRetentionDays:       defaultAuditMinRetentionDays,
		AuditArchiveAfterDays:       defaultAuditArchiveAfterDays,
		ChangeEventArchiveAfterDays: defaultChangeEventArchiveAfterDays,
		DiscoveryCallbackAfterDays:  defaultDiscoveryCallbackAfterDays,
		BatchSize:                   defaultBatchSize,
		ActorID:                     defaultRetentionActor,
	}
}

// Run archives eligible rows to cold tables, prunes only archived rows, and audits the run.
func (s *Service) Run(ctx context.Context, policy Policy) (Stats, error) {
	policy = withDefaults(policy)
	if err := validatePolicy(policy); err != nil {
		return Stats{}, err
	}
	if s.db == nil {
		return Stats{}, ErrInvalidPolicy
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Stats{}, err
	}
	stats, err := s.runWithRepository(ctx, NewRepository(tx), audit.NewService(audit.NewRepository(dbgen.New(tx))), policy)
	if err != nil {
		_ = tx.Rollback()
		return Stats{}, err
	}
	if err := tx.Commit(); err != nil {
		return Stats{}, err
	}
	return stats, nil
}

func (s *Service) runWithRepository(ctx context.Context, repo Repository, auditSink auditRecorder, policy Policy) (Stats, error) {
	now := s.nowFn().UTC()
	stats := Stats{}
	var err error

	auditCutoff := cutoff(now, policy.AuditArchiveAfterDays)
	if stats.AuditLogsArchived, err = repo.ArchiveAuditLogs(ctx, auditCutoff, policy.BatchSize); err != nil {
		return Stats{}, err
	}
	if stats.AuditLogsDeleted, err = repo.DeleteArchivedAuditLogs(ctx, auditCutoff, policy.BatchSize); err != nil {
		return Stats{}, err
	}

	changeCutoff := cutoff(now, policy.ChangeEventArchiveAfterDays)
	if stats.ChangeEventsArchived, err = repo.ArchiveChangeEvents(ctx, changeCutoff, policy.BatchSize); err != nil {
		return Stats{}, err
	}
	if stats.ChangeEventsDeleted, err = repo.DeleteArchivedChangeEvents(ctx, changeCutoff, policy.BatchSize); err != nil {
		return Stats{}, err
	}

	callbackCutoff := cutoff(now, policy.DiscoveryCallbackAfterDays)
	if stats.DiscoveryCallbacksArchived, err = repo.ArchiveDiscoveryCallbacks(ctx, callbackCutoff, policy.BatchSize); err != nil {
		return Stats{}, err
	}
	if stats.DiscoveryCallbacksDeleted, err = repo.DeleteArchivedDiscoveryCallbacks(ctx, callbackCutoff, policy.BatchSize); err != nil {
		return Stats{}, err
	}

	if auditSink != nil {
		if err := auditSink.Record(ctx, audit.Event{
			ActorID:      policy.ActorID,
			ActorType:    audit.ActorSystem,
			Action:       ActionRetentionArchive,
			ResourceType: resourceTypeRetention,
			ResourceID:   resourceIDDefaultPolicy,
			Result:       audit.ResultSuccess,
			Metadata: map[string]any{
				"audit_cutoff":              auditCutoff.Format(time.RFC3339),
				"change_event_cutoff":       changeCutoff.Format(time.RFC3339),
				"discovery_callback_cutoff": callbackCutoff.Format(time.RFC3339),
				"batch_size":                policy.BatchSize,
				"stats":                     stats,
				"compatibility_note":        discoveryResultCompatibilityNote,
			},
		}); err != nil {
			return Stats{}, err
		}
	}
	return stats, nil
}

func withDefaults(policy Policy) Policy {
	defaults := DefaultPolicy()
	if policy.AuditMinRetentionDays == 0 {
		policy.AuditMinRetentionDays = defaults.AuditMinRetentionDays
	}
	if policy.AuditArchiveAfterDays == 0 {
		policy.AuditArchiveAfterDays = defaults.AuditArchiveAfterDays
	}
	if policy.ChangeEventArchiveAfterDays == 0 {
		policy.ChangeEventArchiveAfterDays = defaults.ChangeEventArchiveAfterDays
	}
	if policy.DiscoveryCallbackAfterDays == 0 {
		policy.DiscoveryCallbackAfterDays = defaults.DiscoveryCallbackAfterDays
	}
	if policy.BatchSize == 0 {
		policy.BatchSize = defaults.BatchSize
	}
	if policy.ActorID == "" {
		policy.ActorID = defaults.ActorID
	}
	return policy
}

func validatePolicy(policy Policy) error {
	if policy.AuditMinRetentionDays <= 0 ||
		policy.AuditArchiveAfterDays <= 0 ||
		policy.ChangeEventArchiveAfterDays <= 0 ||
		policy.DiscoveryCallbackAfterDays <= 0 ||
		policy.BatchSize <= 0 ||
		policy.BatchSize > maxBatchSize {
		return ErrInvalidPolicy
	}
	if policy.AuditArchiveAfterDays < policy.AuditMinRetentionDays {
		return ErrAuditRetentionFloor
	}
	return nil
}

func cutoff(now time.Time, days int) time.Time {
	return now.AddDate(0, 0, -days)
}
