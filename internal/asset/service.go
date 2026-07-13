package asset

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Audit action names and resource type for asset change events. Stable
// vocabulary for the audit log.
const (
	ActionAssetImport    = "asset.import"
	ActionAssetUpdate    = "asset.update"
	ActionRelationSave   = "asset.relation.save"
	ActionAssetLifecycle = "asset.lifecycle"
	ResourceTypeAsset    = "asset"
)

// DefaultMissThreshold is the default consecutive-miss count after which an
// active asset transitions to inactive. Overridable via WithMissThreshold.
const DefaultMissThreshold = 3

// MaxMissThreshold is the upper bound on the configurable miss threshold. It
// guards the int->uint32 cast in the comparison: a value above this is clamped
// (not truncated), so a misconfigured ASSET_MISS_THRESHOLD cannot wrap uint32
// and trigger a premature active->inactive transition. 1000 is far above any
// sane consecutive-miss count.
const MaxMissThreshold = 1000

// maxMissCount is the saturation ceiling for miss_count (uint32 max). In
// practice miss_count is capped at the threshold by the active->inactive
// transition, so this is defense-in-depth against a uint32 wrap on +1.
const maxMissCount = 1<<32 - 1

// Service validation errors.
var (
	// ErrInvalidStatus is returned when a caller supplies a status outside the enum.
	ErrInvalidStatus = errors.New("asset: invalid status")
	// ErrInvalidProjectID is returned when ProjectID is unset (0).
	ErrInvalidProjectID = errors.New("asset: invalid project id")
	// ErrMetadataTooLong is returned when a metadata field exceeds its column width.
	ErrMetadataTooLong = errors.New("asset: metadata field too long")
	// ErrBatchTooLarge is returned when an import/preview batch exceeds the cap.
	ErrBatchTooLarge = errors.New("asset: batch too large")
	// ErrNoFields is returned when an update request changes no editable field.
	ErrNoFields = errors.New("asset: no fields to update")
	// ErrInvalidRelationType is returned when a relation_type is outside the enum.
	ErrInvalidRelationType = errors.New("asset: invalid relation_type")
	// ErrSelfRelation is returned when from and to are the same asset.
	ErrSelfRelation = errors.New("asset: self relation not allowed")
	// ErrRelationEndpointNotFound is returned when a relation endpoint does not
	// exist in the relation's project (covers cross-project endpoints).
	ErrRelationEndpointNotFound = errors.New("asset: relation endpoint not found in project")
)

// Metadata length bounds mirror the asset table column widths, so oversized
// metadata is rejected with a typed error instead of an opaque DB truncation.
const (
	maxDisplayNameLen  = 255
	maxSourceLen       = 64
	maxOwnerLen        = 64
	maxBusinessUnitLen = 128
	maxTenantIDLen     = 64
	maxOrgIDLen        = 64
	maxActorIDLen      = 64
)

// nowFn is the clock used for first_seen/last_seen. It is a package var so tests
// can pin time; production uses time.Now in UTC.
var nowFn = func() time.Time { return time.Now().UTC() }

// auditRecorder is the minimal audit sink the mutating operations depend on.
// *audit.Service satisfies it; a nil sink disables audit writes (unit tests that
// assert only on asset state).
type auditRecorder interface {
	Record(ctx context.Context, e audit.Event) error
}

// AuditMeta carries the request-scoped context the service folds into audit
// events. It deliberately excludes secrets and the actor (the actor is already
// part of the service input).
type AuditMeta struct {
	IP        string
	UserAgent string
	RequestID string
}

// Service applies asset business rules: input normalization, enum validation,
// idempotent import and partial edit. It owns the transaction boundary for the
// mutating operations so an asset change and its audit event commit together
// (or roll back together — a committed change never exists without its audit
// record).
type Service struct {
	repo          Repository
	relationRepo  RelationRepository
	db            *sql.DB       // nil in unit tests; non-nil in production to run a real tx
	auditSink     auditRecorder // used on the non-tx path (tests); the tx path builds its own
	missThreshold int           // consecutive misses before active -> inactive, bounded to [1, MaxMissThreshold]
}

// ServiceOption configures a Service. Use WithDB in production (enables the
// asset+audit transaction) and WithAuditSink in tests that assert on audit.
type ServiceOption func(*Service)

// WithDB enables the transactional path: asset writes and the audit event run
// on one *sql.Tx, committed together or rolled back together.
func WithDB(db *sql.DB) ServiceOption {
	return func(s *Service) { s.db = db }
}

// WithAuditSink injects an audit recorder for the non-transactional (test) path.
// On the transactional path the sink is built from the tx and this is ignored.
func WithAuditSink(sink auditRecorder) ServiceOption {
	return func(s *Service) { s.auditSink = sink }
}

// WithRelationRepository wires the asset_relation store required by the relation
// methods (UpsertRelation / ListRelations). Without it those methods return
// ErrRelationEndpointNotFound-style guard errors only if invoked.
func WithRelationRepository(rr RelationRepository) ServiceOption {
	return func(s *Service) { s.relationRepo = rr }
}

// WithMissThreshold sets the consecutive-miss count after which an active asset
// transitions to inactive. A non-positive value is ignored (the default stays);
// a value above MaxMissThreshold is clamped to MaxMissThreshold so the
// int->uint32 comparison cast can never truncate/wrap.
func WithMissThreshold(n int) ServiceOption {
	return func(s *Service) {
		if n <= 0 {
			return
		}
		if n > MaxMissThreshold {
			n = MaxMissThreshold
		}
		s.missThreshold = n
	}
}

// NewService builds a Service over the given repository. With no options it runs
// without a transaction and without audit (legacy single-row behaviour used by
// the unit tests that assert only on asset state), and with the default miss
// threshold.
func NewService(repo Repository, opts ...ServiceOption) *Service {
	s := &Service{repo: repo, missThreshold: DefaultMissThreshold}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ImportInput is the raw, un-normalized input for a single asset import/discovery
// record. AssetType and Value are normalized here; the rest are metadata.
type ImportInput struct {
	TenantID     string
	OrgID        string
	ProjectID    uint64
	AssetType    string
	Value        string
	DisplayName  string
	Source       string
	Owner        string
	BusinessUnit string
	Confidence   uint8
	Status       string
	ActorID      string
	ObservedAt   time.Time
}

// Import normalizes and idempotently upserts a single asset within its project.
// Repeated imports of the same real-world asset (same normalized key) do not
// create duplicate rows. It returns the resulting live asset.
//
// ProjectID must be a caller-authorized project; this service does not itself
// perform the project access check (that is the project.Service boundary applied
// by the handler), but it can never write outside the given ProjectID.
//
// Import is the single-row primitive; it does NOT write an audit event. The HTTP
// layer uses ImportBatch, which runs a batch upsert plus its audit event in one
// transaction.
func (s *Service) Import(ctx context.Context, in ImportInput) (*Asset, error) {
	if in.ProjectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return importWith(ctx, s.repo, in)
}

// importWith is the normalize→validate→upsert→re-read pipeline run against a
// specific repository. It is shared by Import (single row, on the service repo)
// and ImportBatch (per row, on the tx-scoped repo) so the batch path uses the
// exact same business rules.
func importWith(ctx context.Context, repo Repository, in ImportInput) (*Asset, error) {
	norm, err := Normalize(in.AssetType, in.Value)
	if err != nil {
		return nil, err
	}

	status := in.Status
	if status == "" {
		status = StatusActive
	}
	if !IsValidStatus(status) {
		return nil, ErrInvalidStatus
	}

	confidence := in.Confidence
	if confidence > MaxConfidence {
		confidence = MaxConfidence
	}

	// Enforce metadata column widths before the write so overflow is a typed
	// 422-class error, not an opaque DB truncation. This validates the raw,
	// caller-supplied fields — a too-long explicit DisplayName is still rejected.
	if err := checkMetadataLen(in); err != nil {
		return nil, err
	}

	// Default an omitted DisplayName from the normalized value, but only when it
	// fits display_name (VARCHAR(255)); otherwise leave it empty. Optional display
	// metadata must never make an otherwise-valid asset unimportable.
	displayName := in.DisplayName
	if displayName == "" && len(norm.Value) <= maxDisplayNameLen {
		displayName = norm.Value
	}

	if err := repo.Upsert(ctx, UpsertParams{
		TenantID:     in.TenantID,
		OrgID:        in.OrgID,
		ProjectID:    in.ProjectID,
		AssetType:    norm.Type,
		AssetKey:     norm.Key,
		DisplayName:  displayName,
		Value:        norm.Value,
		Source:       in.Source,
		Owner:        in.Owner,
		BusinessUnit: in.BusinessUnit,
		Confidence:   confidence,
		Status:       status,
		ActorID:      in.ActorID,
		ObservedAt:   in.ObservedAt,
	}); err != nil {
		return nil, err
	}

	return repo.GetByKey(ctx, in.ProjectID, norm.Key)
}

// GetByID returns a live asset scoped to projectID, or ErrNotFound.
func (s *Service) GetByID(ctx context.Context, projectID, id uint64) (*Asset, error) {
	return s.repo.GetByID(ctx, projectID, id)
}

// Count returns the number of live assets in projectID (for list pagination
// totals). It shares List's project + soft-delete scoping.
func (s *Service) Count(ctx context.Context, projectID uint64) (int64, error) {
	return s.repo.Count(ctx, projectID)
}

// List returns live assets in projectID, paginated. limit is clamped to
// [1, maxPageSize]; a non-positive limit uses defaultPageSize.
func (s *Service) List(ctx context.Context, projectID uint64, limit, offset int32) ([]*Asset, error) {
	limit = clampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	return s.repo.List(ctx, projectID, limit, offset)
}

const (
	defaultPageSize int32 = 50
	maxPageSize     int32 = 200
	// MaxImportBatch bounds a single import/preview batch so a runaway caller
	// cannot drive an unbounded loop or an oversized request body.
	MaxImportBatch = 500
)

// Row status values reported by DryRun and ImportBatch.
const (
	RowNew       = "new"
	RowUpdate    = "update"
	RowDuplicate = "duplicate"
	RowInvalid   = "invalid"
	RowImported  = "imported"
	RowFailed    = "failed"
)

// checkMetadataLen rejects any caller-supplied metadata field wider than its
// column. It validates the raw input (including an explicit DisplayName); the
// defaulted DisplayName is handled separately and is always DB-safe.
func checkMetadataLen(in ImportInput) error {
	for _, f := range []struct {
		val string
		max int
	}{
		{in.TenantID, maxTenantIDLen},
		{in.OrgID, maxOrgIDLen},
		{in.DisplayName, maxDisplayNameLen},
		{in.Source, maxSourceLen},
		{in.Owner, maxOwnerLen},
		{in.BusinessUnit, maxBusinessUnitLen},
		{in.ActorID, maxActorIDLen},
	} {
		if len(f.val) > f.max {
			return ErrMetadataTooLong
		}
	}
	return nil
}

// DryRunRowResult is the per-row outcome of a dry-run preview. Status is one of
// RowNew/RowUpdate/RowDuplicate/RowInvalid. AssetKey/Value are populated only
// when the row was normalizable; Error is populated only when Status==RowInvalid.
type DryRunRowResult struct {
	Index      int    `json:"index"`
	Status     string `json:"status"`
	AssetType  string `json:"asset_type,omitempty"`
	Value      string `json:"value,omitempty"`
	AssetKey   string `json:"asset_key,omitempty"`
	ExistingID uint64 `json:"existing_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

// DryRunReport is the preview result of an import batch: every input row is
// classified without writing anything to the database.
type DryRunReport struct {
	Total     int64             `json:"total"`
	New       int64             `json:"new"`
	Update    int64             `json:"update"`
	Duplicate int64             `json:"duplicate"`
	Failed    int64             `json:"failed"`
	Rows      []DryRunRowResult `json:"rows"`
}

// DryRun previews an import batch: it normalizes and validates every row,
// classifies each as new / update / duplicate / invalid, and reports per-row
// errors — without writing to the database. ProjectID, TenantID, OrgID and
// ActorID on each row are overridden by projectID so the caller cannot smuggle
// assets into another project.
func (s *Service) DryRun(ctx context.Context, projectID uint64, rows []ImportInput) (DryRunReport, error) {
	if projectID == 0 {
		return DryRunReport{}, ErrInvalidProjectID
	}
	if len(rows) > MaxImportBatch {
		return DryRunReport{}, ErrBatchTooLarge
	}

	report := DryRunReport{Total: int64(len(rows)), Rows: make([]DryRunRowResult, 0, len(rows))}
	// seen keys dedupes within the batch; existing caches DB lookups so each
	// unique key is queried at most once.
	seen := make(map[string]bool, len(rows))
	existing := make(map[string]*Asset, len(rows))

	for i, row := range rows {
		row.ProjectID = projectID
		res := DryRunRowResult{Index: i}

		norm, err := Normalize(row.AssetType, row.Value)
		if err != nil {
			res.Status = RowInvalid
			res.Error = err.Error()
			report.Failed++
			report.Rows = append(report.Rows, res)
			continue
		}
		res.AssetType = norm.Type
		res.Value = norm.Value
		res.AssetKey = norm.Key

		// Row-level validation (status enum, metadata widths) runs BEFORE the
		// duplicate classification so a row that the real import would reject is
		// surfaced as invalid — even if it is also a duplicate of an earlier row.
		// Without this, a duplicate carrying a bad status would be reported as a
		// harmless "duplicate" and the caller would never see the error.
		if vErr := validateRowFields(row); vErr != nil {
			res.Status = RowInvalid
			res.Error = vErr.Error()
			report.Failed++
			report.Rows = append(report.Rows, res)
			continue
		}

		// A row whose key already appeared earlier in this batch is redundant:
		// the earlier row already accounts for the insert/update.
		if seen[norm.Key] {
			res.Status = RowDuplicate
			report.Duplicate++
			report.Rows = append(report.Rows, res)
			continue
		}
		seen[norm.Key] = true

		// Cache DB lookups per unique key: at most one GetByKey per distinct key.
		// GetByKey excludes soft-deleted rows, so a tombstoned key reports as
		// "new" (re-creatable), matching the unique-key-with-deleted_at semantics.
		a, ok := existing[norm.Key]
		if !ok {
			got, err := s.repo.GetByKey(ctx, projectID, norm.Key)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return DryRunReport{}, err
			}
			if got != nil {
				existing[norm.Key] = got
				a = got
			}
		}
		if a != nil {
			res.Status = RowUpdate
			res.ExistingID = a.ID
			report.Update++
		} else {
			res.Status = RowNew
			report.New++
		}
		report.Rows = append(report.Rows, res)
	}

	return report, nil
}

// ImportBatchInput is a batch of import rows plus the project/actor context
// applied to every row. Per-row ProjectID/TenantID/OrgID/ActorID are overridden
// by the batch values so a single row cannot target another project.
type ImportBatchInput struct {
	ProjectID uint64
	TenantID  string
	OrgID     string
	ActorID   string
	Rows      []ImportInput
}

// ImportRowResult is the per-row outcome of a real import.
type ImportRowResult struct {
	Index    int    `json:"index"`
	Status   string `json:"status"`
	AssetID  uint64 `json:"asset_id,omitempty"`
	AssetKey string `json:"asset_key,omitempty"`
	Error    string `json:"error,omitempty"`
}

// ImportBatchReport summarizes a batch import.
type ImportBatchReport struct {
	Total   int64             `json:"total"`
	Success int64             `json:"success"`
	Failed  int64             `json:"failed"`
	Rows    []ImportRowResult `json:"rows"`
}

// ImportBatch idempotently imports every row into projectID, collecting a
// per-row result so partial failures are visible, AND writes one audit event —
// all within a single transaction. A row-level validation/import failure does not
// abort the batch (the remaining rows still import); but a failure to write the
// audit event rolls back the whole batch, so a committed import never exists
// without its audit record. Repeated imports of the same normalized asset
// collapse to one row (Upsert); an 'ignored'/'inactive' asset is never flipped
// back to 'active' by a re-import (status is preserved).
func (s *Service) ImportBatch(ctx context.Context, in ImportBatchInput, meta AuditMeta) (ImportBatchReport, error) {
	if in.ProjectID == 0 {
		return ImportBatchReport{}, ErrInvalidProjectID
	}
	if len(in.Rows) > MaxImportBatch {
		return ImportBatchReport{}, ErrBatchTooLarge
	}

	report := ImportBatchReport{Total: int64(len(in.Rows)), Rows: make([]ImportRowResult, 0, len(in.Rows))}
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, relRepo RelationRepository, sink auditRecorder) error {
		for i, row := range in.Rows {
			row.ProjectID = in.ProjectID
			row.TenantID = in.TenantID
			row.OrgID = in.OrgID
			row.ActorID = in.ActorID

			a, err := importWith(ctx, repo, row)
			if err != nil {
				report.Failed++
				report.Rows = append(report.Rows, ImportRowResult{
					Index:  i,
					Status: RowFailed,
					Error:  err.Error(),
				})
				continue
			}
			if a.AssetType == TypeSubdomain && relRepo != nil {
				if resolver, ok := repo.(RootDomainResolver); ok {
					rootID, resolveErr := resolver.FindRootDomainAssetID(ctx, in.ProjectID, a.Value)
					switch {
					case resolveErr == nil:
						if err := relRepo.Upsert(ctx, UpsertRelationParams{
							TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
							FromAssetID: rootID, ToAssetID: a.ID, RelationType: RelationContains,
							Source: "project_profile", Confidence: MaxRelationConfidence, ActorID: in.ActorID,
						}); err != nil {
							return err
						}
					case !errors.Is(resolveErr, ErrNotFound):
						return resolveErr
					}
				}
			}
			report.Success++
			report.Rows = append(report.Rows, ImportRowResult{
				Index:    i,
				Status:   RowImported,
				AssetID:  a.ID,
				AssetKey: a.AssetKey,
			})
		}

		// The audit event is part of the same transaction: a committed import
		// must carry its audit record. A nil sink (no-tx unit tests that do not
		// assert on audit) skips the write rather than failing.
		if sink == nil {
			return nil
		}
		result := audit.ResultSuccess
		if report.Failed > 0 {
			result = audit.ResultFailure
		}
		return sink.Record(ctx, audit.Event{
			TenantID:     in.TenantID,
			OrgID:        in.OrgID,
			ProjectID:    in.ProjectID,
			ActorID:      in.ActorID,
			ActorType:    audit.ActorUser,
			Action:       ActionAssetImport,
			ResourceType: ResourceTypeAsset,
			Result:       result,
			IP:           meta.IP,
			UserAgent:    meta.UserAgent,
			RequestID:    meta.RequestID,
			Metadata: map[string]any{
				"total":   report.Total,
				"success": report.Success,
				"failed":  report.Failed,
			},
		})
	})
	return report, err
}

// UpdateFields is a partial update of the operator-editable, non-key metadata
// fields. A nil pointer means "leave unchanged". Status may be set to
// active/inactive/ignored; 'deleted' is reserved for the soft-delete operation
// and is rejected here.
type UpdateFields struct {
	DisplayName  *string
	Source       *string
	Owner        *string
	BusinessUnit *string
	Status       *string
}

// Update applies a partial edit to one project-scoped live asset and returns
// the refreshed asset. The edit and its audit event run in one transaction: a
// committed edit always carries its audit record (before+after snapshots). A
// validation error (bad status, overlong metadata, not found, no fields) is
// surfaced as the typed error with the transaction rolled back (nothing
// written); an audit-write failure also rolls the edit back.
func (s *Service) Update(ctx context.Context, projectID, id uint64, fields UpdateFields, actorID string, meta AuditMeta) (*Asset, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if fields.DisplayName == nil && fields.Source == nil && fields.Owner == nil &&
		fields.BusinessUnit == nil && fields.Status == nil {
		return nil, ErrNoFields
	}
	if len(actorID) > maxActorIDLen {
		return nil, ErrMetadataTooLong
	}

	var after *Asset
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, _ RelationRepository, sink auditRecorder) error {
		before, updated, err := updateWith(ctx, repo, projectID, id, fields, actorID)
		if err != nil {
			return err
		}
		after = updated

		if sink == nil {
			return nil
		}
		return sink.Record(ctx, audit.Event{
			TenantID:     before.TenantID,
			OrgID:        before.OrgID,
			ProjectID:    projectID,
			ActorID:      actorID,
			ActorType:    audit.ActorUser,
			Action:       ActionAssetUpdate,
			ResourceType: ResourceTypeAsset,
			ResourceID:   strconv.FormatUint(updated.ID, 10),
			Result:       audit.ResultSuccess,
			IP:           meta.IP,
			UserAgent:    meta.UserAgent,
			RequestID:    meta.RequestID,
			Before:       before,
			After:        updated,
			Metadata:     map[string]any{"changed": changedFields(fields)},
		})
	})
	if err != nil {
		return nil, err
	}
	return after, nil
}

// RelationInput is the validated input for an idempotent relation upsert.
// TenantID/OrgID/ProjectID scope the edge and must match both endpoints; the
// handler derives them from the project (Access), never from the request body.
type RelationInput struct {
	TenantID     string
	OrgID        string
	ProjectID    uint64
	FromAssetID  uint64
	ToAssetID    uint64
	RelationType string
	Source       string
	Confidence   uint8
	ActorID      string
	ObservedAt   time.Time
}

// UpsertRelation idempotently creates or refreshes a directed edge between two
// assets in one project. It validates the type enum, rejects self-loops, and
// explicitly verifies both endpoints exist in the relation's project (and share
// its tenant/org) — so a cross-project endpoint is rejected with
// ErrRelationEndpointNotFound before hitting the composite FK. The edge write and
// its audit event run in one transaction.
func (s *Service) UpsertRelation(ctx context.Context, in RelationInput, meta AuditMeta) (*Relation, error) {
	if in.ProjectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if s.relationRepo == nil {
		return nil, errors.New("asset: relation store not configured")
	}
	if !IsValidRelationType(in.RelationType) {
		return nil, ErrInvalidRelationType
	}
	if in.FromAssetID == in.ToAssetID {
		return nil, ErrSelfRelation
	}
	if len(in.Source) > maxSourceLen || len(in.ActorID) > maxActorIDLen {
		return nil, ErrMetadataTooLong
	}
	confidence := in.Confidence
	if confidence > MaxRelationConfidence {
		confidence = MaxRelationConfidence
	}

	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, relRepo RelationRepository, sink auditRecorder) error {
		// Explicit endpoint validation: both assets must live in this project and
		// share its tenant/org. GetByID is project-scoped, so a cross-project
		// endpoint surfaces as ErrNotFound -> ErrRelationEndpointNotFound.
		from, err := repo.GetByID(ctx, in.ProjectID, in.FromAssetID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return ErrRelationEndpointNotFound
			}
			return err
		}
		to, err := repo.GetByID(ctx, in.ProjectID, in.ToAssetID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return ErrRelationEndpointNotFound
			}
			return err
		}
		if from.TenantID != in.TenantID || from.OrgID != in.OrgID ||
			to.TenantID != in.TenantID || to.OrgID != in.OrgID {
			// Defense-in-depth: the composite FK would also reject this, but a
			// typed error is clearer than an opaque FK violation.
			return ErrRelationEndpointNotFound
		}

		if err := relRepo.Upsert(ctx, UpsertRelationParams{
			TenantID:     in.TenantID,
			OrgID:        in.OrgID,
			ProjectID:    in.ProjectID,
			FromAssetID:  in.FromAssetID,
			ToAssetID:    in.ToAssetID,
			RelationType: in.RelationType,
			Source:       in.Source,
			Confidence:   confidence,
			ActorID:      in.ActorID,
			ObservedAt:   in.ObservedAt,
		}); err != nil {
			return err
		}

		if sink == nil {
			return nil
		}
		return sink.Record(ctx, audit.Event{
			TenantID:     in.TenantID,
			OrgID:        in.OrgID,
			ProjectID:    in.ProjectID,
			ActorID:      in.ActorID,
			ActorType:    audit.ActorUser,
			Action:       ActionRelationSave,
			ResourceType: ResourceTypeAsset,
			Result:       audit.ResultSuccess,
			IP:           meta.IP,
			UserAgent:    meta.UserAgent,
			RequestID:    meta.RequestID,
			Metadata: map[string]any{
				"from_asset_id": in.FromAssetID,
				"to_asset_id":   in.ToAssetID,
				"relation_type": in.RelationType,
				"source":        in.Source,
			},
		})
	})
	if err != nil {
		return nil, err
	}
	// Read the committed edge back so the response carries id/timestamps. On the
	// tx path this reads via the non-tx relation repo (the row is committed); on
	// the test path via the injected fake.
	return s.relationRepo.GetByEndpoints(ctx, in.ProjectID, in.FromAssetID, in.ToAssetID, in.RelationType)
}

// ListRelations returns live edges where the asset is either endpoint (both
// directions), paginated; each row is tagged Direction relative to the asset.
//
// The parent asset must exist in the project: a missing asset returns ErrNotFound
// (rather than an empty 200) so the caller can distinguish "no such asset" from
// "asset exists but has no relations". The handler runs the project access and
// asset:read permission checks before this, so the existence check never leaks
// cross-project asset state.
func (s *Service) ListRelations(ctx context.Context, projectID, assetID uint64, limit, offset int32) ([]*Relation, int64, error) {
	if projectID == 0 {
		return nil, 0, ErrInvalidProjectID
	}
	if s.relationRepo == nil {
		return nil, 0, errors.New("asset: relation store not configured")
	}
	// Validate the parent asset exists in this project before listing its edges.
	// GetByID is project-scoped, so a cross-project or nonexistent id is ErrNotFound.
	if _, err := s.repo.GetByID(ctx, projectID, assetID); err != nil {
		return nil, 0, err
	}
	limit = clampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	rows, err := s.relationRepo.ListByAsset(ctx, projectID, assetID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.relationRepo.CountByAsset(ctx, projectID, assetID)
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

// RecordMiss increments an active asset's consecutive-miss count and, when the
// count reaches the configured threshold, transitions it active -> inactive.
// Non-active assets (inactive/ignored/deleted) are left untouched so the
// lifecycle never re-triggers or un-ignores them. The transition (asset write +
// audit + lifecycle hook) runs in one transaction; a miss below threshold only
// updates miss_count (no audit, no hook). Returns the resulting asset and
// whether a status transition occurred.
func (s *Service) RecordMiss(ctx context.Context, projectID, assetID uint64, actorID string, meta AuditMeta) (*Asset, bool, error) {
	if projectID == 0 {
		return nil, false, ErrInvalidProjectID
	}
	var (
		after        *Asset
		transitioned bool
	)
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, _ RelationRepository, sink auditRecorder) error {
		before, err := repo.GetByID(ctx, projectID, assetID)
		if err != nil {
			return err
		}
		if before.Status != StatusActive {
			// Only active assets accumulate misses / can go inactive.
			after = before
			return nil
		}
		// Saturate at the uint32 ceiling so miss_count+1 can never wrap to 0.
		// Unreachable in practice (the transition caps miss_count at the
		// threshold, <= MaxMissThreshold), but defensive against a wrap.
		if before.MissCount >= maxMissCount {
			after = before
			return nil
		}
		newMiss := before.MissCount + 1
		if newMiss < uint32(s.missThreshold) { //nolint:gosec // G115: missThreshold is bounded to [1, MaxMissThreshold] (1000) by WithMissThreshold, so the cast cannot overflow/truncate.
			if err := repo.UpdateLifecycle(ctx, UpdateLifecycleParams{
				ProjectID: projectID, ID: assetID, MissCount: newMiss, Status: StatusActive, ActorID: actorID,
			}); err != nil {
				return err
			}
			after, err = repo.GetByID(ctx, projectID, assetID)
			if err != nil {
				return err
			}
			return nil
		}
		if err := repo.UpdateLifecycle(ctx, UpdateLifecycleParams{
			ProjectID: projectID, ID: assetID, MissCount: newMiss, Status: StatusInactive, ActorID: actorID,
		}); err != nil {
			return err
		}
		after, err = repo.GetByID(ctx, projectID, assetID)
		if err != nil {
			return err
		}
		transitioned = true
		return s.recordLifecycleTransition(ctx, sink, before, after, StatusActive, StatusInactive, actorID, meta)
	})
	if err != nil {
		return nil, false, err
	}
	return after, transitioned, nil
}

// RecordHit records a discovery "hit" for an asset: resets miss_count to 0 and,
// if the asset was inactive (stale), re-activates it (inactive -> active).
// active assets keep their status (miss_count reset only if it had climbed);
// ignored/deleted assets are preserved — a hit never un-ignores or un-deletes.
// The re-activation (asset write + audit + lifecycle hook) runs in one
// transaction. Returns the resulting asset and whether a transition occurred.
func (s *Service) RecordHit(ctx context.Context, projectID, assetID uint64, actorID string, meta AuditMeta) (*Asset, bool, error) {
	if projectID == 0 {
		return nil, false, ErrInvalidProjectID
	}
	var (
		after        *Asset
		transitioned bool
	)
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository, _ RelationRepository, sink auditRecorder) error {
		before, err := repo.GetByID(ctx, projectID, assetID)
		if err != nil {
			return err
		}
		switch before.Status {
		case StatusActive:
			if before.MissCount == 0 {
				after = before
				return nil
			}
			if err := repo.UpdateLifecycle(ctx, UpdateLifecycleParams{
				ProjectID: projectID, ID: assetID, MissCount: 0, Status: StatusActive, ActorID: actorID,
			}); err != nil {
				return err
			}
			after, err = repo.GetByID(ctx, projectID, assetID)
			if err != nil {
				return err
			}
			return nil
		case StatusInactive:
			if err := repo.UpdateLifecycle(ctx, UpdateLifecycleParams{
				ProjectID: projectID, ID: assetID, MissCount: 0, Status: StatusActive, ActorID: actorID,
			}); err != nil {
				return err
			}
			after, err = repo.GetByID(ctx, projectID, assetID)
			if err != nil {
				return err
			}
			transitioned = true
			return s.recordLifecycleTransition(ctx, sink, before, after, StatusInactive, StatusActive, actorID, meta)
		default:
			// ignored/deleted: preserve, no lifecycle action.
			after = before
			return nil
		}
	})
	if err != nil {
		return nil, false, err
	}
	return after, transitioned, nil
}

// recordLifecycleTransition writes the audit event and invokes the lifecycle
// hook for a status transition, inside the caller's transaction. Either failure
// returns an error so the transition rolls back (audit and future change_event
// stay atomic with the asset write).
func (s *Service) recordLifecycleTransition(ctx context.Context, sink auditRecorder, before, after *Asset, fromStatus, toStatus, actorID string, meta AuditMeta) error {
	if sink != nil {
		if err := sink.Record(ctx, audit.Event{
			TenantID:     before.TenantID,
			OrgID:        before.OrgID,
			ProjectID:    before.ProjectID,
			ActorID:      actorID,
			ActorType:    audit.ActorSystem,
			Action:       ActionAssetLifecycle,
			ResourceType: ResourceTypeAsset,
			ResourceID:   strconv.FormatUint(after.ID, 10),
			Result:       audit.ResultSuccess,
			IP:           meta.IP,
			UserAgent:    meta.UserAgent,
			RequestID:    meta.RequestID,
			Before:       before,
			After:        after,
			Metadata: map[string]any{
				"from":       fromStatus,
				"to":         toStatus,
				"miss_count": after.MissCount,
			},
		}); err != nil {
			return err
		}
	}
	// TODO(M2-5): produce a change_event row on THIS transaction (not a side
	// channel). The event writer must be tx-scoped — built from the same
	// *sql.Tx the asset write and the audit event run on — so a commit/rollback
	// covers all three. A hook that only receives ctx/ids cannot honour that
	// contract (it would have to open its own connection), so M1-4 deliberately
	// does not wire one; M2-5 will extend runInTx to pass a tx-scoped event
	// writer when the change_event table lands.
	return nil
}

// updateWith loads the current row, merges the provided fields, validates,
// writes, and re-reads — all against the given repository (the service repo for
// plain reads, or a tx-scoped repo inside Update). It returns the before and
// after snapshots so the caller can record an auditable before→after transition.
func updateWith(ctx context.Context, repo Repository, projectID, id uint64, fields UpdateFields, actorID string) (*Asset, *Asset, error) {
	before, err := repo.GetByID(ctx, projectID, id)
	if err != nil {
		return nil, nil, err
	}

	// Merge provided fields onto the current values; omitted fields are preserved.
	displayName := before.DisplayName
	if fields.DisplayName != nil {
		displayName = *fields.DisplayName
	}
	source := before.Source
	if fields.Source != nil {
		source = *fields.Source
	}
	owner := before.Owner
	if fields.Owner != nil {
		owner = *fields.Owner
	}
	businessUnit := before.BusinessUnit
	if fields.BusinessUnit != nil {
		businessUnit = *fields.BusinessUnit
	}
	status := before.Status
	if fields.Status != nil {
		status = *fields.Status
		// Edit may not tombstone; 'deleted' is the soft-delete operation's job.
		if !IsValidStatus(status) || status == StatusDeleted {
			return nil, nil, ErrInvalidStatus
		}
	}

	// Enforce column widths on the merged values so overflow is a typed 422, not
	// an opaque DB truncation.
	for _, f := range []struct {
		val string
		max int
	}{
		{displayName, maxDisplayNameLen},
		{source, maxSourceLen},
		{owner, maxOwnerLen},
		{businessUnit, maxBusinessUnitLen},
	} {
		if len(f.val) > f.max {
			return nil, nil, ErrMetadataTooLong
		}
	}

	if err := repo.Update(ctx, UpdateParams{
		ProjectID:    projectID,
		ID:           id,
		DisplayName:  displayName,
		Source:       source,
		Owner:        owner,
		BusinessUnit: businessUnit,
		Status:       status,
		ActorID:      actorID,
	}); err != nil {
		return nil, nil, err
	}
	after, err := repo.GetByID(ctx, projectID, id)
	if err != nil {
		return nil, nil, err
	}
	return before, after, nil
}

// changedFields reports which UpdateFields pointers were set (the operator-
// supplied change set), for the audit metadata.
func changedFields(fields UpdateFields) map[string]string {
	changed := make(map[string]string, 5)
	if fields.DisplayName != nil {
		changed["display_name"] = *fields.DisplayName
	}
	if fields.Source != nil {
		changed["source"] = *fields.Source
	}
	if fields.Owner != nil {
		changed["owner"] = *fields.Owner
	}
	if fields.BusinessUnit != nil {
		changed["business_unit"] = *fields.BusinessUnit
	}
	if fields.Status != nil {
		changed["status"] = *fields.Status
	}
	return changed
}

// runInTx runs fn against transaction-scoped asset + relation repositories and
// an audit sink. When the service has a *sql.DB (production), fn runs on a real
// *sql.Tx so the asset/relation write and the audit insert commit together or
// roll back together. When there is no DB (unit tests), fn runs on the injected
// repos and audit sink with no real transaction — enough to exercise the wiring
// without a DB.
func (s *Service) runInTx(ctx context.Context, fn func(ctx context.Context, repo Repository, relRepo RelationRepository, sink auditRecorder) error) error {
	if s.db == nil {
		return fn(ctx, s.repo, s.relationRepo, s.auditSink)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txRepo := NewRepository(dbgen.New(tx))
	txRelRepo := NewRelationRepository(dbgen.New(tx))
	txAudit := audit.NewService(audit.NewRepository(dbgen.New(tx)))
	if err := fn(ctx, txRepo, txRelRepo, txAudit); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// validateRowFields checks the non-normalizable ImportInput fields (status enum
// + metadata widths) without touching the DB. It mirrors Import's guards so
// dry-run surfaces the same issues the real import would reject on.
func validateRowFields(in ImportInput) error {
	status := in.Status
	if status == "" {
		status = StatusActive
	}
	if !IsValidStatus(status) {
		return ErrInvalidStatus
	}
	return checkMetadataLen(in)
}

func clampLimit(limit int32) int32 {
	switch {
	case limit <= 0:
		return defaultPageSize
	case limit > maxPageSize:
		return maxPageSize
	default:
		return limit
	}
}
