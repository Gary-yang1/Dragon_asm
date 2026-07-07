package asset

import (
	"context"
	"errors"
	"time"
)

// Service validation errors.
var (
	// ErrInvalidStatus is returned when a caller supplies a status outside the enum.
	ErrInvalidStatus = errors.New("asset: invalid status")
	// ErrInvalidProjectID is returned when ProjectID is unset (0).
	ErrInvalidProjectID = errors.New("asset: invalid project id")
	// ErrMetadataTooLong is returned when a metadata field exceeds its column width.
	ErrMetadataTooLong = errors.New("asset: metadata field too long")
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

// Service applies asset business rules: input normalization, enum validation and
// idempotent import. It owns no HTTP concerns.
type Service struct {
	repo Repository
}

// NewService builds a Service over the given repository.
func NewService(repo Repository) *Service {
	return &Service{repo: repo}
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
}

// Import normalizes and idempotently upserts a single asset within its project.
// Repeated imports of the same real-world asset (same normalized key) do not
// create duplicate rows. It returns the resulting live asset.
//
// ProjectID must be a caller-authorized project; this service does not itself
// perform the project access check (that is the project.Service boundary applied
// by the future handler), but it can never write outside the given ProjectID.
func (s *Service) Import(ctx context.Context, in ImportInput) (*Asset, error) {
	if in.ProjectID == 0 {
		return nil, ErrInvalidProjectID
	}
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

	if err := s.repo.Upsert(ctx, UpsertParams{
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
	}); err != nil {
		return nil, err
	}

	return s.repo.GetByKey(ctx, in.ProjectID, norm.Key)
}

// GetByID returns a live asset scoped to projectID, or ErrNotFound.
func (s *Service) GetByID(ctx context.Context, projectID, id uint64) (*Asset, error) {
	return s.repo.GetByID(ctx, projectID, id)
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
