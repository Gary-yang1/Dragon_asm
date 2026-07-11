//revive:disable:exported

package exposure

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var ErrNotFound = errors.New("exposure: not found")

type Repository interface {
	GetByKey(ctx context.Context, projectID uint64, exposureKey string) (*Exposure, error)
	GetByID(ctx context.Context, projectID, id uint64) (*Exposure, error)
	List(ctx context.Context, projectID uint64, limit, offset int32) ([]*Exposure, error)
	Count(ctx context.Context, projectID uint64) (int64, error)
	Upsert(ctx context.Context, in UpsertParams) error
	InsertChangeEvent(ctx context.Context, in ChangeEventParams) error
}

type UpsertParams struct {
	TenantID      string
	OrgID         string
	ProjectID     uint64
	AssetID       uint64
	ExposureType  string
	ExposureKey   string
	Name          string
	Value         string
	Protocol      string
	Port          uint32
	Service       string
	Version       string
	CPE           string
	URL           string
	Fingerprint   string
	CertSubject   string
	CertIssuer    string
	CertSerial    string
	CertNotBefore time.Time
	CertNotAfter  time.Time
	CertSANs      []string
	EvidenceHash  string
	Source        string
	Confidence    uint8
	ActorID       string
	ObservedAt    time.Time
}

type ChangeEventParams struct {
	TenantID   string
	OrgID      string
	ProjectID  uint64
	EntityType string
	EntityID   uint64
	ChangeType string
	Severity   string
	Title      string
	Summary    string
	Source     string
	Before     json.RawMessage
	After      json.RawMessage
	DetectedAt time.Time
}

type sqlcRepository struct {
	q *dbgen.Queries
}

func NewRepository(q *dbgen.Queries) Repository {
	return &sqlcRepository{q: q}
}

func (r *sqlcRepository) GetByKey(ctx context.Context, projectID uint64, exposureKey string) (*Exposure, error) {
	row, err := r.q.GetExposureByKey(ctx, dbgen.GetExposureByKeyParams{
		ProjectID:   projectID,
		ExposureKey: exposureKey,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return toDomain(row), nil
}

func (r *sqlcRepository) GetByID(ctx context.Context, projectID, id uint64) (*Exposure, error) {
	row, err := r.q.GetExposureByID(ctx, dbgen.GetExposureByIDParams{ID: id, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toDomain(row), nil
}

func (r *sqlcRepository) List(ctx context.Context, projectID uint64, limit, offset int32) ([]*Exposure, error) {
	rows, err := r.q.ListExposuresByProject(ctx, dbgen.ListExposuresByProjectParams{
		ProjectID: projectID,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		return nil, err
	}
	out := make([]*Exposure, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomain(row))
	}
	return out, nil
}

func (r *sqlcRepository) Count(ctx context.Context, projectID uint64) (int64, error) {
	n, err := r.q.CountExposuresByProject(ctx, projectID)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (r *sqlcRepository) Upsert(ctx context.Context, in UpsertParams) error {
	observedAt := in.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	_, err := r.q.UpsertExposure(ctx, dbgen.UpsertExposureParams{
		TenantID:      in.TenantID,
		OrgID:         in.OrgID,
		ProjectID:     in.ProjectID,
		AssetID:       in.AssetID,
		ExposureType:  in.ExposureType,
		ExposureKey:   in.ExposureKey,
		Name:          in.Name,
		Value:         in.Value,
		Protocol:      in.Protocol,
		Port:          in.Port,
		Service:       in.Service,
		Version:       in.Version,
		Cpe:           in.CPE,
		Url:           in.URL,
		Fingerprint:   in.Fingerprint,
		CertSubject:   in.CertSubject,
		CertIssuer:    in.CertIssuer,
		CertSerial:    in.CertSerial,
		CertNotBefore: certTimeForDB(in.CertNotBefore),
		CertNotAfter:  certTimeForDB(in.CertNotAfter),
		CertSanJson:   marshalSANs(in.CertSANs),
		EvidenceHash:  in.EvidenceHash,
		Source:        in.Source,
		Confidence:    in.Confidence,
		FirstSeen:     observedAt,
		LastSeen:      observedAt,
		CreatedBy:     in.ActorID,
		UpdatedBy:     in.ActorID,
	})
	return err
}

func (r *sqlcRepository) InsertChangeEvent(ctx context.Context, in ChangeEventParams) error {
	_, err := r.q.InsertChangeEvent(ctx, dbgen.InsertChangeEventParams{
		TenantID:   in.TenantID,
		OrgID:      in.OrgID,
		ProjectID:  in.ProjectID,
		EntityType: in.EntityType,
		EntityID:   in.EntityID,
		ChangeType: in.ChangeType,
		Severity:   in.Severity,
		Title:      in.Title,
		Summary:    in.Summary,
		Source:     in.Source,
		BeforeJson: in.Before,
		AfterJson:  in.After,
		DetectedAt: in.DetectedAt,
	})
	return err
}

func toDomain(row dbgen.Exposure) *Exposure {
	return &Exposure{
		ID:            row.ID,
		TenantID:      row.TenantID,
		OrgID:         row.OrgID,
		ProjectID:     row.ProjectID,
		AssetID:       row.AssetID,
		ExposureType:  row.ExposureType,
		ExposureKey:   row.ExposureKey,
		Name:          row.Name,
		Value:         row.Value,
		Protocol:      row.Protocol,
		Port:          row.Port,
		Service:       row.Service,
		Version:       row.Version,
		CPE:           row.Cpe,
		URL:           row.Url,
		Fingerprint:   row.Fingerprint,
		CertSubject:   row.CertSubject,
		CertIssuer:    row.CertIssuer,
		CertSerial:    row.CertSerial,
		CertNotBefore: row.CertNotBefore,
		CertNotAfter:  row.CertNotAfter,
		CertSANs:      unmarshalSANs(row.CertSanJson),
		EvidenceHash:  row.EvidenceHash,
		Source:        row.Source,
		Confidence:    row.Confidence,
		FirstSeen:     row.FirstSeen,
		LastSeen:      row.LastSeen,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
		CreatedBy:     row.CreatedBy,
		UpdatedBy:     row.UpdatedBy,
	}
}

func marshalSANs(sans []string) json.RawMessage {
	if len(sans) == 0 {
		return nil
	}
	raw, _ := json.Marshal(sans)
	return raw
}

func unmarshalSANs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var sans []string
	if err := json.Unmarshal(raw, &sans); err != nil {
		return nil
	}
	return sans
}

func certTimeForDB(t time.Time) time.Time {
	if t.IsZero() {
		return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return t.UTC()
}

func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
