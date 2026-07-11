package exposure

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/notification"
)

type fakeRepo struct {
	rows   map[string]*Exposure
	events []ChangeEventParams
	nextID uint64
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{rows: make(map[string]*Exposure), nextID: 1}
}

func (f *fakeRepo) GetByKey(_ context.Context, projectID uint64, exposureKey string) (*Exposure, error) {
	row := f.rows[key(projectID, exposureKey)]
	if row == nil {
		return nil, ErrNotFound
	}
	cp := *row
	return &cp, nil
}

func (f *fakeRepo) GetByID(_ context.Context, projectID, id uint64) (*Exposure, error) {
	for _, row := range f.rows {
		if row.ProjectID == projectID && row.ID == id {
			cp := *row
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (f *fakeRepo) List(_ context.Context, projectID uint64, limit, offset int32) ([]*Exposure, error) {
	var rows []*Exposure
	for _, row := range f.rows {
		if row.ProjectID == projectID {
			cp := *row
			rows = append(rows, &cp)
		}
	}
	if offset >= int32(len(rows)) {
		return nil, nil
	}
	end := offset + limit
	if end > int32(len(rows)) {
		end = int32(len(rows))
	}
	return rows[offset:end], nil
}

func (f *fakeRepo) Count(_ context.Context, projectID uint64) (int64, error) {
	var n int64
	for _, row := range f.rows {
		if row.ProjectID == projectID {
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) Upsert(_ context.Context, in UpsertParams) error {
	k := key(in.ProjectID, in.ExposureKey)
	id := f.nextID
	if existing := f.rows[k]; existing != nil {
		id = existing.ID
	} else {
		f.nextID++
	}
	f.rows[k] = &Exposure{
		ID:            id,
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
		CPE:           in.CPE,
		URL:           in.URL,
		Fingerprint:   in.Fingerprint,
		CertSubject:   in.CertSubject,
		CertIssuer:    in.CertIssuer,
		CertSerial:    in.CertSerial,
		CertNotBefore: in.CertNotBefore,
		CertNotAfter:  in.CertNotAfter,
		CertSANs:      in.CertSANs,
		EvidenceHash:  in.EvidenceHash,
		Source:        in.Source,
		Confidence:    in.Confidence,
	}
	return nil
}

func (f *fakeRepo) InsertChangeEvent(_ context.Context, in ChangeEventParams) error {
	f.events = append(f.events, in)
	return nil
}

func TestIngestCreatesChangeEventForNewExposure(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)

	res, err := svc.Ingest(context.Background(), IngestInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 2,
		ExposureType: TypePort, Protocol: "TCP", Port: 443, Source: "engine",
	})
	require.NoError(t, err)
	require.True(t, res.Changed)
	assert.Equal(t, ChangeTypeNew, res.ChangeType)
	require.Len(t, repo.events, 1)
	assert.Equal(t, EntityTypeExposure, repo.events[0].EntityType)
	assert.Equal(t, "tcp", res.Exposure.Protocol)
}

func TestIngestDoesNotCreateEventWhenUnchanged(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	input := IngestInput{TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 2, ExposureType: TypePort, Protocol: "tcp", Port: 443}

	_, err := svc.Ingest(context.Background(), input)
	require.NoError(t, err)
	res, err := svc.Ingest(context.Background(), input)
	require.NoError(t, err)

	assert.False(t, res.Changed)
	require.Len(t, repo.events, 1)
}

func TestIngestCreatesModifiedEventWhenSnapshotChanges(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	input := IngestInput{TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 2, ExposureType: TypeService, Protocol: "tcp", Port: 443, Service: "nginx", Version: "1.0"}

	_, err := svc.Ingest(context.Background(), input)
	require.NoError(t, err)
	input.Version = "1.1"
	res, err := svc.Ingest(context.Background(), input)
	require.NoError(t, err)

	assert.True(t, res.Changed)
	assert.Equal(t, ChangeTypeModified, res.ChangeType)
	require.Len(t, repo.events, 2)
	assert.Equal(t, ChangeTypeModified, repo.events[1].ChangeType)
}

func TestIngestNormalizesServiceCPE(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)

	res, err := svc.Ingest(context.Background(), IngestInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 2,
		ExposureType: TypeService, Protocol: "tcp", Port: 443, Service: "OpenResty", Version: "1.25.3.1",
	})
	require.NoError(t, err)
	assert.Equal(t, "cpe:2.3:a:*:openresty:1.25.3.1:*:*:*:*:*:*:*", res.Exposure.CPE)
}

func TestIngestCertificateExpiredCreatesCriticalEvent(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	repo := newFakeRepo()
	svc := NewService(repo)

	res, err := svc.Ingest(context.Background(), IngestInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 2,
		ExposureType:  TypeCertificate,
		Fingerprint:   "abc123",
		CertSubject:   "www.example.com",
		CertIssuer:    "Example CA",
		CertSerial:    "01",
		CertNotBefore: now.Add(-365 * 24 * time.Hour),
		CertNotAfter:  now.Add(-time.Hour),
		CertSANs:      []string{"WWW.EXAMPLE.COM", "api.example.com", "www.example.com"},
		DetectedAt:    now,
	})
	require.NoError(t, err)
	assert.Equal(t, "www.example.com", res.Exposure.CertSubject)
	assert.Equal(t, []string{"api.example.com", "www.example.com"}, res.Exposure.CertSANs)
	require.Len(t, repo.events, 1)
	assert.Equal(t, "certificate", repo.events[0].EntityType)
	assert.Equal(t, SeverityCritical, repo.events[0].Severity)
	assert.Equal(t, "Certificate expired", repo.events[0].Title)
}

func TestIngestCertificateExpiringCreatesHighEvent(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	repo := newFakeRepo()
	risks := &fakeCertificateRiskReporter{result: CertificateRiskResult{RiskID: 99, Outcome: "new"}}
	notifier := &fakeNotificationTrigger{}
	svc := NewService(repo, WithCertificateRiskReporter(risks), WithNotificationTrigger(notifier))

	res, err := svc.Ingest(context.Background(), IngestInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 2,
		ExposureType: TypeCertificate,
		Fingerprint:  "abc123",
		CertSubject:  "www.example.com",
		CertIssuer:   "Example CA",
		CertSerial:   "01",
		CertNotAfter: now.Add(15 * 24 * time.Hour),
		DetectedAt:   now,
	})
	require.NoError(t, err)
	assert.Equal(t, string(certificateStateExpiring), res.CertificateState)
	assert.Equal(t, uint64(99), res.RiskID)
	assert.True(t, res.NotificationSent)
	require.Len(t, repo.events, 1)
	assert.Equal(t, "certificate", repo.events[0].EntityType)
	assert.Equal(t, SeverityHigh, repo.events[0].Severity)
	assert.Equal(t, "Certificate expiring soon", repo.events[0].Title)
	require.Len(t, risks.findings, 1)
	assert.Equal(t, "www.example.com", risks.findings[0].CertSubject)
	require.Len(t, notifier.inputs, 1)
	assert.Equal(t, notification.TriggerCertExpiring, notifier.inputs[0].Trigger)
	assert.Equal(t, SeverityHigh, notifier.inputs[0].Severity)
}

func TestListAndGetAreProjectScoped(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	one, err := svc.Ingest(context.Background(), IngestInput{TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 2, ExposureType: TypePort, Protocol: "tcp", Port: 443})
	require.NoError(t, err)
	_, err = svc.Ingest(context.Background(), IngestInput{TenantID: "t1", OrgID: "o1", ProjectID: 2, AssetID: 3, ExposureType: TypePort, Protocol: "tcp", Port: 443})
	require.NoError(t, err)

	rows, err := svc.List(context.Background(), 1, 50, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, uint64(1), rows[0].ProjectID)
	count, err := svc.Count(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
	got, err := svc.GetByID(context.Background(), 1, one.Exposure.ID)
	require.NoError(t, err)
	assert.Equal(t, one.Exposure.ID, got.ID)
	_, err = svc.GetByID(context.Background(), 2, one.Exposure.ID)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestIngestValidatesInput(t *testing.T) {
	_, err := NewService(newFakeRepo()).Ingest(context.Background(), IngestInput{ProjectID: 1, AssetID: 2, ExposureType: "bad"})
	require.ErrorIs(t, err, ErrInvalidType)

	_, err = NewService(newFakeRepo()).Ingest(context.Background(), IngestInput{ProjectID: 1, AssetID: 2, ExposureType: TypePort, Port: 70000})
	require.ErrorIs(t, err, ErrInvalidPort)

	_, err = NewService(newFakeRepo()).Ingest(context.Background(), IngestInput{ProjectID: 1, AssetID: 2, ExposureType: TypeWeb, URL: "://bad"})
	require.ErrorIs(t, err, ErrInvalidURL)
}

func key(projectID uint64, exposureKey string) string {
	return fmt.Sprintf("%d:%s", projectID, exposureKey)
}

type fakeCertificateRiskReporter struct {
	findings []CertificateFinding
	result   CertificateRiskResult
}

func (f *fakeCertificateRiskReporter) ReportCertificateFinding(_ context.Context, finding CertificateFinding) (CertificateRiskResult, error) {
	f.findings = append(f.findings, finding)
	return f.result, nil
}

type fakeNotificationTrigger struct {
	inputs []notification.TriggerInput
}

func (f *fakeNotificationTrigger) Trigger(_ context.Context, in notification.TriggerInput) (notification.TriggerResult, error) {
	f.inputs = append(f.inputs, in)
	var payload map[string]any
	_ = json.Unmarshal(in.Payload, &payload)
	if payload["state"] == "" {
		return notification.TriggerResult{}, fmt.Errorf("missing state payload")
	}
	return notification.TriggerResult{Sent: 1}, nil
}
