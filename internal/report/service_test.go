package report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

func TestCreateExportRedactsWithoutExportPermission(t *testing.T) {
	repo := newFakeRepo()
	audits := &fakeAudit{}
	enq := &fakeEnqueuer{}
	svc := NewService(repo, WithAuditSink(audits), WithExportEnqueuer(enq))

	job, err := svc.CreateExport(context.Background(), ExportRequest{
		ProjectID: 1, ReportType: ReportTypeRisk, ActorID: "u1",
		Fields: []string{"id", "owner", "evidence_summary"}, CanExport: false,
	})
	if err == nil {
		t.Fatalf("expected restricted field error, got job %#v", job)
	}

	job, err = svc.CreateExport(context.Background(), ExportRequest{
		ProjectID: 1, ReportType: ReportTypeRisk, ActorID: "u1",
		Fields: []string{"id", "owner", "severity"}, CanExport: false,
	})
	if err != nil {
		t.Fatalf("CreateExport: %v", err)
	}
	if !job.Redacted {
		t.Fatalf("expected redacted export")
	}
	if enq.count != 1 {
		t.Fatalf("expected enqueue, got %d", enq.count)
	}
	if len(audits.events) != 1 || audits.events[0].Action != ActionReportExportCreate {
		t.Fatalf("missing create audit: %#v", audits.events)
	}
}

func TestCreateExportAllowsFullFieldsWithExportPermission(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)

	job, err := svc.CreateExport(context.Background(), ExportRequest{
		ProjectID: 1, ReportType: ReportTypeRisk, ActorID: "u1",
		Fields: []string{"id", "evidence_summary", "evidence_ref"}, CanExport: true,
	})
	if err != nil {
		t.Fatalf("CreateExport: %v", err)
	}
	if job.Redacted {
		t.Fatalf("expected unredacted export")
	}
	if len(job.Fields) != 3 {
		t.Fatalf("fields not preserved: %#v", job.Fields)
	}
}

func TestProcessNextExportWritesRedactedJSONL(t *testing.T) {
	repo := newFakeRepo()
	repo.riskRows = []map[string]any{
		{"id": uint64(1), "owner": "alice", "severity": "critical", "evidence_summary": "secret detail"},
	}
	dir := t.TempDir()
	svc := NewService(repo, WithExportDir(dir), WithNow(func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) }))
	_, err := svc.CreateExport(context.Background(), ExportRequest{
		ProjectID: 1, ReportType: ReportTypeRisk, ActorID: "u1",
		Fields: []string{"id", "owner", "severity"}, CanExport: false,
	})
	if err != nil {
		t.Fatalf("CreateExport: %v", err)
	}

	job, err := svc.ProcessNextExport(context.Background())
	if err != nil {
		t.Fatalf("ProcessNextExport: %v", err)
	}
	if job.Status != ExportStatusSucceeded || job.RowCount != 1 {
		t.Fatalf("unexpected job: %#v", job)
	}
	data, err := os.ReadFile(filepath.Clean(job.FilePath))
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if !strings.Contains(string(data), `"[REDACTED]"`) || strings.Contains(string(data), "alice") {
		t.Fatalf("export not redacted: %s", data)
	}
}

func TestRemediationRates(t *testing.T) {
	repo := newFakeRepo()
	repo.remediation = &RemediationStats{TotalRisks: 10, FixedRisks: 4, SLAMetRisks: 3, ReopenedRisks: 1}
	svc := NewService(repo)
	stats, err := svc.Remediation(context.Background(), 1)
	if err != nil {
		t.Fatalf("Remediation: %v", err)
	}
	if stats.FixedRisks != 4 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

type fakeRepo struct {
	exports     []*ExportJob
	riskRows    []map[string]any
	remediation *RemediationStats
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{remediation: &RemediationStats{}}
}

func (f *fakeRepo) Dashboard(context.Context, uint64, time.Time) (*Dashboard, error) {
	return &Dashboard{}, nil
}

func (f *fakeRepo) Trend(context.Context, uint64, time.Time, time.Time) ([]TrendPoint, error) {
	return nil, nil
}

func (f *fakeRepo) TopAssets(context.Context, uint64, int32) ([]TopRiskItem, error) {
	return nil, nil
}

func (f *fakeRepo) TopBusinessUnits(context.Context, uint64, int32) ([]TopRiskItem, error) {
	return nil, nil
}

func (f *fakeRepo) Remediation(context.Context, uint64, time.Time) (*RemediationStats, error) {
	return f.remediation, nil
}

func (f *fakeRepo) CreateExport(_ context.Context, in CreateExportParams) (uint64, error) {
	id := uint64(len(f.exports) + 1)
	f.exports = append(f.exports, &ExportJob{
		ID: id, ProjectID: in.ProjectID, ReportType: in.ReportType, Status: ExportStatusPending,
		Format: in.Format, Fields: in.Fields, Filters: in.Filters, Redacted: in.Redacted, RequestedBy: in.ActorID,
	})
	return id, nil
}

func (f *fakeRepo) GetExport(_ context.Context, projectID, id uint64) (*ExportJob, error) {
	for _, job := range f.exports {
		if job.ProjectID == projectID && job.ID == id {
			cp := *job
			cp.Fields = append([]string(nil), job.Fields...)
			if len(cp.Filters) == 0 {
				cp.Filters = json.RawMessage(`{}`)
			}
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (f *fakeRepo) ListExports(context.Context, uint64, int32, int32) ([]*ExportJob, error) {
	return f.exports, nil
}

func (f *fakeRepo) CountExports(context.Context, uint64) (int64, error) {
	return int64(len(f.exports)), nil
}

func (f *fakeRepo) ClaimPendingExport(context.Context) (*ExportJob, error) {
	for _, job := range f.exports {
		if job.Status == ExportStatusPending {
			return job, nil
		}
	}
	return nil, ErrNotFound
}

func (f *fakeRepo) MarkExportRunning(_ context.Context, projectID, id uint64, at time.Time) error {
	job, err := f.find(projectID, id)
	if err != nil {
		return err
	}
	job.Status = ExportStatusRunning
	job.StartedAt = at
	return nil
}

func (f *fakeRepo) MarkExportSucceeded(_ context.Context, projectID, id, rowCount uint64, path string, at time.Time) error {
	job, err := f.find(projectID, id)
	if err != nil {
		return err
	}
	job.Status = ExportStatusSucceeded
	job.RowCount = rowCount
	job.FilePath = path
	job.FinishedAt = at
	return nil
}

func (f *fakeRepo) MarkExportFailed(_ context.Context, projectID, id uint64, message string, at time.Time) error {
	job, err := f.find(projectID, id)
	if err != nil {
		return err
	}
	job.Status = ExportStatusFailed
	job.ErrorMessage = message
	job.FinishedAt = at
	return nil
}

func (f *fakeRepo) ListRiskRows(_ context.Context, _ uint64, limit, offset int32) ([]map[string]any, error) {
	if offset >= int32(len(f.riskRows)) {
		return nil, nil
	}
	end := offset + limit
	if end > int32(len(f.riskRows)) {
		end = int32(len(f.riskRows))
	}
	return f.riskRows[offset:end], nil
}

func (f *fakeRepo) ListTicketRows(context.Context, uint64, int32, int32) ([]map[string]any, error) {
	return nil, nil
}

func (f *fakeRepo) ListExposureRows(context.Context, uint64, int32, int32) ([]map[string]any, error) {
	return nil, nil
}

func (f *fakeRepo) find(projectID, id uint64) (*ExportJob, error) {
	for _, job := range f.exports {
		if job.ProjectID == projectID && job.ID == id {
			return job, nil
		}
	}
	return nil, ErrNotFound
}

type fakeAudit struct {
	events []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) error {
	f.events = append(f.events, e)
	return nil
}

type fakeEnqueuer struct {
	count int
}

func (f *fakeEnqueuer) EnqueueReportExport(context.Context, uint64) error {
	f.count++
	return nil
}
