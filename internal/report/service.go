//revive:disable:exported

package report

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var (
	ErrInvalidProjectID  = errors.New("report: invalid project id")
	ErrInvalidActorID    = errors.New("report: invalid actor id")
	ErrInvalidReportType = errors.New("report: invalid report_type")
	ErrInvalidFormat     = errors.New("report: invalid format")
	ErrInvalidField      = errors.New("report: invalid field")
	ErrFieldTooLong      = errors.New("report: field too long")
)

type auditRecorder interface {
	Record(ctx context.Context, e audit.Event) error
}

type Service struct {
	repo      Repository
	db        *sql.DB
	auditSink auditRecorder
	enqueuer  ExportEnqueuer
	now       func() time.Time
	exportDir string
}

type ServiceOption func(*Service)

func WithDB(db *sql.DB) ServiceOption {
	return func(s *Service) { s.db = db }
}

func WithAuditSink(sink auditRecorder) ServiceOption {
	return func(s *Service) { s.auditSink = sink }
}

func WithExportEnqueuer(enqueuer ExportEnqueuer) ServiceOption {
	return func(s *Service) { s.enqueuer = enqueuer }
}

func WithNow(fn func() time.Time) ServiceOption {
	return func(s *Service) {
		if fn != nil {
			s.now = fn
		}
	}
}

func WithExportDir(dir string) ServiceOption {
	return func(s *Service) {
		if strings.TrimSpace(dir) != "" {
			s.exportDir = dir
		}
	}
}

func NewService(repo Repository, opts ...ServiceOption) *Service {
	s := &Service{repo: repo, now: func() time.Time { return time.Now().UTC() }, exportDir: "/tmp/asm-report-exports"}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Service) Dashboard(ctx context.Context, projectID uint64) (*Dashboard, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.Dashboard(ctx, projectID, s.now())
}

func (s *Service) Trend(ctx context.Context, projectID uint64, from, to time.Time) ([]TrendPoint, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if from.IsZero() {
		from = s.now().AddDate(0, 0, -30)
	}
	if to.IsZero() || !to.After(from) {
		to = s.now().AddDate(0, 0, 1)
	}
	return s.repo.Trend(ctx, projectID, startOfDay(from), startOfDay(to).AddDate(0, 0, 1))
}

func (s *Service) Top(ctx context.Context, projectID uint64, dimension string, limit int32) ([]TopRiskItem, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	switch strings.TrimSpace(dimension) {
	case "", "asset":
		return s.repo.TopAssets(ctx, projectID, limit)
	case "business_unit":
		return s.repo.TopBusinessUnits(ctx, projectID, limit)
	default:
		return nil, ErrInvalidField
	}
}

func (s *Service) Remediation(ctx context.Context, projectID uint64) (*RemediationStats, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.Remediation(ctx, projectID, s.now())
}

func (s *Service) CreateExport(ctx context.Context, in ExportRequest) (*ExportJob, error) {
	if err := normalizeExportRequest(&in); err != nil {
		return nil, err
	}
	fields, err := normalizeFields(in.ReportType, in.Fields, in.CanExport)
	if err != nil {
		return nil, err
	}
	in.Fields = fields
	in.Format = defaultString(in.Format, ExportFormatJSONL)
	redacted := !in.CanExport
	create := func(ctx context.Context, repo Repository) (uint64, error) {
		return repo.CreateExport(ctx, CreateExportParams{
			TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
			ReportType: in.ReportType, Format: in.Format, Fields: fields, Filters: in.Filters,
			Redacted: redacted, ActorID: in.ActorID,
		})
	}
	var id uint64
	if err := s.runInTx(ctx, func(ctx context.Context, repo Repository) error {
		var err error
		id, err = create(ctx, repo)
		if err != nil {
			return err
		}
		return s.audit(ctx, audit.Event{
			TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
			ActorID: in.ActorID, Action: ActionReportExportCreate,
			ResourceType: ResourceTypeReportExport, ResourceID: strconv.FormatUint(id, 10),
			IP: in.IP, UserAgent: in.UserAgent, RequestID: in.RequestID,
			Metadata: map[string]any{"report_type": in.ReportType, "format": in.Format, "fields": fields, "redacted": redacted},
		})
	}); err != nil {
		return nil, err
	}
	if s.enqueuer != nil {
		if err := s.enqueuer.EnqueueReportExport(ctx, in.ProjectID); err != nil {
			return nil, err
		}
	}
	return s.repo.GetExport(ctx, in.ProjectID, id)
}

func (s *Service) GetExport(ctx context.Context, projectID, id uint64) (*ExportJob, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.GetExport(ctx, projectID, id)
}

func (s *Service) ListExports(ctx context.Context, projectID uint64, limit, offset int32) ([]*ExportJob, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.ListExports(ctx, projectID, limit, offset)
}

func (s *Service) CountExports(ctx context.Context, projectID uint64) (int64, error) {
	if projectID == 0 {
		return 0, ErrInvalidProjectID
	}
	return s.repo.CountExports(ctx, projectID)
}

func (s *Service) ProcessNextExport(ctx context.Context) (*ExportJob, error) {
	job, err := s.repo.ClaimPendingExport(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if err := s.repo.MarkExportRunning(ctx, job.ProjectID, job.ID, now); err != nil {
		return nil, err
	}
	path, rows, err := s.writeExport(ctx, job)
	finished := s.now()
	if err != nil {
		_ = s.repo.MarkExportFailed(ctx, job.ProjectID, job.ID, err.Error(), finished)
		_ = s.audit(ctx, audit.Event{
			TenantID: job.TenantID, OrgID: job.OrgID, ProjectID: job.ProjectID, ActorID: job.RequestedBy,
			ActorType: audit.ActorSystem, Action: ActionReportExportFail, ResourceType: ResourceTypeReportExport,
			ResourceID: strconv.FormatUint(job.ID, 10), Result: audit.ResultFailure,
			Metadata: map[string]any{"report_type": job.ReportType}, ErrorMessage: err.Error(),
		})
		return nil, err
	}
	if err := s.repo.MarkExportSucceeded(ctx, job.ProjectID, job.ID, rows, path, finished); err != nil {
		return nil, err
	}
	_ = s.audit(ctx, audit.Event{
		TenantID: job.TenantID, OrgID: job.OrgID, ProjectID: job.ProjectID, ActorID: job.RequestedBy,
		ActorType: audit.ActorSystem, Action: ActionReportExportComplete, ResourceType: ResourceTypeReportExport,
		ResourceID: strconv.FormatUint(job.ID, 10), Metadata: map[string]any{"report_type": job.ReportType, "rows": rows, "path": path},
	})
	return s.repo.GetExport(ctx, job.ProjectID, job.ID)
}

func (s *Service) writeExport(ctx context.Context, job *ExportJob) (string, uint64, error) {
	if err := os.MkdirAll(s.exportDir, 0o750); err != nil {
		return "", 0, err
	}
	ext := job.Format
	if ext == "" {
		ext = ExportFormatJSONL
	}
	path := filepath.Clean(filepath.Join(s.exportDir, fmt.Sprintf("project-%d-export-%d.%s", job.ProjectID, job.ID, ext)))
	// #nosec G304 -- path is generated from the configured export directory and numeric IDs, not user input.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = file.Close() }()

	const batchSize int32 = 500
	var count uint64
	switch job.Format {
	case ExportFormatCSV:
		w := csv.NewWriter(file)
		if err := w.Write(job.Fields); err != nil {
			return "", 0, err
		}
		for offset := int32(0); ; offset += batchSize {
			rows, err := s.exportRows(ctx, job, batchSize, offset)
			if err != nil {
				return "", 0, err
			}
			if len(rows) == 0 {
				break
			}
			for _, row := range rows {
				if err := w.Write(projectCSV(row, job.Fields, job.Redacted)); err != nil {
					return "", 0, err
				}
				count++
			}
		}
		w.Flush()
		return path, count, w.Error()
	default:
		w := bufio.NewWriter(file)
		enc := json.NewEncoder(w)
		for offset := int32(0); ; offset += batchSize {
			rows, err := s.exportRows(ctx, job, batchSize, offset)
			if err != nil {
				return "", 0, err
			}
			if len(rows) == 0 {
				break
			}
			for _, row := range rows {
				if err := enc.Encode(projectRow(row, job.Fields, job.Redacted)); err != nil {
					return "", 0, err
				}
				count++
			}
		}
		return path, count, w.Flush()
	}
}

func (s *Service) exportRows(ctx context.Context, job *ExportJob, limit, offset int32) ([]map[string]any, error) {
	switch job.ReportType {
	case ReportTypeRisk:
		return s.repo.ListRiskRows(ctx, job.ProjectID, limit, offset)
	case ReportTypeTicket:
		return s.repo.ListTicketRows(ctx, job.ProjectID, limit, offset)
	case ReportTypeExposure:
		return s.repo.ListExposureRows(ctx, job.ProjectID, limit, offset)
	default:
		return nil, ErrInvalidReportType
	}
}

func (s *Service) runInTx(ctx context.Context, fn func(context.Context, Repository) error) error {
	if s.db == nil {
		return fn(ctx, s.repo)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txRepo := NewRepository(dbgen.New(tx))
	if err := fn(ctx, txRepo); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Service) audit(ctx context.Context, event audit.Event) error {
	if s.auditSink == nil {
		return nil
	}
	return s.auditSink.Record(ctx, event)
}

func normalizeExportRequest(in *ExportRequest) error {
	if in.ProjectID == 0 {
		return ErrInvalidProjectID
	}
	in.ActorID = strings.TrimSpace(in.ActorID)
	if in.ActorID == "" || len(in.ActorID) > 128 {
		return ErrInvalidActorID
	}
	in.ReportType = strings.TrimSpace(strings.ToLower(in.ReportType))
	if !validReportType(in.ReportType) {
		return ErrInvalidReportType
	}
	in.Format = defaultString(strings.TrimSpace(strings.ToLower(in.Format)), ExportFormatJSONL)
	if in.Format != ExportFormatJSONL && in.Format != ExportFormatCSV {
		return ErrInvalidFormat
	}
	if len(in.Filters) == 0 {
		in.Filters = json.RawMessage(`{}`)
	}
	if len(in.Filters) > 4096 || !json.Valid(in.Filters) {
		return ErrFieldTooLong
	}
	if len(in.TenantID) > 64 || len(in.OrgID) > 64 {
		return ErrFieldTooLong
	}
	return nil
}

func normalizeFields(reportType string, requested []string, canExport bool) ([]string, error) {
	allowed := allowedFields(reportType, canExport)
	if len(requested) == 0 {
		return append([]string(nil), allowed...), nil
	}
	allowedSet := map[string]struct{}{}
	for _, f := range allowed {
		allowedSet[f] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	seen := map[string]struct{}{}
	for _, f := range requested {
		f = strings.TrimSpace(strings.ToLower(f))
		if _, ok := allowedSet[f]; !ok {
			return nil, ErrInvalidField
		}
		if _, ok := seen[f]; ok {
			continue
		}
		out = append(out, f)
		seen[f] = struct{}{}
	}
	if len(out) == 0 {
		return nil, ErrInvalidField
	}
	return out, nil
}

func allowedFields(reportType string, canExport bool) []string {
	fields := map[string][]string{
		ReportTypeRisk:     {"id", "asset_id", "risk_type", "title", "severity", "score", "score_level", "rule_id", "source", "status", "owner", "business_unit", "sla_due_at", "first_seen", "last_seen", "fixed_at"},
		ReportTypeTicket:   {"id", "title", "assignee", "business_unit", "status", "priority", "due_at", "resolution", "closed_at", "created_at", "updated_at"},
		ReportTypeExposure: {"id", "asset_id", "exposure_type", "name", "value", "protocol", "port", "service", "version", "url", "source", "confidence", "first_seen", "last_seen"},
	}
	full := map[string][]string{
		ReportTypeRisk:     {"risk_key", "exposure_id", "evidence_summary", "evidence_ref"},
		ReportTypeTicket:   {"retest_result", "external_ticket_id"},
		ReportTypeExposure: {"exposure_key", "cpe", "fingerprint", "cert_subject", "cert_issuer", "cert_serial", "cert_not_after"},
	}
	base := append([]string(nil), fields[reportType]...)
	if canExport {
		base = append(base, full[reportType]...)
	}
	return base
}

func projectRow(row map[string]any, fields []string, redacted bool) map[string]any {
	out := make(map[string]any, len(fields))
	for _, field := range fields {
		out[field] = redactedValue(field, row[field], redacted)
	}
	return out
}

func projectCSV(row map[string]any, fields []string, redacted bool) []string {
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		out = append(out, fmt.Sprint(redactedValue(field, row[field], redacted)))
	}
	return out
}

func redactedValue(field string, value any, redacted bool) any {
	if !redacted {
		return value
	}
	switch field {
	case "owner", "assignee", "evidence_summary", "evidence_ref", "external_ticket_id", "url", "value", "fingerprint", "cert_subject", "cert_issuer", "cert_serial":
		if value == nil || value == "" {
			return value
		}
		return "[REDACTED]"
	default:
		return value
	}
}

func validReportType(v string) bool {
	return v == ReportTypeRisk || v == ReportTypeTicket || v == ReportTypeExposure
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func startOfDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}
