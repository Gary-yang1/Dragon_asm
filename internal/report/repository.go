//revive:disable:exported

package report

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var ErrNotFound = errors.New("report: not found")

type Repository interface {
	Dashboard(ctx context.Context, projectID uint64, now time.Time) (*Dashboard, error)
	Trend(ctx context.Context, projectID uint64, from, to time.Time) ([]TrendPoint, error)
	TopAssets(ctx context.Context, projectID uint64, limit int32) ([]TopRiskItem, error)
	TopBusinessUnits(ctx context.Context, projectID uint64, limit int32) ([]TopRiskItem, error)
	Remediation(ctx context.Context, projectID uint64, now time.Time) (*RemediationStats, error)
	CreateExport(ctx context.Context, in CreateExportParams) (uint64, error)
	GetExport(ctx context.Context, projectID, id uint64) (*ExportJob, error)
	ListExports(ctx context.Context, projectID uint64, limit, offset int32) ([]*ExportJob, error)
	CountExports(ctx context.Context, projectID uint64) (int64, error)
	ClaimPendingExport(ctx context.Context) (*ExportJob, error)
	MarkExportRunning(ctx context.Context, projectID, id uint64, at time.Time) error
	MarkExportSucceeded(ctx context.Context, projectID, id, rowCount uint64, path string, at time.Time) error
	MarkExportFailed(ctx context.Context, projectID, id uint64, message string, at time.Time) error
	ListRiskRows(ctx context.Context, projectID uint64, limit, offset int32) ([]map[string]any, error)
	ListTicketRows(ctx context.Context, projectID uint64, limit, offset int32) ([]map[string]any, error)
	ListExposureRows(ctx context.Context, projectID uint64, limit, offset int32) ([]map[string]any, error)
}

type CreateExportParams struct {
	TenantID   string
	OrgID      string
	ProjectID  uint64
	ReportType string
	Format     string
	Fields     []string
	Filters    json.RawMessage
	Redacted   bool
	ActorID    string
}

type sqlcRepository struct {
	q *dbgen.Queries
}

func NewRepository(q *dbgen.Queries) Repository {
	return &sqlcRepository{q: q}
}

func (r *sqlcRepository) Dashboard(ctx context.Context, projectID uint64, now time.Time) (*Dashboard, error) {
	riskRow, err := r.q.ReportRiskDashboard(ctx, dbgen.ReportRiskDashboardParams{ProjectID: projectID, SlaDueAt: now})
	if err != nil {
		return nil, err
	}
	ticketRow, err := r.q.ReportTicketDashboard(ctx, dbgen.ReportTicketDashboardParams{ProjectID: projectID, DueAt: now})
	if err != nil {
		return nil, err
	}
	exposureRow, err := r.q.ReportExposureDashboard(ctx, dbgen.ReportExposureDashboardParams{ProjectID: projectID, CertNotAfter: now.Add(30 * 24 * time.Hour)})
	if err != nil {
		return nil, err
	}
	return &Dashboard{
		Risk: RiskDashboard{
			Total: riskRow.TotalRisks, Open: toInt64(riskRow.OpenRisks),
			Critical: toInt64(riskRow.CriticalRisks), High: toInt64(riskRow.HighRisks),
			Overdue: toInt64(riskRow.OverdueRisks), Fixed: toInt64(riskRow.FixedRisks),
		},
		Ticket: TicketDashboard{
			Total: ticketRow.TotalTickets, Open: toInt64(ticketRow.OpenTickets),
			Overdue: toInt64(ticketRow.OverdueTickets), Closed: toInt64(ticketRow.ClosedTickets),
		},
		Exposure: ExposureDashboard{
			Total: exposureRow.TotalExposures, Ports: toInt64(exposureRow.PortExposures),
			Web: toInt64(exposureRow.WebExposures), ExpiringCerts: toInt64(exposureRow.ExpiringCerts),
		},
	}, nil
}

func (r *sqlcRepository) Trend(ctx context.Context, projectID uint64, from, to time.Time) ([]TrendPoint, error) {
	newRows, err := r.q.ReportRiskTrend(ctx, dbgen.ReportRiskTrendParams{ProjectID: projectID, FirstSeen: from, FirstSeen_2: to})
	if err != nil {
		return nil, err
	}
	fixedRows, err := r.q.ReportFixedRiskTrend(ctx, dbgen.ReportFixedRiskTrendParams{ProjectID: projectID, FixedAt: from, FixedAt_2: to})
	if err != nil {
		return nil, err
	}
	byDay := map[string]*TrendPoint{}
	for _, row := range newRows {
		key := row.Day.Format("2006-01-02")
		byDay[key] = &TrendPoint{Day: row.Day, New: row.NewRisks}
	}
	for _, row := range fixedRows {
		key := row.Day.Format("2006-01-02")
		p, ok := byDay[key]
		if !ok {
			p = &TrendPoint{Day: row.Day}
			byDay[key] = p
		}
		p.Fixed = row.FixedRisks
	}
	out := make([]TrendPoint, 0, len(byDay))
	for d := from; d.Before(to); d = d.AddDate(0, 0, 1) {
		key := d.Format("2006-01-02")
		if p, ok := byDay[key]; ok {
			out = append(out, *p)
		}
	}
	return out, nil
}

func (r *sqlcRepository) TopAssets(ctx context.Context, projectID uint64, limit int32) ([]TopRiskItem, error) {
	rows, err := r.q.ReportTopAssetsByRisk(ctx, dbgen.ReportTopAssetsByRiskParams{ProjectID: projectID, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]TopRiskItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, TopRiskItem{Key: strconv.FormatUint(row.AssetID, 10), AssetID: row.AssetID, Count: row.RiskCount, MaxScore: toInt64(row.MaxScore), Dimension: "asset"})
	}
	return out, nil
}

func (r *sqlcRepository) TopBusinessUnits(ctx context.Context, projectID uint64, limit int32) ([]TopRiskItem, error) {
	rows, err := r.q.ReportTopBusinessUnitsByRisk(ctx, dbgen.ReportTopBusinessUnitsByRiskParams{ProjectID: projectID, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]TopRiskItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, TopRiskItem{Key: row.BusinessUnit, Count: row.RiskCount, MaxScore: toInt64(row.MaxScore), Dimension: "business_unit"})
	}
	return out, nil
}

func (r *sqlcRepository) Remediation(ctx context.Context, projectID uint64, now time.Time) (*RemediationStats, error) {
	row, err := r.q.ReportRemediationStats(ctx, dbgen.ReportRemediationStatsParams{
		TIMESTAMPDIFF: now, TIMESTAMPDIFF_2: now, TIMESTAMPDIFF_3: now, ProjectID: projectID,
	})
	if err != nil {
		return nil, err
	}
	fixed := toInt64(row.FixedRisks)
	slaMet := toInt64(row.SlaMetRisks)
	reopened := toInt64(row.ReopenedRisks)
	stats := &RemediationStats{
		TotalRisks: row.TotalRisks, FixedRisks: fixed, SLAMetRisks: slaMet,
		MTTRHours: toFloat64(row.MttrHours), Age0To7: toInt64(row.Age07),
		Age8To30: toInt64(row.Age830), AgeOver30: toInt64(row.AgeOver30), ReopenedRisks: reopened,
	}
	if fixed > 0 {
		stats.SLAHitRate = float64(slaMet) / float64(fixed)
		stats.RecurrenceRate = float64(reopened) / float64(fixed)
	}
	return stats, nil
}

func (r *sqlcRepository) CreateExport(ctx context.Context, in CreateExportParams) (uint64, error) {
	fields, err := json.Marshal(in.Fields)
	if err != nil {
		return 0, err
	}
	if len(in.Filters) == 0 {
		in.Filters = json.RawMessage(`{}`)
	}
	res, err := r.q.CreateReportExport(ctx, dbgen.CreateReportExportParams{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		ReportType: in.ReportType, Format: dbgen.ReportExportFormat(in.Format),
		FieldsJson: fields, FiltersJson: in.Filters, Redacted: in.Redacted, RequestedBy: in.ActorID,
	})
	if err != nil {
		return 0, err
	}
	return resultID(res)
}

func (r *sqlcRepository) GetExport(ctx context.Context, projectID, id uint64) (*ExportJob, error) {
	row, err := r.q.GetReportExportByID(ctx, dbgen.GetReportExportByIDParams{ID: id, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toExport(row), nil
}

func (r *sqlcRepository) ListExports(ctx context.Context, projectID uint64, limit, offset int32) ([]*ExportJob, error) {
	rows, err := r.q.ListReportExports(ctx, dbgen.ListReportExportsParams{ProjectID: projectID, Limit: limit, Offset: offset})
	if err != nil {
		return nil, err
	}
	out := make([]*ExportJob, 0, len(rows))
	for _, row := range rows {
		out = append(out, toExport(row))
	}
	return out, nil
}

func (r *sqlcRepository) CountExports(ctx context.Context, projectID uint64) (int64, error) {
	return r.q.CountReportExports(ctx, projectID)
}

func (r *sqlcRepository) ClaimPendingExport(ctx context.Context) (*ExportJob, error) {
	row, err := r.q.ClaimPendingReportExport(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	return toExport(row), nil
}

func (r *sqlcRepository) MarkExportRunning(ctx context.Context, projectID, id uint64, at time.Time) error {
	res, err := r.q.MarkReportExportRunning(ctx, dbgen.MarkReportExportRunningParams{ID: id, ProjectID: projectID, StartedAt: at, UpdatedAt: at})
	return rowsAffectedErr(res, err)
}

func (r *sqlcRepository) MarkExportSucceeded(ctx context.Context, projectID, id, rowCount uint64, path string, at time.Time) error {
	res, err := r.q.MarkReportExportSucceeded(ctx, dbgen.MarkReportExportSucceededParams{ID: id, ProjectID: projectID, RowCount: rowCount, FilePath: path, FinishedAt: at, UpdatedAt: at})
	return rowsAffectedErr(res, err)
}

func (r *sqlcRepository) MarkExportFailed(ctx context.Context, projectID, id uint64, message string, at time.Time) error {
	if len(message) > 512 {
		message = message[:512]
	}
	res, err := r.q.MarkReportExportFailed(ctx, dbgen.MarkReportExportFailedParams{ID: id, ProjectID: projectID, ErrorMessage: message, FinishedAt: at, UpdatedAt: at})
	return rowsAffectedErr(res, err)
}

func (r *sqlcRepository) ListRiskRows(ctx context.Context, projectID uint64, limit, offset int32) ([]map[string]any, error) {
	rows, err := r.q.ListRiskExportRows(ctx, dbgen.ListRiskExportRowsParams{ProjectID: projectID, Limit: limit, Offset: offset})
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{"id": row.ID, "asset_id": row.AssetID, "exposure_id": nullInt(row.ExposureID), "risk_key": row.RiskKey, "risk_type": row.RiskType, "title": row.Title, "severity": row.Severity, "score": row.Score, "score_level": row.ScoreLevel, "rule_id": row.RuleID, "source": row.Source, "evidence_summary": row.EvidenceSummary, "evidence_ref": row.EvidenceRef, "status": row.Status, "owner": row.Owner, "business_unit": row.BusinessUnit, "sla_due_at": row.SlaDueAt, "first_seen": row.FirstSeen, "last_seen": row.LastSeen, "fixed_at": row.FixedAt})
	}
	return out, nil
}

func (r *sqlcRepository) ListTicketRows(ctx context.Context, projectID uint64, limit, offset int32) ([]map[string]any, error) {
	rows, err := r.q.ListTicketExportRows(ctx, dbgen.ListTicketExportRowsParams{ProjectID: projectID, Limit: limit, Offset: offset})
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{"id": row.ID, "title": row.Title, "assignee": row.Assignee, "business_unit": row.BusinessUnit, "status": row.Status, "priority": row.Priority, "due_at": row.DueAt, "resolution": row.Resolution, "retest_result": row.RetestResult, "external_ticket_id": row.ExternalTicketID, "closed_at": row.ClosedAt, "created_at": row.CreatedAt, "updated_at": row.UpdatedAt})
	}
	return out, nil
}

func (r *sqlcRepository) ListExposureRows(ctx context.Context, projectID uint64, limit, offset int32) ([]map[string]any, error) {
	rows, err := r.q.ListExposureExportRows(ctx, dbgen.ListExposureExportRowsParams{ProjectID: projectID, Limit: limit, Offset: offset})
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{"id": row.ID, "asset_id": row.AssetID, "exposure_type": row.ExposureType, "exposure_key": row.ExposureKey, "name": row.Name, "value": row.Value, "protocol": row.Protocol, "port": row.Port, "service": row.Service, "version": row.Version, "cpe": row.Cpe, "url": row.Url, "fingerprint": row.Fingerprint, "cert_subject": row.CertSubject, "cert_issuer": row.CertIssuer, "cert_serial": row.CertSerial, "cert_not_after": row.CertNotAfter, "source": row.Source, "confidence": row.Confidence, "first_seen": row.FirstSeen, "last_seen": row.LastSeen})
	}
	return out, nil
}

func toExport(row dbgen.ReportExport) *ExportJob {
	var fields []string
	_ = json.Unmarshal(row.FieldsJson, &fields)
	return &ExportJob{ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID, ReportType: row.ReportType, Status: string(row.Status), Format: string(row.Format), Fields: fields, Filters: row.FiltersJson, Redacted: row.Redacted, RowCount: row.RowCount, FilePath: row.FilePath, ErrorMessage: row.ErrorMessage, RequestedBy: row.RequestedBy, StartedAt: row.StartedAt, FinishedAt: row.FinishedAt, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case nil:
		return 0
	case int64:
		return x
	case int:
		return int64(x)
	case uint64:
		if x > uint64(^uint64(0)>>1) {
			return 0
		}
		return int64(x)
	case []byte:
		n, _ := strconv.ParseInt(string(x), 10, 64)
		return n
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	default:
		return 0
	}
}

func toFloat64(v any) float64 {
	switch x := v.(type) {
	case nil:
		return 0
	case float64:
		return x
	case float32:
		return float64(x)
	case int64:
		return float64(x)
	case []byte:
		n, _ := strconv.ParseFloat(string(x), 64)
		return n
	case string:
		n, _ := strconv.ParseFloat(x, 64)
		return n
	default:
		return 0
	}
}

func nullInt(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}

func resultID(res sql.Result) (uint64, error) {
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if id < 0 {
		return 0, fmt.Errorf("report: negative insert id %d", id)
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
