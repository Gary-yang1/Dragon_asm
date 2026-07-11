//revive:disable:exported

package report

import (
	"encoding/json"
	"time"
)

const (
	ReportTypeRisk     = "risk"
	ReportTypeTicket   = "ticket"
	ReportTypeExposure = "exposure"
)

const (
	ExportStatusPending   = "pending"
	ExportStatusRunning   = "running"
	ExportStatusSucceeded = "succeeded"
	ExportStatusFailed    = "failed"
	ExportStatusCancelled = "cancelled"
)

const (
	ExportFormatJSONL = "jsonl"
	ExportFormatCSV   = "csv"
)

const (
	ActionReportExportCreate   = "report.export.create"
	ActionReportExportComplete = "report.export.complete"
	ActionReportExportFail     = "report.export.fail"
	ResourceTypeReportExport   = "report_export"
)

type Dashboard struct {
	Risk     RiskDashboard     `json:"risk"`
	Ticket   TicketDashboard   `json:"ticket"`
	Exposure ExposureDashboard `json:"exposure"`
}

type RiskDashboard struct {
	Total    int64 `json:"total"`
	Open     int64 `json:"open"`
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Overdue  int64 `json:"overdue"`
	Fixed    int64 `json:"fixed"`
}

type TicketDashboard struct {
	Total   int64 `json:"total"`
	Open    int64 `json:"open"`
	Overdue int64 `json:"overdue"`
	Closed  int64 `json:"closed"`
}

type ExposureDashboard struct {
	Total         int64 `json:"total"`
	Ports         int64 `json:"ports"`
	Web           int64 `json:"web"`
	ExpiringCerts int64 `json:"expiring_certs"`
}

type TrendPoint struct {
	Day   time.Time `json:"day"`
	New   int64     `json:"new"`
	Fixed int64     `json:"fixed"`
}

type TopRiskItem struct {
	Key       string `json:"key"`
	AssetID   uint64 `json:"asset_id,omitempty"`
	Count     int64  `json:"count"`
	MaxScore  int64  `json:"max_score"`
	Dimension string `json:"dimension"`
}

type RemediationStats struct {
	TotalRisks     int64   `json:"total_risks"`
	FixedRisks     int64   `json:"fixed_risks"`
	SLAMetRisks    int64   `json:"sla_met_risks"`
	SLAHitRate     float64 `json:"sla_hit_rate"`
	MTTRHours      float64 `json:"mttr_hours"`
	Age0To7        int64   `json:"age_0_7"`
	Age8To30       int64   `json:"age_8_30"`
	AgeOver30      int64   `json:"age_over_30"`
	ReopenedRisks  int64   `json:"reopened_risks"`
	RecurrenceRate float64 `json:"recurrence_rate"`
}

type ExportJob struct {
	ID           uint64
	TenantID     string
	OrgID        string
	ProjectID    uint64
	ReportType   string
	Status       string
	Format       string
	Fields       []string
	Filters      json.RawMessage
	Redacted     bool
	RowCount     uint64
	FilePath     string
	ErrorMessage string
	RequestedBy  string
	StartedAt    time.Time
	FinishedAt   time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type ExportRequest struct {
	TenantID   string
	OrgID      string
	ProjectID  uint64
	ReportType string
	Format     string
	Fields     []string
	Filters    json.RawMessage
	CanExport  bool
	ActorID    string
	RequestID  string
	IP         string
	UserAgent  string
}
