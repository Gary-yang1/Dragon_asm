package contract

import "time"

const SchemaVersion = "1.0"

const (
	ProfileSubdomainPassive = "subdomain_passive"
	ProfileResolve          = "resolve"
)

type Target struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type ScanRequest struct {
	SchemaVersion  string         `json:"schema_version"`
	RunID          uint64         `json:"run_id"`
	ProjectID      uint64         `json:"project_id"`
	ScopeID        uint64         `json:"scope_id"`
	JobType        string         `json:"job_type"`
	Targets        []Target       `json:"targets"`
	RateLimit      int            `json:"rate_limit"`
	Concurrency    int            `json:"concurrency"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	CallbackURL    string         `json:"callback_url"`
	Options        map[string]any `json:"options"`
}

type JobStatus struct {
	SchemaVersion string    `json:"schema_version"`
	JobID         string    `json:"job_id"`
	RunID         uint64    `json:"run_id"`
	Status        string    `json:"status"`
	Progress      int       `json:"progress"`
	ResultCount   uint64    `json:"result_count"`
	ErrorSummary  string    `json:"error_summary"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type FactMeta struct {
	ClientRef    string    `json:"client_ref,omitempty"`
	NaturalKey   string    `json:"natural_key,omitempty"`
	Source       string    `json:"source"`
	Provider     string    `json:"provider"`
	ObservedAt   time.Time `json:"observed_at"`
	Confidence   uint8     `json:"confidence"`
	ActiveProbe  bool      `json:"active_probe"`
	EvidenceHash string    `json:"evidence_hash"`
	EvidenceRef  string    `json:"evidence_ref,omitempty"`
}

type AssetFact struct {
	FactMeta
	AssetType   string            `json:"asset_type"`
	Value       string            `json:"value"`
	DisplayName string            `json:"display_name,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

type FactReference struct {
	ClientRef  string `json:"client_ref,omitempty"`
	NaturalKey string `json:"natural_key,omitempty"`
}

type RelationFact struct {
	FactMeta
	RelationType string        `json:"relation_type"`
	From         FactReference `json:"from"`
	To           FactReference `json:"to"`
}

type ExposureFact struct {
	FactMeta
	Parent       FactReference `json:"parent"`
	ExposureType string        `json:"exposure_type"`
	Value        string        `json:"value"`
	Protocol     string        `json:"protocol,omitempty"`
	Port         uint32        `json:"port,omitempty"`
	Service      string        `json:"service,omitempty"`
	Version      string        `json:"version,omitempty"`
	URL          string        `json:"url,omitempty"`
	Fingerprint  string        `json:"fingerprint,omitempty"`
}

type ProviderError struct {
	Provider  string `json:"provider"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type CallbackBatch struct {
	SchemaVersion  string          `json:"schema_version"`
	RunID          uint64          `json:"run_id"`
	Seq            uint64          `json:"seq"`
	Phase          string          `json:"phase"`
	Status         string          `json:"status"`
	ResultCount    uint64          `json:"result_count"`
	ObservedAt     time.Time       `json:"observed_at"`
	Assets         []AssetFact     `json:"assets"`
	Relations      []RelationFact  `json:"relations"`
	Exposures      []ExposureFact  `json:"exposures"`
	ProviderErrors []ProviderError `json:"provider_errors"`
	ErrorSummary   string          `json:"error_summary"`
}

func (b CallbackBatch) FactCount() int {
	return len(b.Assets) + len(b.Relations) + len(b.Exposures)
}
