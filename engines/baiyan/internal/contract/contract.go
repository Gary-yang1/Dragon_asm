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
	ConfigurationVersion uint64         `json:"configuration_version,omitempty"`
	SchemaVersion        string         `json:"schema_version"`
	RunID                uint64         `json:"run_id"`
	ProjectID            uint64         `json:"project_id"`
	ScopeID              uint64         `json:"scope_id"`
	JobType              string         `json:"job_type"`
	Targets              []Target       `json:"targets"`
	RateLimit            int            `json:"rate_limit"`
	Concurrency          int            `json:"concurrency"`
	TimeoutSeconds       int            `json:"timeout_seconds"`
	CallbackURL          string         `json:"callback_url"`
	Options              map[string]any `json:"options"`
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
	// Name is a human label such as a crawled page title; ASM falls back to Value.
	Name        string `json:"name,omitempty"`
	Value       string `json:"value"`
	Protocol    string `json:"protocol,omitempty"`
	Port        uint32 `json:"port,omitempty"`
	Service     string `json:"service,omitempty"`
	Version     string `json:"version,omitempty"`
	URL         string `json:"url,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// OrganizationFact is one legal entity discovered while mapping a company.
//
// Enterprise registry data is the start of the discovery chain in China: a
// company name yields subsidiaries and branches, those yield ICP filings, and
// filings yield the root domains everything else is built on. ASM stores these
// in project_subject, which until now could only be filled in by hand.
type OrganizationFact struct {
	FactMeta
	// Name is the registered legal name. It is the identity operators recognise.
	Name string `json:"name"`
	// SubjectType is company / government / institution / individual / other.
	SubjectType string `json:"subject_type"`
	// RegistrationCode is the unified social credit code where the source has it.
	RegistrationCode string `json:"registration_code,omitempty"`
	// Parent references the organization this one was reached through, so the
	// equity chain survives into ASM instead of collapsing into a flat list.
	Parent FactReference `json:"parent,omitempty"`
	// EquityRatio is the parent's stake, 0-100, when the source reports one.
	EquityRatio float64 `json:"equity_ratio,omitempty"`
	// Relation is how this entity hangs off its parent: invest / branch / hold.
	Relation string `json:"relation,omitempty"`
}

// FilingFact is one ICP filing and the domains registered under it.
//
// The filing is what ties a domain to a legal entity, which is the closest thing
// to documentary evidence that a domain belongs to the customer.
type FilingFact struct {
	FactMeta
	// Organization references the OrganizationFact holding this filing.
	Organization FactReference `json:"organization"`
	// FilingNo is the 备案号, e.g. "京ICP备12345678号-1".
	FilingNo string `json:"filing_no"`
	// FilingType is filing or license.
	FilingType string `json:"filing_type"`
	// WebsiteName is the registered site name, kept as human-readable evidence.
	WebsiteName string `json:"website_name,omitempty"`
	// Domains are the registrable domains covered by this filing.
	Domains []string `json:"domains,omitempty"`
}

type ProviderError struct {
	Provider  string `json:"provider"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// StageProgress is an absolute snapshot for one source or DNS stage, not a delta.
type StageProgress struct {
	Stage      string `json:"stage"`
	Provider   string `json:"provider"`
	Target     string `json:"target"`
	Status     string `json:"status"`
	Discovered int    `json:"discovered"`
	Completed  int    `json:"completed"`
	Total      int    `json:"total"`
	Failed     int    `json:"failed"`
	NoRecords  int    `json:"no_records"`
	Message    string `json:"message,omitempty"`
}

type CallbackBatch struct {
	StageProgress *StageProgress `json:"stage_progress,omitempty"`
	SchemaVersion string         `json:"schema_version"`
	RunID         uint64         `json:"run_id"`
	Seq           uint64         `json:"seq"`
	Phase         string         `json:"phase"`
	Status        string         `json:"status"`
	ResultCount   uint64         `json:"result_count"`
	ObservedAt    time.Time      `json:"observed_at"`
	Assets        []AssetFact    `json:"assets"`
	Relations     []RelationFact `json:"relations"`
	Exposures     []ExposureFact `json:"exposures"`
	// Organizations and Filings are omitted entirely by engines that do not
	// collect enterprise data, so an older engine stays wire-compatible.
	Organizations  []OrganizationFact `json:"organizations,omitempty"`
	Filings        []FilingFact       `json:"filings,omitempty"`
	ProviderErrors []ProviderError    `json:"provider_errors"`
	ErrorSummary   string             `json:"error_summary"`
}

func (b CallbackBatch) FactCount() int {
	return len(b.Assets) + len(b.Relations) + len(b.Exposures) +
		len(b.Organizations) + len(b.Filings)
}
