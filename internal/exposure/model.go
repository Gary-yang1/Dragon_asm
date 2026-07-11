//revive:disable:exported

package exposure

import "time"

const (
	TypePort        = "port"
	TypeService     = "service"
	TypeWeb         = "web"
	TypeCertificate = "certificate"
	TypeCloudConfig = "cloud_config"
)

const (
	EntityTypeExposure = "exposure"

	ChangeTypeNew      = "new"
	ChangeTypeModified = "modified"

	SeverityInfo     = "info"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

type Exposure struct {
	ID            uint64
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
	FirstSeen     time.Time
	LastSeen      time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
	CreatedBy     string
	UpdatedBy     string
}

type IngestInput struct {
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
	DetectedAt    time.Time
}

type IngestResult struct {
	Exposure         *Exposure
	ChangeType       string
	Changed          bool
	CertificateState string
	RiskID           uint64
	RiskOutcome      string
	NotificationSent bool
}

type CertificateFinding struct {
	TenantID        string
	OrgID           string
	ProjectID       uint64
	AssetID         uint64
	ExposureID      uint64
	ExposureKey     string
	CertSubject     string
	CertIssuer      string
	CertSerial      string
	Fingerprint     string
	CertNotBefore   time.Time
	CertNotAfter    time.Time
	CertSANs        []string
	State           string
	Source          string
	ObservedAt      time.Time
	ActorID         string
	BusinessUnit    string
	Owner           string
	EvidenceSummary string
}

type CertificateRiskResult struct {
	RiskID  uint64
	Outcome string
}
