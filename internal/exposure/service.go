//revive:disable:exported

package exposure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/notification"
)

const MaxConfidence = 100

const certificateExpiryWarningWindow = 30 * 24 * time.Hour

var (
	ErrInvalidProjectID = errors.New("exposure: invalid project id")
	ErrInvalidAssetID   = errors.New("exposure: invalid asset id")
	ErrInvalidType      = errors.New("exposure: invalid exposure_type")
	ErrInvalidPort      = errors.New("exposure: invalid port")
	ErrInvalidURL       = errors.New("exposure: invalid url")
	ErrFieldTooLong     = errors.New("exposure: field too long")
)

type Service struct {
	repo     Repository
	risks    CertificateRiskReporter
	notifier NotificationTrigger
}

type CertificateRiskReporter interface {
	ReportCertificateFinding(ctx context.Context, finding CertificateFinding) (CertificateRiskResult, error)
}

type NotificationTrigger interface {
	Trigger(ctx context.Context, in notification.TriggerInput) (notification.TriggerResult, error)
}

type ServiceOption func(*Service)

func WithCertificateRiskReporter(reporter CertificateRiskReporter) ServiceOption {
	return func(s *Service) { s.risks = reporter }
}

func WithNotificationTrigger(trigger NotificationTrigger) ServiceOption {
	return func(s *Service) { s.notifier = trigger }
}

func NewService(repo Repository, opts ...ServiceOption) *Service {
	s := &Service{repo: repo}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Service) GetByID(ctx context.Context, projectID, id uint64) (*Exposure, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.GetByID(ctx, projectID, id)
}

func (s *Service) List(ctx context.Context, projectID uint64, limit, offset int32) ([]*Exposure, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	limit = clampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	return s.repo.List(ctx, projectID, limit, offset)
}

func (s *Service) Count(ctx context.Context, projectID uint64) (int64, error) {
	if projectID == 0 {
		return 0, ErrInvalidProjectID
	}
	return s.repo.Count(ctx, projectID)
}

func (s *Service) Ingest(ctx context.Context, in IngestInput) (*IngestResult, error) {
	if in.ProjectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if in.AssetID == 0 {
		return nil, ErrInvalidAssetID
	}
	norm, err := normalize(in)
	if err != nil {
		return nil, err
	}

	before, err := s.repo.GetByKey(ctx, norm.ProjectID, norm.ExposureKey)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	isNew := errors.Is(err, ErrNotFound)
	changed := isNew || exposureChanged(before, norm)

	if err := s.repo.Upsert(ctx, UpsertParams{
		TenantID:      norm.TenantID,
		OrgID:         norm.OrgID,
		ProjectID:     norm.ProjectID,
		AssetID:       norm.AssetID,
		ExposureType:  norm.ExposureType,
		ExposureKey:   norm.ExposureKey,
		Name:          norm.Name,
		Value:         norm.Value,
		Protocol:      norm.Protocol,
		Port:          norm.Port,
		Service:       norm.Service,
		Version:       norm.Version,
		CPE:           norm.CPE,
		URL:           norm.URL,
		Fingerprint:   norm.Fingerprint,
		CertSubject:   norm.CertSubject,
		CertIssuer:    norm.CertIssuer,
		CertSerial:    norm.CertSerial,
		CertNotBefore: norm.CertNotBefore,
		CertNotAfter:  norm.CertNotAfter,
		CertSANs:      norm.CertSANs,
		EvidenceHash:  norm.EvidenceHash,
		Source:        norm.Source,
		Confidence:    norm.Confidence,
		ActorID:       norm.ActorID,
		ObservedAt:    norm.DetectedAt,
	}); err != nil {
		return nil, err
	}

	after, err := s.repo.GetByKey(ctx, norm.ProjectID, norm.ExposureKey)
	if err != nil {
		return nil, err
	}
	result := &IngestResult{Exposure: after}
	if state := certificateState(norm, norm.DetectedAt); norm.ExposureType == TypeCertificate && state != certificateStateOK {
		result.CertificateState = string(state)
		if err := s.handleCertificateFinding(ctx, norm, after, result, changed); err != nil {
			return nil, err
		}
	}
	if !changed {
		return result, nil
	}

	changeType := ChangeTypeModified
	if isNew {
		changeType = ChangeTypeNew
	}
	if err := s.repo.InsertChangeEvent(ctx, buildChangeEvent(norm, before, after, changeType)); err != nil {
		return nil, err
	}
	result.Changed = true
	result.ChangeType = changeType
	return result, nil
}

func normalize(in IngestInput) (IngestInput, error) {
	in.ExposureType = strings.TrimSpace(in.ExposureType)
	if !validType(in.ExposureType) {
		return IngestInput{}, ErrInvalidType
	}
	in.Protocol = strings.ToLower(strings.TrimSpace(in.Protocol))
	in.Source = defaultString(in.Source, "discovery")
	if in.Confidence > MaxConfidence {
		in.Confidence = MaxConfidence
	}
	if in.Confidence == 0 {
		in.Confidence = MaxConfidence
	}
	if in.DetectedAt.IsZero() {
		in.DetectedAt = time.Now().UTC()
	}
	if in.Port > 65535 {
		return IngestInput{}, ErrInvalidPort
	}
	if in.URL != "" {
		u, err := url.ParseRequestURI(strings.TrimSpace(in.URL))
		if err != nil || u.Scheme == "" || u.Host == "" {
			return IngestInput{}, ErrInvalidURL
		}
		in.URL = u.String()
	}

	in.Name = strings.TrimSpace(in.Name)
	in.Value = strings.TrimSpace(in.Value)
	in.Service = strings.TrimSpace(in.Service)
	in.Version = strings.TrimSpace(in.Version)
	in.CPE = strings.TrimSpace(in.CPE)
	if in.CPE == "" && in.ExposureType == TypeService && in.Service != "" && in.Version != "" {
		in.CPE = buildCPE(in.Service, in.Version)
	}
	in.Fingerprint = strings.TrimSpace(in.Fingerprint)
	in.CertSubject = strings.TrimSpace(in.CertSubject)
	in.CertIssuer = strings.TrimSpace(in.CertIssuer)
	in.CertSerial = strings.TrimSpace(in.CertSerial)
	in.CertSANs = normalizeSANs(in.CertSANs)
	if in.ExposureType == TypeCertificate {
		if in.Name == "" {
			in.Name = in.CertSubject
		}
		if in.Value == "" {
			in.Value = in.CertSerial
		}
	}
	in.EvidenceHash = normalizeEvidenceHash(in.EvidenceHash, in)
	if err := checkLengths(in); err != nil {
		return IngestInput{}, err
	}
	if strings.TrimSpace(in.ExposureKey) == "" {
		in.ExposureKey = buildExposureKey(in)
	}
	if len(in.ExposureKey) > 512 {
		return IngestInput{}, ErrFieldTooLong
	}
	return in, nil
}

func validType(t string) bool {
	switch t {
	case TypePort, TypeService, TypeWeb, TypeCertificate, TypeCloudConfig:
		return true
	default:
		return false
	}
}

func buildExposureKey(in IngestInput) string {
	parts := []string{in.ExposureType, strconv.FormatUint(in.AssetID, 10)}
	switch in.ExposureType {
	case TypePort:
		parts = append(parts, in.Protocol, strconv.FormatUint(uint64(in.Port), 10))
	case TypeService:
		parts = append(parts, in.Protocol, strconv.FormatUint(uint64(in.Port), 10), in.Service)
	case TypeWeb:
		parts = append(parts, in.URL)
	case TypeCertificate:
		identity := in.Fingerprint
		if identity == "" {
			identity = in.CertSerial
		}
		if identity == "" {
			identity = in.CertSubject
		}
		parts = append(parts, identity, in.CertNotAfter.UTC().Format("20060102T150405Z"))
	case TypeCloudConfig:
		parts = append(parts, in.Name, in.Value)
	}
	return strings.Join(parts, ":")
}

func normalizeEvidenceHash(v string, in IngestInput) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if len(v) == 64 {
		return v
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s",
		in.ExposureType, in.Value, in.Protocol, in.Port, in.Service, in.Version, in.URL, in.Fingerprint,
		in.CertSubject, in.CertIssuer, in.CertSerial, strings.Join(in.CertSANs, ","))))
	return hex.EncodeToString(sum[:])
}

func checkLengths(in IngestInput) error {
	for _, f := range []struct {
		v string
		n int
	}{
		{in.TenantID, 64}, {in.OrgID, 64}, {in.Name, 255}, {in.Value, 1024},
		{in.Protocol, 16}, {in.Service, 128}, {in.Version, 128}, {in.CPE, 255}, {in.URL, 1024},
		{in.Fingerprint, 255}, {in.CertSubject, 255}, {in.CertIssuer, 255}, {in.CertSerial, 128},
		{in.Source, 64}, {in.ActorID, 64},
	} {
		if len(f.v) > f.n {
			return ErrFieldTooLong
		}
	}
	return nil
}

func exposureChanged(before *Exposure, after IngestInput) bool {
	if before == nil {
		return true
	}
	return before.AssetID != after.AssetID ||
		before.Name != after.Name ||
		before.Value != after.Value ||
		before.Protocol != after.Protocol ||
		before.Port != after.Port ||
		before.Service != after.Service ||
		before.Version != after.Version ||
		before.CPE != after.CPE ||
		before.URL != after.URL ||
		before.Fingerprint != after.Fingerprint ||
		before.CertSubject != after.CertSubject ||
		before.CertIssuer != after.CertIssuer ||
		before.CertSerial != after.CertSerial ||
		!before.CertNotBefore.Equal(after.CertNotBefore) ||
		!before.CertNotAfter.Equal(after.CertNotAfter) ||
		!stringSlicesEqual(before.CertSANs, after.CertSANs) ||
		before.EvidenceHash != after.EvidenceHash
}

func buildChangeEvent(in IngestInput, before, after *Exposure, changeType string) ChangeEventParams {
	beforeJSON := exposureSnapshotJSON(before)
	afterJSON := exposureSnapshotJSON(after)
	title := "Exposure discovered"
	if changeType == ChangeTypeModified {
		title = "Exposure changed"
	}
	severity := SeverityInfo
	entityType := EntityTypeExposure
	summary := after.ExposureKey
	if in.ExposureType == TypeCertificate {
		entityType = "certificate"
		switch certificateState(in, in.DetectedAt) {
		case certificateStateExpired:
			severity = SeverityCritical
			title = "Certificate expired"
			summary = "certificate expired: " + after.ExposureKey
		case certificateStateExpiring:
			severity = SeverityHigh
			title = "Certificate expiring soon"
			summary = "certificate expiring soon: " + after.ExposureKey
		}
	}
	return ChangeEventParams{
		TenantID:   in.TenantID,
		OrgID:      in.OrgID,
		ProjectID:  in.ProjectID,
		EntityType: entityType,
		EntityID:   after.ID,
		ChangeType: changeType,
		Severity:   severity,
		Title:      title,
		Summary:    summary,
		Source:     in.Source,
		Before:     beforeJSON,
		After:      afterJSON,
		DetectedAt: in.DetectedAt,
	}
}

func (s *Service) handleCertificateFinding(ctx context.Context, in IngestInput, cert *Exposure, result *IngestResult, changed bool) error {
	finding := CertificateFinding{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		AssetID: cert.AssetID, ExposureID: cert.ID, ExposureKey: cert.ExposureKey,
		CertSubject: cert.CertSubject, CertIssuer: cert.CertIssuer, CertSerial: cert.CertSerial,
		Fingerprint: cert.Fingerprint, CertNotBefore: cert.CertNotBefore, CertNotAfter: cert.CertNotAfter,
		CertSANs: append([]string(nil), cert.CertSANs...), State: result.CertificateState,
		Source: in.Source, ObservedAt: in.DetectedAt, ActorID: in.ActorID,
		EvidenceSummary: certificateEvidenceSummary(cert, result.CertificateState, in.DetectedAt),
	}
	if s.risks != nil {
		riskResult, err := s.risks.ReportCertificateFinding(ctx, finding)
		if err != nil {
			return err
		}
		result.RiskID = riskResult.RiskID
		result.RiskOutcome = riskResult.Outcome
	}
	if s.notifier == nil {
		return nil
	}
	if !changed && result.RiskOutcome != "new" && result.RiskOutcome != "reopened" {
		return nil
	}
	payload, _ := json.Marshal(map[string]any{
		"asset_id":     cert.AssetID,
		"exposure_id":  cert.ID,
		"exposure_key": cert.ExposureKey,
		"certificate":  cert.CertSubject,
		"issuer":       cert.CertIssuer,
		"serial":       cert.CertSerial,
		"fingerprint":  cert.Fingerprint,
		"not_after":    cert.CertNotAfter,
		"state":        result.CertificateState,
		"risk_id":      result.RiskID,
		"evidence":     finding.EvidenceSummary,
	})
	severity := SeverityHigh
	if result.CertificateState == string(certificateStateExpired) {
		severity = SeverityCritical
	}
	trigger, err := s.notifier.Trigger(ctx, notification.TriggerInput{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		Trigger: notification.TriggerCertExpiring, Severity: severity,
		EntityType: "certificate", EntityID: cert.ID, AssetID: cert.AssetID, RiskID: result.RiskID,
		Subject: "Certificate expiry detected", Summary: finding.EvidenceSummary,
		DedupeKey: fmt.Sprintf("certificate:%d:%s", cert.ID, result.CertificateState),
		Payload:   payload, OccurredAt: in.DetectedAt,
	})
	if err != nil {
		return err
	}
	result.NotificationSent = trigger.Sent > 0
	return nil
}

func exposureSnapshotJSON(e *Exposure) json.RawMessage {
	if e == nil {
		return nil
	}
	raw, _ := json.Marshal(map[string]any{
		"id":              e.ID,
		"asset_id":        e.AssetID,
		"exposure_type":   e.ExposureType,
		"exposure_key":    e.ExposureKey,
		"name":            e.Name,
		"value":           e.Value,
		"protocol":        e.Protocol,
		"port":            e.Port,
		"service":         e.Service,
		"version":         e.Version,
		"cpe":             e.CPE,
		"url":             e.URL,
		"fingerprint":     e.Fingerprint,
		"cert_subject":    e.CertSubject,
		"cert_issuer":     e.CertIssuer,
		"cert_serial":     e.CertSerial,
		"cert_not_before": e.CertNotBefore,
		"cert_not_after":  e.CertNotAfter,
		"cert_sans":       e.CertSANs,
		"evidence_hash":   e.EvidenceHash,
	})
	return raw
}

func certificateEvidenceSummary(cert *Exposure, state string, now time.Time) string {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	switch state {
	case string(certificateStateExpired):
		return fmt.Sprintf("certificate %q expired at %s", cert.CertSubject, cert.CertNotAfter.UTC().Format(time.RFC3339))
	case string(certificateStateExpiring):
		days := int(cert.CertNotAfter.UTC().Sub(now.UTC()).Hours() / 24)
		if days < 0 {
			days = 0
		}
		return fmt.Sprintf("certificate %q expires at %s (%d days remaining)", cert.CertSubject, cert.CertNotAfter.UTC().Format(time.RFC3339), days)
	default:
		return fmt.Sprintf("certificate %q is valid until %s", cert.CertSubject, cert.CertNotAfter.UTC().Format(time.RFC3339))
	}
}

type certificateExpiryState string

const (
	certificateStateOK       certificateExpiryState = "ok"
	certificateStateExpiring certificateExpiryState = "expiring"
	certificateStateExpired  certificateExpiryState = "expired"
)

const (
	defaultPageSize int32 = 50
	maxPageSize     int32 = 200
)

var cpePartRe = regexp.MustCompile(`[^a-z0-9._-]+`)

func clampLimit(limit int32) int32 {
	if limit <= 0 {
		return defaultPageSize
	}
	if limit > maxPageSize {
		return maxPageSize
	}
	return limit
}

func buildCPE(service, version string) string {
	product := cpePartRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(service)), "_")
	ver := cpePartRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(version)), "_")
	product = strings.Trim(product, "_")
	ver = strings.Trim(ver, "_")
	if product == "" || ver == "" {
		return ""
	}
	return "cpe:2.3:a:*:" + product + ":" + ver + ":*:*:*:*:*:*:*"
}

func normalizeSANs(sans []string) []string {
	if len(sans) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(sans))
	out := make([]string, 0, len(sans))
	for _, san := range sans {
		san = strings.ToLower(strings.TrimSpace(san))
		if san == "" {
			continue
		}
		if _, ok := seen[san]; ok {
			continue
		}
		seen[san] = struct{}{}
		out = append(out, san)
	}
	sort.Strings(out)
	return out
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func certificateState(in IngestInput, now time.Time) certificateExpiryState {
	if in.CertNotAfter.IsZero() || in.CertNotAfter.Equal(time.Time{}) {
		return certificateStateOK
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	notAfter := in.CertNotAfter.UTC()
	now = now.UTC()
	if !notAfter.After(now) {
		return certificateStateExpired
	}
	if !notAfter.After(now.Add(certificateExpiryWarningWindow)) {
		return certificateStateExpiring
	}
	return certificateStateOK
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
