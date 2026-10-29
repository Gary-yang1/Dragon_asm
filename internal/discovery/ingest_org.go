package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Enterprise facts land in the project workspace rather than the asset graph.
//
// A company and an ICP filing are not assets — they are the paper trail that
// explains why a domain belongs to the customer. ASM already models them as
// project_subject / icp_filing / icp_filing_domain; until now those tables could
// only be filled in by hand, which meant the evidence chain stopped at whatever
// an operator had time to type.
//
// Two rules govern everything here:
//
//   - Ingestion is idempotent. A rerun of the same job must converge, not
//     accumulate duplicates, so every write is keyed on a natural key.
//   - Ingestion never claims ownership. An ICP filing is strong evidence, but it
//     is not the DNS proof that gates active scanning, so domains created here
//     stay 'unverified' and an already-verified domain is left alone.
const (
	// orgIntelSource marks rows this pipeline created, so an operator can tell
	// collected data from data they entered themselves.
	orgIntelSource = "org_intel"
	// maxEvidenceSummary matches the column width on the workspace tables.
	maxEvidenceSummary = 1024
)

// ingestOrgFacts writes organizations and filings for one callback batch.
func (s *Service) ingestOrgFacts(
	ctx context.Context, q *dbgen.Queries, callback DiscoveryCallback, payload callbackPayload,
) error {
	if len(payload.Organizations) == 0 && len(payload.Filings) == 0 {
		return nil
	}
	capability := capabilityForTaskType(TaskTypeOrgIntel)
	discoveryRepo := NewRepository(q)

	// Facts reference each other by client_ref within one batch, so a filing can
	// point at the organization that holds it.
	subjectIDs := make(map[string]uint64, len(payload.Organizations))

	for _, fact := range payload.Organizations {
		subjectID, err := s.upsertSubject(ctx, q, callback, fact)
		if err != nil {
			return err
		}
		if ref := strings.TrimSpace(fact.ClientRef); ref != "" {
			subjectIDs[ref] = subjectID
		}
		if err := recordOrgObservation(ctx, discoveryRepo, callback, payload, capability,
			ObservationKindAsset, "org:"+subjectKeyFor(fact), fact.Provider, fact); err != nil {
			return err
		}
	}

	for _, fact := range payload.Filings {
		if err := s.upsertFiling(ctx, q, callback, fact, subjectIDs); err != nil {
			return err
		}
		if err := recordOrgObservation(ctx, discoveryRepo, callback, payload, capability,
			ObservationKindAsset, "filing:"+strings.TrimSpace(fact.FilingNo), fact.Provider, fact); err != nil {
			return err
		}
	}
	return nil
}

// subjectKeyFor derives the natural key a subject is deduplicated on.
//
// The registration code is preferred because it is the only stable identifier —
// companies rename, and registries render the same name inconsistently. The name
// is the fallback for sources that do not report a code.
func subjectKeyFor(fact callbackOrganization) string {
	if code := strings.TrimSpace(fact.RegistrationCode); code != "" {
		return "code:" + strings.ToUpper(code)
	}
	return "name:" + strings.ToLower(strings.TrimSpace(fact.Name))
}

func (s *Service) upsertSubject(
	ctx context.Context, q *dbgen.Queries, callback DiscoveryCallback, fact callbackOrganization,
) (uint64, error) {
	key := subjectKeyFor(fact)
	name := strings.TrimSpace(fact.Name)
	evidence := boundedEvidence(orgEvidenceSummary(fact))

	existing, err := q.GetProjectSubjectByKey(ctx, dbgen.GetProjectSubjectByKeyParams{
		ProjectID: callback.ProjectID, SubjectKey: key,
	})
	switch {
	case err == nil:
		// A subject an operator created by hand keeps its own verification
		// status and primary flag; collection only refreshes the descriptive
		// fields and the evidence trail.
		if updateErr := q.UpdateProjectSubject(ctx, dbgen.UpdateProjectSubjectParams{
			SubjectKey: key, SubjectName: name, SubjectType: fact.SubjectType,
			RegistrationCode:   strings.ToUpper(strings.TrimSpace(fact.RegistrationCode)),
			CountryCode:        existing.CountryCode,
			Region:             existing.Region,
			IsPrimary:          existing.IsPrimary,
			VerificationStatus: existing.VerificationStatus,
			Source:             existing.Source,
			VerifiedAt:         existing.VerifiedAt,
			EvidenceSummary:    evidence,
			UpdatedBy:          orgIntelSource,
			ID:                 existing.ID,
			ProjectID:          callback.ProjectID,
		}); updateErr != nil {
			return 0, updateErr
		}
		return existing.ID, nil
	case errors.Is(err, sql.ErrNoRows):
		result, createErr := q.CreateProjectSubject(ctx, dbgen.CreateProjectSubjectParams{
			TenantID: callback.TenantID, OrgID: callback.OrgID, ProjectID: callback.ProjectID,
			SubjectKey: key, SubjectName: name, SubjectType: fact.SubjectType,
			RegistrationCode: strings.ToUpper(strings.TrimSpace(fact.RegistrationCode)),
			CountryCode:      "CN", Region: "",
			// Never primary and never verified: both are operator decisions, and
			// a collected subject has not been checked by anyone.
			IsPrimary: false, VerificationStatus: "unverified",
			Source: orgIntelSource, VerifiedAt: sql.NullTime{},
			EvidenceSummary: evidence,
			CreatedBy:       orgIntelSource, UpdatedBy: orgIntelSource,
		})
		if createErr != nil {
			return 0, createErr
		}
		return resultID(result)
	default:
		return 0, err
	}
}

func (s *Service) upsertFiling(
	ctx context.Context, q *dbgen.Queries, callback DiscoveryCallback,
	fact callbackFiling, subjectIDs map[string]uint64,
) error {
	subjectID, ok := subjectIDs[strings.TrimSpace(fact.Organization.ClientRef)]
	if !ok {
		// A filing with no organization in this batch has nothing to hang off:
		// icp_filing.subject_id is a foreign key. Dropping it is correct — the
		// filing is evidence about a company, and without the company it is not
		// evidence about anything.
		return nil
	}
	filingNo := strings.TrimSpace(fact.FilingNo)
	evidence := boundedEvidence(filingEvidenceSummary(fact))

	var filingID uint64
	existing, err := q.GetICPFilingByNo(ctx, dbgen.GetICPFilingByNoParams{
		ProjectID: callback.ProjectID, FilingNo: filingNo,
	})
	switch {
	case err == nil:
		filingID = existing.ID
		if updateErr := q.UpdateICPFiling(ctx, dbgen.UpdateICPFilingParams{
			SubjectID: subjectID, FilingNo: filingNo, FilingType: fact.FilingType,
			WebsiteName: strings.TrimSpace(fact.WebsiteName),
			// The filing's own status is an operator judgement, not something a
			// scraped registry row can settle.
			Status: existing.Status, ApprovedAt: existing.ApprovedAt,
			Source: existing.Source, VerifiedAt: existing.VerifiedAt,
			EvidenceSummary: evidence, UpdatedBy: orgIntelSource,
			ID: existing.ID, ProjectID: callback.ProjectID,
		}); updateErr != nil {
			return updateErr
		}
	case errors.Is(err, sql.ErrNoRows):
		result, createErr := q.CreateICPFilings(ctx, dbgen.CreateICPFilingsParams{
			TenantID: callback.TenantID, OrgID: callback.OrgID, ProjectID: callback.ProjectID,
			SubjectID: subjectID, FilingNo: filingNo, FilingType: fact.FilingType,
			WebsiteName: strings.TrimSpace(fact.WebsiteName),
			Status:      "unverified", ApprovedAt: sql.NullTime{},
			Source: orgIntelSource, VerifiedAt: sql.NullTime{},
			EvidenceSummary: evidence,
			CreatedBy:       orgIntelSource, UpdatedBy: orgIntelSource,
		})
		if createErr != nil {
			return createErr
		}
		newID, idErr := resultID(result)
		if idErr != nil {
			return idErr
		}
		filingID = newID
	default:
		return err
	}

	return s.linkFilingDomains(ctx, q, callback, filingID, fact.Domains)
}

// linkFilingDomains joins a filing to the domain profiles of the domains it
// covers.
//
// The domains arrive in the same batch as ordinary domain AssetFacts and are
// materialised by the asset pipeline before this runs, so the profile lookup
// finds them. A domain with no profile is skipped rather than created here:
// creating one would mean choosing an ownership_status, and this pipeline is not
// entitled to make that call.
func (s *Service) linkFilingDomains(
	ctx context.Context, q *dbgen.Queries, callback DiscoveryCallback, filingID uint64, domains []string,
) error {
	for _, raw := range domains {
		domain := strings.ToLower(strings.TrimSpace(raw))
		if domain == "" {
			continue
		}
		profile, err := q.GetProjectDomainProfileByDomain(ctx, dbgen.GetProjectDomainProfileByDomainParams{
			ProjectID: callback.ProjectID, Value: domain,
		})
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		// INSERT IGNORE: re-running the same job must not fail on the unique key.
		if _, err := q.LinkICPFilingDomainIfAbsent(ctx, dbgen.LinkICPFilingDomainIfAbsentParams{
			TenantID: callback.TenantID, OrgID: callback.OrgID, ProjectID: callback.ProjectID,
			FilingID: filingID, DomainProfileID: profile.ID,
			CreatedBy: orgIntelSource, UpdatedBy: orgIntelSource,
		}); err != nil {
			return err
		}
	}
	return nil
}

func orgEvidenceSummary(fact callbackOrganization) string {
	parts := []string{"source=" + fact.Provider}
	if relation := strings.TrimSpace(fact.Relation); relation != "" {
		parts = append(parts, "relation="+relation)
	}
	if fact.EquityRatio > 0 {
		parts = append(parts, "equity_ratio="+trimFloat(fact.EquityRatio))
	}
	if hash := strings.TrimSpace(fact.EvidenceHash); hash != "" {
		parts = append(parts, "evidence="+hash)
	}
	return strings.Join(parts, " ")
}

func filingEvidenceSummary(fact callbackFiling) string {
	parts := []string{"source=" + fact.Provider}
	if len(fact.Domains) > 0 {
		parts = append(parts, "domains="+strings.Join(fact.Domains, ","))
	}
	if hash := strings.TrimSpace(fact.EvidenceHash); hash != "" {
		parts = append(parts, "evidence="+hash)
	}
	return strings.Join(parts, " ")
}

func trimFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func boundedEvidence(summary string) string {
	if len(summary) > maxEvidenceSummary {
		return summary[:maxEvidenceSummary]
	}
	return summary
}

// recordOrgObservation keeps the raw fact in the observation ledger, so the
// evidence behind a subject or filing survives even after the row is edited.
func recordOrgObservation(
	ctx context.Context, repo Repository, callback DiscoveryCallback, payload callbackPayload,
	capability, kind, naturalKey, provider string, fact any,
) error {
	raw, err := json.Marshal(fact)
	if err != nil {
		return err
	}
	observation, err := repo.UpsertDiscoveryObservation(ctx, DiscoveryObservation{
		TenantID: callback.TenantID, OrgID: callback.OrgID, ProjectID: callback.ProjectID,
		RunID: callback.RunID, Seq: callback.Seq, Kind: kind,
		NaturalKey: naturalKey, Provider: provider, Capability: capability,
		ObservedAt: payload.ObservedAt, EvidenceHash: callback.PayloadHash,
		NormalizedJSON: raw, IngestStatus: ObservationStatusObserved,
	})
	if err != nil {
		return err
	}
	return repo.MarkDiscoveryObservationMaterialized(ctx, callback.ProjectID, observation.ID)
}
