package risk

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/exposure"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

type fakeRepo struct {
	defs              map[uint64]*VulnerabilityDefinition
	defByRule         map[string]*VulnerabilityDefinition
	rules             map[uint64]*RiskRule
	ruleByRule        map[string]*RiskRule
	risks             map[uint64]*Risk
	riskByKey         map[string]*Risk
	events            []ChangeEventParams
	history           []ScoreHistoryParams
	statuses          []StatusHistoryParams
	suppressions      map[uint64]*SuppressionRule
	decisions         []RiskDecisionParams
	slaPolicies       map[string]*SLAPolicy
	audits            []audit.Event
	nextDefID         uint64
	nextRuleID        uint64
	nextRiskID        uint64
	nextSuppressionID uint64
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		defs:              make(map[uint64]*VulnerabilityDefinition),
		defByRule:         make(map[string]*VulnerabilityDefinition),
		rules:             make(map[uint64]*RiskRule),
		ruleByRule:        make(map[string]*RiskRule),
		risks:             make(map[uint64]*Risk),
		riskByKey:         make(map[string]*Risk),
		suppressions:      make(map[uint64]*SuppressionRule),
		slaPolicies:       make(map[string]*SLAPolicy),
		nextDefID:         1,
		nextRuleID:        1,
		nextRiskID:        1,
		nextSuppressionID: 1,
	}
}

func (f *fakeRepo) CreateDefinition(_ context.Context, in CreateDefinitionParams) (uint64, error) {
	id := f.nextDefID
	f.nextDefID++
	def := &VulnerabilityDefinition{
		ID: id, TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		RuleID: in.RuleID, CVEID: in.CVEID, Title: in.Title, Description: in.Description,
		Severity: in.Severity, CPEPattern: in.CPEPattern, Remediation: in.Remediation,
		Source: in.Source, Enabled: in.Enabled, CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	}
	f.defs[id] = def
	f.defByRule[key(in.ProjectID, in.RuleID)] = def
	return id, nil
}

func (f *fakeRepo) GetDefinitionByID(_ context.Context, projectID, id uint64) (*VulnerabilityDefinition, error) {
	def := f.defs[id]
	if def == nil || def.ProjectID != projectID {
		return nil, ErrNotFound
	}
	cp := *def
	return &cp, nil
}

func (f *fakeRepo) GetDefinitionByRuleID(_ context.Context, projectID uint64, ruleID string) (*VulnerabilityDefinition, error) {
	def := f.defByRule[key(projectID, ruleID)]
	if def == nil {
		return nil, ErrNotFound
	}
	cp := *def
	return &cp, nil
}

func (f *fakeRepo) ListDefinitions(_ context.Context, projectID uint64) ([]*VulnerabilityDefinition, error) {
	out := []*VulnerabilityDefinition{}
	for _, def := range f.defs {
		if def.ProjectID == projectID {
			cp := *def
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeRepo) CreateRule(_ context.Context, in CreateRuleParams) (uint64, error) {
	id := f.nextRuleID
	f.nextRuleID++
	rule := &RiskRule{
		ID: id, TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		RuleID: in.RuleID, Name: in.Name, Description: in.Description,
		RiskType: in.RiskType, Severity: in.Severity, MatchType: in.MatchType,
		MatchValue: in.MatchValue, Remediation: in.Remediation, Source: in.Source,
		Enabled: in.Enabled, CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	}
	f.rules[id] = rule
	f.ruleByRule[key(in.ProjectID, in.RuleID)] = rule
	return id, nil
}

func (f *fakeRepo) GetRuleByID(_ context.Context, projectID, id uint64) (*RiskRule, error) {
	rule := f.rules[id]
	if rule == nil || rule.ProjectID != projectID {
		return nil, ErrNotFound
	}
	cp := *rule
	return &cp, nil
}

func (f *fakeRepo) GetRuleByRuleID(_ context.Context, projectID uint64, ruleID string) (*RiskRule, error) {
	rule := f.ruleByRule[key(projectID, ruleID)]
	if rule == nil {
		return nil, ErrNotFound
	}
	cp := *rule
	return &cp, nil
}

func (f *fakeRepo) ListEnabledRules(_ context.Context, projectID uint64) ([]*RiskRule, error) {
	out := []*RiskRule{}
	for _, rule := range f.rules {
		if rule.ProjectID == projectID && rule.Enabled {
			cp := *rule
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeRepo) SetRuleEnabled(_ context.Context, projectID, id uint64, enabled bool, actorID string) error {
	rule := f.rules[id]
	if rule == nil || rule.ProjectID != projectID {
		return ErrNotFound
	}
	rule.Enabled = enabled
	rule.UpdatedBy = actorID
	return nil
}

func (f *fakeRepo) CreateRisk(_ context.Context, in UpsertRiskParams) (uint64, error) {
	id := f.nextRiskID
	f.nextRiskID++
	r := riskFromParams(id, in)
	f.risks[id] = r
	f.riskByKey[key(in.ProjectID, in.RiskKey)] = r
	return id, nil
}

func (f *fakeRepo) GetRiskByID(_ context.Context, projectID, id uint64) (*Risk, error) {
	r := f.risks[id]
	if r == nil || r.ProjectID != projectID {
		return nil, ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (f *fakeRepo) GetRiskByIDForUpdate(ctx context.Context, projectID, id uint64) (*Risk, error) {
	return f.GetRiskByID(ctx, projectID, id)
}

func (f *fakeRepo) GetRiskByKey(_ context.Context, projectID uint64, riskKey string) (*Risk, error) {
	r := f.riskByKey[key(projectID, riskKey)]
	if r == nil {
		return nil, ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (f *fakeRepo) ListRisks(_ context.Context, projectID uint64, limit, offset int32) ([]*Risk, error) {
	out := []*Risk{}
	for _, r := range f.risks {
		if r.ProjectID == projectID {
			cp := *r
			out = append(out, &cp)
		}
	}
	if offset >= int32(len(out)) {
		return nil, nil
	}
	end := offset + limit
	if end > int32(len(out)) {
		end = int32(len(out))
	}
	return out[offset:end], nil
}

func (f *fakeRepo) CountRisks(_ context.Context, projectID uint64) (int64, error) {
	var n int64
	for _, r := range f.risks {
		if r.ProjectID == projectID {
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) RefreshRisk(_ context.Context, in UpsertRiskParams) error {
	r := f.risks[in.ID]
	if r == nil {
		return ErrNotFound
	}
	applyRiskRefresh(r, in)
	return nil
}

func (f *fakeRepo) ReopenRisk(_ context.Context, in UpsertRiskParams) error {
	r := f.risks[in.ID]
	if r == nil || r.Status != StatusFixed {
		return ErrNotFound
	}
	applyRiskRefresh(r, in)
	r.Status = StatusReopened
	r.FixedAt = time.Time{}
	return nil
}

func (f *fakeRepo) UpdateRiskScore(_ context.Context, in ScoreUpdateParams) error {
	r := f.risks[in.RiskID]
	if r == nil || r.ProjectID != in.ProjectID {
		return ErrNotFound
	}
	r.Score = in.Score
	r.ScoreLevel = in.ScoreLevel
	r.ScoreModelVersion = in.ScoreModelVersion
	r.ScoreFactors = in.ScoreFactors
	r.ScoredAt = in.ScoredAt
	r.UpdatedBy = in.ActorID
	return nil
}

func (f *fakeRepo) InsertScoreHistory(_ context.Context, in ScoreHistoryParams) error {
	f.history = append(f.history, in)
	return nil
}

func (f *fakeRepo) ListScoreHistory(_ context.Context, projectID, riskID uint64) ([]*ScoreHistory, error) {
	out := []*ScoreHistory{}
	for i, row := range f.history {
		if row.ProjectID == projectID && row.RiskID == riskID {
			out = append(out, &ScoreHistory{
				ID: uint64(i + 1), TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
				RiskID: row.RiskID, Score: row.Score, ScoreLevel: row.ScoreLevel,
				ScoreModelVersion: row.ScoreModelVersion, ScoreFactors: row.ScoreFactors,
				Reason: row.Reason, ScoredAt: row.ScoredAt, CreatedBy: row.ActorID,
			})
		}
	}
	return out, nil
}

func (f *fakeRepo) UpdateRiskStatus(_ context.Context, in StatusUpdateParams) error {
	r := f.risks[in.RiskID]
	if r == nil || r.ProjectID != in.ProjectID || r.Status != in.OldStatus {
		return ErrNotFound
	}
	r.Status = in.NewStatus
	r.Owner = in.Owner
	r.SLADueAt = in.SLADueAt
	r.ConfirmedAt = in.ConfirmedAt
	r.FixedAt = in.FixedAt
	r.UpdatedBy = in.ActorID
	return nil
}

func (f *fakeRepo) InsertStatusHistory(_ context.Context, in StatusHistoryParams) error {
	f.statuses = append(f.statuses, in)
	return nil
}

func (f *fakeRepo) ListStatusHistory(_ context.Context, projectID, riskID uint64) ([]*RiskStatusHistory, error) {
	out := []*RiskStatusHistory{}
	for i, row := range f.statuses {
		if row.ProjectID == projectID && row.RiskID == riskID {
			out = append(out, &RiskStatusHistory{
				ID: uint64(i + 1), TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
				RiskID: row.RiskID, Action: row.Action, OldStatus: row.OldStatus, NewStatus: row.NewStatus,
				ActorID: row.ActorID, Reason: row.Reason, RequestID: row.RequestID,
			})
		}
	}
	return out, nil
}

func (f *fakeRepo) CreateSuppressionRule(_ context.Context, in CreateSuppressionRuleParams) (uint64, error) {
	id := f.nextSuppressionID
	f.nextSuppressionID++
	rule := &SuppressionRule{
		ID: id, TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		Name: in.Name, RiskType: in.RiskType, RuleID: in.RuleID, AssetID: in.AssetID,
		Reason: in.Reason, ExpiresAt: in.ExpiresAt, Enabled: in.Enabled,
		CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	}
	f.suppressions[id] = rule
	return id, nil
}

func (f *fakeRepo) GetSuppressionRuleByID(_ context.Context, projectID, id uint64) (*SuppressionRule, error) {
	rule := f.suppressions[id]
	if rule == nil || rule.ProjectID != projectID {
		return nil, ErrNotFound
	}
	cp := *rule
	return &cp, nil
}

func (f *fakeRepo) ListActiveSuppressionRules(_ context.Context, projectID uint64, now time.Time) ([]*SuppressionRule, error) {
	out := []*SuppressionRule{}
	for _, rule := range f.suppressions {
		if rule.ProjectID != projectID || !rule.Enabled {
			continue
		}
		if !rule.ExpiresAt.IsZero() && !rule.ExpiresAt.Equal(time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)) && !rule.ExpiresAt.After(now) {
			continue
		}
		cp := *rule
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeRepo) SetSuppressionRuleEnabled(_ context.Context, projectID, id uint64, enabled bool, actorID string) error {
	rule := f.suppressions[id]
	if rule == nil || rule.ProjectID != projectID {
		return ErrNotFound
	}
	rule.Enabled = enabled
	rule.UpdatedBy = actorID
	return nil
}

func (f *fakeRepo) InsertRiskDecision(_ context.Context, in RiskDecisionParams) error {
	f.decisions = append(f.decisions, in)
	return nil
}

func (f *fakeRepo) ListRiskDecisions(_ context.Context, projectID, riskID uint64) ([]*RiskDecision, error) {
	out := []*RiskDecision{}
	for i, row := range f.decisions {
		if row.ProjectID == projectID && row.RiskID == riskID {
			out = append(out, &RiskDecision{
				ID: uint64(i + 1), TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
				RiskID: row.RiskID, Decision: row.Decision, Reason: row.Reason,
				ApprovedBy: row.ApprovedBy, ExpiresAt: row.ExpiresAt, ReviewRequiredAt: row.ReviewRequiredAt,
				CreatedBy: row.ActorID,
			})
		}
	}
	return out, nil
}

func (f *fakeRepo) ListExpiredRiskDecisions(_ context.Context, projectID uint64, now time.Time, limit int32) ([]*RiskDecision, error) {
	out := []*RiskDecision{}
	for i, row := range f.decisions {
		if row.ProjectID != projectID {
			continue
		}
		expired := !row.ExpiresAt.IsZero() && !row.ExpiresAt.After(now)
		review := !row.ReviewRequiredAt.IsZero() && !row.ReviewRequiredAt.After(now)
		if expired || review {
			out = append(out, &RiskDecision{
				ID: uint64(i + 1), TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
				RiskID: row.RiskID, Decision: row.Decision, Reason: row.Reason,
				ApprovedBy: row.ApprovedBy, ExpiresAt: row.ExpiresAt, ReviewRequiredAt: row.ReviewRequiredAt,
				CreatedBy: row.ActorID,
			})
			if int32(len(out)) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (f *fakeRepo) UpsertSLAPolicy(_ context.Context, in SLAPolicyParams) error {
	policy := &SLAPolicy{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		Severity: in.Severity, BusinessUnit: in.BusinessUnit,
		ResponseHours: in.ResponseHours, ResolutionHours: in.ResolutionHours,
		Enabled: in.Enabled, CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	}
	f.slaPolicies[key(in.ProjectID, in.Severity+":"+in.BusinessUnit)] = policy
	return nil
}

func (f *fakeRepo) GetSLAPolicy(_ context.Context, projectID uint64, severity, businessUnit string) (*SLAPolicy, error) {
	policy := f.slaPolicies[key(projectID, severity+":"+businessUnit)]
	if policy == nil || !policy.Enabled {
		return nil, ErrNotFound
	}
	cp := *policy
	return &cp, nil
}

func (f *fakeRepo) ListSLAPolicies(_ context.Context, projectID uint64) ([]*SLAPolicy, error) {
	out := []*SLAPolicy{}
	for _, policy := range f.slaPolicies {
		if policy.ProjectID == projectID {
			cp := *policy
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeRepo) ListOpenRisksForSLARecalc(_ context.Context, projectID uint64, limit int32) ([]*Risk, error) {
	out := []*Risk{}
	for _, r := range f.risks {
		if r.ProjectID == projectID && r.Status != StatusFixed && r.Status != StatusRiskAccepted && r.Status != StatusFalsePositive {
			cp := *r
			out = append(out, &cp)
			if int32(len(out)) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (f *fakeRepo) CountOverdueRisks(_ context.Context, projectID uint64, now time.Time) (int64, error) {
	var n int64
	for _, r := range f.risks {
		if r.ProjectID == projectID && r.Status != StatusFixed && r.Status != StatusRiskAccepted &&
			r.Status != StatusFalsePositive && !r.SLADueAt.IsZero() && r.SLADueAt.Before(now) {
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) InsertChangeEvent(_ context.Context, in ChangeEventParams) error {
	f.events = append(f.events, in)
	return nil
}

func (f *fakeRepo) Record(_ context.Context, e audit.Event) error {
	f.audits = append(f.audits, e)
	return nil
}

func TestApplyDefinitionMatchesCreatesOneRiskPerAsset(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	def := createDefinition(t, svc)

	result, err := svc.ApplyDefinitionMatches(context.Background(), 1, def.ID, []MatchInput{
		{TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10, ExposureID: 100, CPE: "cpe:2.3:a:*:nginx:1.25:*:*:*:*:*:*:*"},
		{TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 11, ExposureID: 101, CPE: "cpe:2.3:a:*:nginx:1.24:*:*:*:*:*:*:*"},
	}, "engine")
	require.NoError(t, err)
	assert.Equal(t, 2, result.Created)
	assert.Equal(t, 2, len(result.Risks))
	assert.Len(t, repo.events, 2)
}

func TestApplyDefinitionMatchesRefreshesDuplicateRisk(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	def := createDefinition(t, svc)
	match := MatchInput{TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10, ExposureID: 100, CPE: "cpe:2.3:a:*:nginx:1.25:*:*:*:*:*:*:*", EvidenceSummary: "first"}
	_, err := svc.ApplyDefinitionMatches(context.Background(), 1, def.ID, []MatchInput{match}, "engine")
	require.NoError(t, err)
	match.EvidenceSummary = "second"

	result, err := svc.ApplyDefinitionMatches(context.Background(), 1, def.ID, []MatchInput{match}, "engine")
	require.NoError(t, err)
	assert.Equal(t, 0, result.Created)
	assert.Equal(t, 1, result.Updated)
	assert.Equal(t, "second", result.Risks[0].EvidenceSummary)
	assert.Len(t, repo.risks, 1)
	assert.Len(t, repo.events, 1, "duplicate refresh must not create noisy change_event")
	assert.Len(t, repo.history, 2)
}

func TestApplyDefinitionMatchesReopensFixedRisk(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	def := createDefinition(t, svc)
	match := MatchInput{TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10, ExposureID: 100, CPE: "cpe:2.3:a:*:nginx:1.25:*:*:*:*:*:*:*"}
	first, err := svc.ApplyDefinitionMatches(context.Background(), 1, def.ID, []MatchInput{match}, "engine")
	require.NoError(t, err)
	repo.risks[first.Risks[0].ID].Status = StatusFixed
	repo.risks[first.Risks[0].ID].FixedAt = time.Now().UTC()

	result, err := svc.ApplyDefinitionMatches(context.Background(), 1, def.ID, []MatchInput{match}, "engine")
	require.NoError(t, err)
	assert.Equal(t, 1, result.Reopened)
	assert.Equal(t, StatusReopened, result.Risks[0].Status)
	require.Len(t, repo.events, 2)
	assert.Equal(t, ChangeTypeReopened, repo.events[1].ChangeType)
}

func TestApplyDefinitionMatchesRejectsUnmatchedCPE(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	def := createDefinition(t, svc)

	_, err := svc.ApplyDefinitionMatches(context.Background(), 1, def.ID, []MatchInput{{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10, ExposureID: 100,
		CPE: "cpe:2.3:a:*:apache:2.4:*:*:*:*:*:*:*",
	}}, "engine")
	require.ErrorIs(t, err, ErrCPENotMatched)
}

func TestApplyDefinitionMatchesRejectsDisabledDefinition(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	def, err := svc.CreateDefinition(context.Background(), CreateDefinitionInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, RuleID: "disabled-rule",
		Title: "disabled", Severity: SeverityLow, Enabled: false, ActorID: "alice",
	})
	require.NoError(t, err)

	_, err = svc.ApplyDefinitionMatches(context.Background(), 1, def.ID, []MatchInput{{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10,
	}}, "engine")
	require.ErrorIs(t, err, ErrDefinitionDisabled)
}

func TestApplyRulesCreatesRiskForHighRiskPort(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	rule := createRiskRule(t, svc, CreateRuleInput{
		RuleID: "port-rdp", Name: "Public RDP", MatchType: RuleMatchPort, MatchValue: "3389",
		RiskType: TypeHighRiskPort, Severity: SeverityHigh,
	})

	result, err := svc.ApplyRules(context.Background(), 1, []RuleTarget{{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10, ExposureID: 100,
		Port: 3389, Source: "engine", EvidenceRef: "scan://run/1",
	}}, "engine")
	require.NoError(t, err)
	require.Equal(t, 1, result.Created)
	require.Len(t, result.Risks, 1)
	assert.Equal(t, TypeHighRiskPort, result.Risks[0].RiskType)
	assert.Equal(t, rule.RuleID, result.Risks[0].RuleID)
	assert.Equal(t, uint64(100), result.Risks[0].ExposureID)
	assert.Len(t, repo.events, 1)
}

func TestApplyRulesRefreshesDuplicateWithoutNoisyEvent(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	createRiskRule(t, svc, CreateRuleInput{
		RuleID: "svc-jenkins", Name: "Public Jenkins", MatchType: RuleMatchService, MatchValue: "jenkins",
	})
	target := RuleTarget{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10, ExposureID: 100,
		Service: "Jenkins", EvidenceSummary: "first",
	}
	_, err := svc.ApplyRules(context.Background(), 1, []RuleTarget{target}, "engine")
	require.NoError(t, err)
	target.EvidenceSummary = "second"

	result, err := svc.ApplyRules(context.Background(), 1, []RuleTarget{target}, "engine")
	require.NoError(t, err)
	assert.Equal(t, 0, result.Created)
	assert.Equal(t, 1, result.Updated)
	assert.Equal(t, "second", result.Risks[0].EvidenceSummary)
	assert.Len(t, repo.risks, 1)
	assert.Len(t, repo.events, 1)
}

func TestApplyRulesHonorsRuleEnablement(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	rule := createRiskRule(t, svc, CreateRuleInput{
		RuleID: "web-grafana", Name: "Public Grafana", MatchType: RuleMatchWeb, MatchValue: "grafana",
	})
	require.NoError(t, svc.SetRuleEnabled(context.Background(), 1, rule.ID, false, "alice"))

	result, err := svc.ApplyRules(context.Background(), 1, []RuleTarget{{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10, ExposureID: 100,
		URL: "https://example.test/grafana/login",
	}}, "engine")
	require.NoError(t, err)
	assert.Empty(t, result.Risks)
	assert.Empty(t, repo.events)
}

func TestRiskScoringUsesConfigurableModelAndStoresFactors(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo, WithScoreModel(ScoreModel{
		Version:          "unit-v2",
		InternetExposure: 15,
		ManagementEntry:  7,
		Severity: map[string]uint8{
			SeverityHigh: 30,
		},
		BusinessUnitCriticality: map[string]uint8{"payments": 18},
	}))
	createRiskRule(t, svc, CreateRuleInput{
		RuleID: "web-admin", Name: "Admin console", MatchType: RuleMatchWeb, MatchValue: "admin",
		Severity: SeverityHigh,
	})

	result, err := svc.ApplyRules(context.Background(), 1, []RuleTarget{{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10, ExposureID: 100,
		URL: "https://example.test/admin", BusinessUnit: "Payments",
	}}, "engine")
	require.NoError(t, err)
	require.Len(t, result.Risks, 1)
	r := result.Risks[0]
	assert.Equal(t, uint8(70), r.Score)
	assert.Equal(t, SeverityHigh, r.ScoreLevel)
	assert.Equal(t, "unit-v2", r.ScoreModelVersion)
	assert.NotEmpty(t, r.ScoredAt)
	assert.JSONEq(t, `{"asset_criticality":18,"compensating_control":0,"exploit_maturity":0,"exposure_age":0,"internet_exposure":15,"management_entry":7,"severity":30,"threat_intel":0}`, string(r.ScoreFactors))
	require.Len(t, repo.history, 1)
	assert.Equal(t, "create", repo.history[0].Reason)
}

func TestRecalculateScoresKeepsHistoryVersions(t *testing.T) {
	repo := newFakeRepo()
	oldSvc := NewService(repo, WithScoreModel(ScoreModel{
		Version: "unit-v1", InternetExposure: 10, Severity: map[string]uint8{SeverityHigh: 30},
	}))
	createRiskRule(t, oldSvc, CreateRuleInput{
		RuleID: "port-rdp", Name: "Public RDP", MatchType: RuleMatchPort, MatchValue: "3389",
		RiskType: TypeHighRiskPort, Severity: SeverityHigh,
	})
	first, err := oldSvc.ApplyRules(context.Background(), 1, []RuleTarget{{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10, ExposureID: 100, Port: 3389,
	}}, "engine")
	require.NoError(t, err)

	newSvc := NewService(repo, WithScoreModel(ScoreModel{
		Version: "unit-v2", InternetExposure: 20, Severity: map[string]uint8{SeverityHigh: 35},
	}))
	updated, err := newSvc.RecalculateScores(context.Background(), 1, []uint64{first.Risks[0].ID}, "alice", "model changed")
	require.NoError(t, err)
	require.Len(t, updated, 1)
	assert.Equal(t, "unit-v2", updated[0].ScoreModelVersion)
	require.Len(t, repo.history, 2)
	assert.Equal(t, "unit-v1", repo.history[0].ScoreModelVersion)
	assert.Equal(t, "unit-v2", repo.history[1].ScoreModelVersion)
	assert.Equal(t, "model changed", repo.history[1].Reason)
}

func TestTransitionStatusWritesHistoryAndAudit(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo, WithAuditSink(repo), WithNow(func() time.Time {
		return time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	}))
	r := createRiskByRule(t, svc)

	confirmed, err := svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionConfirm, ActorID: "alice",
		Meta: AuditMeta{RequestID: "req-1", IP: "127.0.0.1"},
	})
	require.NoError(t, err)
	assert.Equal(t, StatusConfirmed, confirmed.Status)
	assert.Equal(t, "alice", confirmed.UpdatedBy)
	assert.Equal(t, time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC), confirmed.ConfirmedAt)
	require.Len(t, repo.statuses, 1)
	assert.Equal(t, StatusNew, repo.statuses[0].OldStatus)
	assert.Equal(t, StatusConfirmed, repo.statuses[0].NewStatus)
	require.Len(t, repo.audits, 1)
	assert.Equal(t, ActionRiskStatusChange, repo.audits[0].Action)
	assert.Equal(t, "req-1", repo.audits[0].RequestID)
}

func TestTransitionStatusRejectsInvalidTransition(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	r := createRiskByRule(t, svc)

	_, err := svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionStartFix, ActorID: "alice",
	})
	require.ErrorIs(t, err, ErrInvalidStatusTransition)
	assert.Empty(t, repo.statuses)
}

func TestTransitionStatusAssignRequiresOwnerAndSLA(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	r := createRiskByRule(t, svc)
	_, err := svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionConfirm, ActorID: "alice",
	})
	require.NoError(t, err)

	_, err = svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionAssign, ActorID: "alice",
	})
	require.ErrorIs(t, err, ErrOwnerRequired)

	_, err = svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionAssign, ActorID: "alice", Owner: "bob",
	})
	require.ErrorIs(t, err, ErrSLARequired)
}

func TestTransitionStatusMarkFixedRequiresReason(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	r := createRiskByRule(t, svc)
	require.NoError(t, transitionToAssigned(t, svc, r.ID))

	_, err := svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionMarkFixed, ActorID: "alice",
	})
	require.ErrorIs(t, err, ErrReasonRequired)

	fixed, err := svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionMarkFixed, ActorID: "alice", Reason: "patched",
	})
	require.NoError(t, err)
	assert.Equal(t, StatusFixed, fixed.Status)
	assert.False(t, fixed.FixedAt.IsZero())
}

func TestSuppressionRuleMarksMatchingRiskSuppressed(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	supp, err := svc.CreateSuppressionRule(context.Background(), CreateSuppressionRuleInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Name: "accepted public rdp",
		RiskType: TypeHighRiskPort, RuleID: "port-rdp", Reason: "known exception",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour), ActorID: "alice",
	})
	require.NoError(t, err)

	r := createRiskByRule(t, svc)
	assert.True(t, r.Suppressed)
	assert.Equal(t, supp.ID, r.SuppressionRuleID)
	assert.Equal(t, supp.ExpiresAt, r.SuppressedUntil)
}

func TestSuppressionRuleDisableStopsFutureSuppression(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	supp, err := svc.CreateSuppressionRule(context.Background(), CreateSuppressionRuleInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, Name: "accepted rdp",
		RiskType: TypeHighRiskPort, RuleID: "port-rdp", Reason: "known exception", ActorID: "alice",
	})
	require.NoError(t, err)
	require.NoError(t, svc.SetSuppressionRuleEnabled(context.Background(), 1, supp.ID, false, "alice"))

	r := createRiskByRule(t, svc)
	assert.False(t, r.Suppressed)
	assert.Zero(t, r.SuppressionRuleID)
}

func TestAcceptAndFalsePositiveWriteDecision(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	r := createRiskByRule(t, svc)
	require.NoError(t, transitionToAssigned(t, svc, r.ID))
	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)

	accepted, err := svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionAccept, ActorID: "alice",
		Reason: "business accepts", ApprovedBy: "ciso", ExpiresAt: expiresAt,
	})
	require.NoError(t, err)
	assert.Equal(t, StatusRiskAccepted, accepted.Status)
	require.Len(t, repo.decisions, 1)
	assert.Equal(t, StatusRiskAccepted, repo.decisions[0].Decision)
	assert.Equal(t, "ciso", repo.decisions[0].ApprovedBy)
	assert.Equal(t, expiresAt, repo.decisions[0].ExpiresAt)
}

func TestDecisionTransitionsRequireApprovalAndReviewWindow(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	r := createRiskByRule(t, svc)
	_, err := svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionConfirm, ActorID: "alice",
	})
	require.NoError(t, err)

	_, err = svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionFalsePositive, ActorID: "alice",
		Reason: "scanner matched banner",
	})
	require.ErrorIs(t, err, ErrApprovedByRequired)

	_, err = svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionFalsePositive, ActorID: "alice",
		Reason: "scanner matched banner", ApprovedBy: "lead",
	})
	require.ErrorIs(t, err, ErrReviewRequiredAtMissing)
}

func TestExpiredDecisionReopensRiskForReview(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	svc := NewService(repo, WithNow(func() time.Time { return now }))
	r := createRiskByRule(t, svc)
	require.NoError(t, transitionToAssigned(t, svc, r.ID))
	_, err := svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionAccept, ActorID: "alice",
		Reason: "temporary exception", ApprovedBy: "ciso", ExpiresAt: now.Add(-time.Hour),
	})
	require.NoError(t, err)

	result, err := svc.ReopenExpiredDecisions(context.Background(), 1, 10, "system")
	require.NoError(t, err)
	assert.Equal(t, 1, result.Reopened)
	require.Len(t, result.Risks, 1)
	assert.Equal(t, StatusReopened, result.Risks[0].Status)
}

func TestResolveDueAtUsesBusinessUnitPolicyBeforeDefault(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	require.NoError(t, svc.UpsertSLAPolicy(context.Background(), UpsertSLAPolicyInput{
		ProjectID: 1, Severity: SeverityHigh, ResolutionHours: 72, ActorID: "admin",
	}))
	require.NoError(t, svc.UpsertSLAPolicy(context.Background(), UpsertSLAPolicyInput{
		ProjectID: 1, Severity: SeverityHigh, BusinessUnit: "payments", ResolutionHours: 24, ActorID: "admin",
	}))

	dueAt, err := svc.ResolveDueAt(context.Background(), 1, SeverityHigh, "payments", base)
	require.NoError(t, err)
	assert.Equal(t, base.Add(24*time.Hour), dueAt)

	dueAt, err = svc.ResolveDueAt(context.Background(), 1, SeverityHigh, "infra", base)
	require.NoError(t, err)
	assert.Equal(t, base.Add(72*time.Hour), dueAt)
}

func TestAssignDerivesSLADueAtFromPolicy(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	svc := NewService(repo, WithNow(func() time.Time { return now }))
	require.NoError(t, svc.UpsertSLAPolicy(context.Background(), UpsertSLAPolicyInput{
		ProjectID: 1, Severity: SeverityHigh, ResolutionHours: 48, ActorID: "admin",
	}))
	r := createRiskByRule(t, svc)
	_, err := svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionConfirm, ActorID: "alice",
	})
	require.NoError(t, err)

	assigned, err := svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: r.ID, Action: StatusActionAssign, ActorID: "alice", Owner: "bob",
	})
	require.NoError(t, err)
	assert.Equal(t, StatusAssigned, assigned.Status)
	assert.Equal(t, now.Add(48*time.Hour), assigned.SLADueAt)
}

func TestRecalculateSLADueAtUpdatesOpenRisks(t *testing.T) {
	repo := newFakeRepo()
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	svc := NewService(repo, WithNow(func() time.Time { return base }))
	require.NoError(t, svc.UpsertSLAPolicy(context.Background(), UpsertSLAPolicyInput{
		ProjectID: 1, Severity: SeverityHigh, ResolutionHours: 24, ActorID: "admin",
	}))
	r := createRiskByRule(t, svc)
	repo.risks[r.ID].Status = StatusAssigned
	repo.risks[r.ID].Owner = "bob"
	repo.risks[r.ID].FirstSeen = base

	require.NoError(t, svc.UpsertSLAPolicy(context.Background(), UpsertSLAPolicyInput{
		ProjectID: 1, Severity: SeverityHigh, ResolutionHours: 12, ActorID: "admin",
	}))
	updated, err := svc.RecalculateSLADueAt(context.Background(), 1, 10, "admin")
	require.NoError(t, err)
	require.Len(t, updated, 1)
	assert.Equal(t, base.Add(12*time.Hour), updated[0].SLADueAt)
}

func TestCountOverdueRisks(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	r := createRiskByRule(t, svc)
	repo.risks[r.ID].Status = StatusAssigned
	repo.risks[r.ID].SLADueAt = time.Date(2026, 7, 8, 11, 0, 0, 0, time.UTC)

	n, err := svc.CountOverdue(context.Background(), 1, time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

func TestReportCertificateFindingCreatesRefreshesAndReopensRisk(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo, WithNow(func() time.Time { return time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC) }))
	finding := exposure.CertificateFinding{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10, ExposureID: 200,
		ExposureKey: "certificate:10:abc", CertSubject: "www.example.com",
		CertNotAfter: time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC),
		State:        "expiring", Source: "discovery", ActorID: "engine",
		EvidenceSummary: "certificate expires soon",
	}

	first, err := svc.ReportCertificateFinding(context.Background(), finding)
	require.NoError(t, err)
	assert.Equal(t, ChangeTypeNew, first.Outcome)
	r := repo.risks[first.RiskID]
	require.NotNil(t, r)
	assert.Equal(t, TypeExpiredCertificate, r.RiskType)
	assert.Equal(t, SeverityHigh, r.Severity)
	assert.Equal(t, "builtin:certificate_expiry", r.RuleID)

	second, err := svc.ReportCertificateFinding(context.Background(), finding)
	require.NoError(t, err)
	assert.Empty(t, second.Outcome)
	assert.Equal(t, first.RiskID, second.RiskID)

	repo.risks[first.RiskID].Status = StatusFixed
	repo.risks[first.RiskID].FixedAt = time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC)
	finding.State = "expired"
	finding.EvidenceSummary = "certificate expired"
	reopened, err := svc.ReportCertificateFinding(context.Background(), finding)
	require.NoError(t, err)
	assert.Equal(t, ChangeTypeReopened, reopened.Outcome)
	assert.Equal(t, first.RiskID, reopened.RiskID)
	assert.Equal(t, StatusReopened, repo.risks[first.RiskID].Status)
	assert.Equal(t, SeverityCritical, repo.risks[first.RiskID].Severity)
}

func createDefinition(t *testing.T, svc *Service) *VulnerabilityDefinition {
	t.Helper()
	def, err := svc.CreateDefinition(context.Background(), CreateDefinitionInput{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, RuleID: "CVE-TEST-1", CVEID: "CVE-TEST-1",
		Title: "nginx vulnerable", Severity: SeverityHigh, CPEPattern: "cpe:2.3:a:*:nginx:*",
		Source: "nvd", Enabled: true, ActorID: "alice",
	})
	require.NoError(t, err)
	return def
}

func createRiskRule(t *testing.T, svc *Service, in CreateRuleInput) *RiskRule {
	t.Helper()
	in.TenantID = "t1"
	in.OrgID = "o1"
	in.ProjectID = 1
	in.ActorID = "alice"
	in.Source = "builtin"
	if in.Name == "" {
		in.Name = in.RuleID
	}
	rule, err := svc.CreateRule(context.Background(), in)
	require.NoError(t, err)
	return rule
}

func createRiskByRule(t *testing.T, svc *Service) *Risk {
	t.Helper()
	createRiskRule(t, svc, CreateRuleInput{
		RuleID: "port-rdp", Name: "Public RDP", MatchType: RuleMatchPort, MatchValue: "3389",
		RiskType: TypeHighRiskPort, Severity: SeverityHigh,
	})
	result, err := svc.ApplyRules(context.Background(), 1, []RuleTarget{{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, AssetID: 10, ExposureID: 100, Port: 3389,
	}}, "engine")
	require.NoError(t, err)
	require.Len(t, result.Risks, 1)
	return result.Risks[0]
}

func transitionToAssigned(t *testing.T, svc *Service, riskID uint64) error {
	t.Helper()
	_, err := svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: riskID, Action: StatusActionConfirm, ActorID: "alice",
	})
	if err != nil {
		return err
	}
	_, err = svc.TransitionStatus(context.Background(), StatusTransitionInput{
		ProjectID: 1, RiskID: riskID, Action: StatusActionAssign, ActorID: "alice", Owner: "bob",
		SLADueAt: time.Now().UTC().Add(24 * time.Hour),
	})
	return err
}

func riskFromParams(id uint64, in UpsertRiskParams) *Risk {
	r := &Risk{ID: id, Status: in.Status, FirstSeen: in.ObservedAt}
	applyRiskRefresh(r, in)
	return r
}

func applyRiskRefresh(r *Risk, in UpsertRiskParams) {
	r.TenantID = in.TenantID
	r.OrgID = in.OrgID
	r.ProjectID = in.ProjectID
	r.AssetID = in.AssetID
	r.ExposureID = in.ExposureID
	r.VulnDefinitionID = in.VulnDefinitionID
	r.RiskKey = in.RiskKey
	r.RiskType = in.RiskType
	r.Title = in.Title
	r.Severity = in.Severity
	r.Score = in.Score
	r.ScoreLevel = in.ScoreLevel
	r.ScoreModelVersion = in.ScoreModelVersion
	r.ScoreFactors = in.ScoreFactors
	r.ScoredAt = in.ScoredAt
	r.RuleID = in.RuleID
	r.Source = in.Source
	r.EvidenceSummary = in.EvidenceSummary
	r.EvidenceRef = in.EvidenceRef
	r.Owner = in.Owner
	r.BusinessUnit = in.BusinessUnit
	r.Suppressed = in.Suppressed
	r.SuppressionRuleID = in.SuppressionRuleID
	r.SuppressedUntil = in.SuppressedUntil
	r.LastSeen = in.ObservedAt
	r.UpdatedBy = in.ActorID
}

func key(projectID uint64, value string) string {
	return fmt.Sprintf("%d:%s", projectID, value)
}
