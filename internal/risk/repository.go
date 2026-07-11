//revive:disable:exported

package risk

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var ErrNotFound = errors.New("risk: not found")

type Repository interface {
	CreateDefinition(ctx context.Context, in CreateDefinitionParams) (uint64, error)
	GetDefinitionByID(ctx context.Context, projectID, id uint64) (*VulnerabilityDefinition, error)
	GetDefinitionByRuleID(ctx context.Context, projectID uint64, ruleID string) (*VulnerabilityDefinition, error)
	ListDefinitions(ctx context.Context, projectID uint64) ([]*VulnerabilityDefinition, error)
	CreateRule(ctx context.Context, in CreateRuleParams) (uint64, error)
	GetRuleByID(ctx context.Context, projectID, id uint64) (*RiskRule, error)
	GetRuleByRuleID(ctx context.Context, projectID uint64, ruleID string) (*RiskRule, error)
	ListEnabledRules(ctx context.Context, projectID uint64) ([]*RiskRule, error)
	SetRuleEnabled(ctx context.Context, projectID, id uint64, enabled bool, actorID string) error
	CreateRisk(ctx context.Context, in UpsertRiskParams) (uint64, error)
	GetRiskByID(ctx context.Context, projectID, id uint64) (*Risk, error)
	GetRiskByIDForUpdate(ctx context.Context, projectID, id uint64) (*Risk, error)
	GetRiskByKey(ctx context.Context, projectID uint64, riskKey string) (*Risk, error)
	ListRisks(ctx context.Context, projectID uint64, limit, offset int32) ([]*Risk, error)
	CountRisks(ctx context.Context, projectID uint64) (int64, error)
	RefreshRisk(ctx context.Context, in UpsertRiskParams) error
	ReopenRisk(ctx context.Context, in UpsertRiskParams) error
	UpdateRiskScore(ctx context.Context, in ScoreUpdateParams) error
	InsertScoreHistory(ctx context.Context, in ScoreHistoryParams) error
	ListScoreHistory(ctx context.Context, projectID, riskID uint64) ([]*ScoreHistory, error)
	UpdateRiskStatus(ctx context.Context, in StatusUpdateParams) error
	InsertStatusHistory(ctx context.Context, in StatusHistoryParams) error
	ListStatusHistory(ctx context.Context, projectID, riskID uint64) ([]*RiskStatusHistory, error)
	CreateSuppressionRule(ctx context.Context, in CreateSuppressionRuleParams) (uint64, error)
	GetSuppressionRuleByID(ctx context.Context, projectID, id uint64) (*SuppressionRule, error)
	ListActiveSuppressionRules(ctx context.Context, projectID uint64, now time.Time) ([]*SuppressionRule, error)
	SetSuppressionRuleEnabled(ctx context.Context, projectID, id uint64, enabled bool, actorID string) error
	InsertRiskDecision(ctx context.Context, in RiskDecisionParams) error
	ListRiskDecisions(ctx context.Context, projectID, riskID uint64) ([]*RiskDecision, error)
	ListExpiredRiskDecisions(ctx context.Context, projectID uint64, now time.Time, limit int32) ([]*RiskDecision, error)
	UpsertSLAPolicy(ctx context.Context, in SLAPolicyParams) error
	GetSLAPolicy(ctx context.Context, projectID uint64, severity, businessUnit string) (*SLAPolicy, error)
	ListSLAPolicies(ctx context.Context, projectID uint64) ([]*SLAPolicy, error)
	ListOpenRisksForSLARecalc(ctx context.Context, projectID uint64, limit int32) ([]*Risk, error)
	CountOverdueRisks(ctx context.Context, projectID uint64, now time.Time) (int64, error)
	InsertChangeEvent(ctx context.Context, in ChangeEventParams) error
}

type CreateDefinitionParams struct {
	TenantID    string
	OrgID       string
	ProjectID   uint64
	RuleID      string
	CVEID       string
	Title       string
	Description string
	Severity    string
	CPEPattern  string
	Remediation string
	Source      string
	Enabled     bool
	ActorID     string
}

type CreateRuleParams struct {
	TenantID    string
	OrgID       string
	ProjectID   uint64
	RuleID      string
	Name        string
	Description string
	RiskType    string
	Severity    string
	MatchType   string
	MatchValue  string
	Remediation string
	Source      string
	Enabled     bool
	ActorID     string
}

type UpsertRiskParams struct {
	ID                uint64
	TenantID          string
	OrgID             string
	ProjectID         uint64
	AssetID           uint64
	ExposureID        uint64
	VulnDefinitionID  uint64
	RiskKey           string
	RiskType          string
	Title             string
	Severity          string
	Score             uint8
	ScoreLevel        string
	ScoreModelVersion string
	ScoreFactors      json.RawMessage
	ScoredAt          time.Time
	RuleID            string
	Source            string
	EvidenceSummary   string
	EvidenceRef       string
	Status            string
	Owner             string
	BusinessUnit      string
	SLADueAt          time.Time
	Suppressed        bool
	SuppressionRuleID uint64
	SuppressedUntil   time.Time
	ObservedAt        time.Time
	ActorID           string
}

type CreateSuppressionRuleParams struct {
	TenantID  string
	OrgID     string
	ProjectID uint64
	Name      string
	RiskType  string
	RuleID    string
	AssetID   uint64
	Reason    string
	ExpiresAt time.Time
	Enabled   bool
	ActorID   string
}

type RiskDecisionParams struct {
	TenantID         string
	OrgID            string
	ProjectID        uint64
	RiskID           uint64
	Decision         string
	Reason           string
	ApprovedBy       string
	ExpiresAt        time.Time
	ReviewRequiredAt time.Time
	ActorID          string
}

type SLAPolicyParams struct {
	TenantID        string
	OrgID           string
	ProjectID       uint64
	Severity        string
	BusinessUnit    string
	ResponseHours   uint32
	ResolutionHours uint32
	Enabled         bool
	ActorID         string
}

type ScoreUpdateParams struct {
	ProjectID         uint64
	RiskID            uint64
	Score             uint8
	ScoreLevel        string
	ScoreModelVersion string
	ScoreFactors      json.RawMessage
	ScoredAt          time.Time
	ActorID           string
}

type ScoreHistoryParams struct {
	TenantID          string
	OrgID             string
	ProjectID         uint64
	RiskID            uint64
	Score             uint8
	ScoreLevel        string
	ScoreModelVersion string
	ScoreFactors      json.RawMessage
	Reason            string
	ScoredAt          time.Time
	ActorID           string
}

type StatusUpdateParams struct {
	ProjectID   uint64
	RiskID      uint64
	OldStatus   string
	NewStatus   string
	Owner       string
	SLADueAt    time.Time
	ConfirmedAt time.Time
	FixedAt     time.Time
	ActorID     string
}

type StatusHistoryParams struct {
	TenantID  string
	OrgID     string
	ProjectID uint64
	RiskID    uint64
	Action    string
	OldStatus string
	NewStatus string
	ActorID   string
	Reason    string
	RequestID string
}

type ChangeEventParams struct {
	TenantID   string
	OrgID      string
	ProjectID  uint64
	EntityType string
	EntityID   uint64
	ChangeType string
	Severity   string
	Title      string
	Summary    string
	Source     string
	Before     json.RawMessage
	After      json.RawMessage
	DetectedAt time.Time
}

type sqlcRepository struct {
	q *dbgen.Queries
}

func NewRepository(q *dbgen.Queries) Repository {
	return &sqlcRepository{q: q}
}

func (r *sqlcRepository) CreateDefinition(ctx context.Context, in CreateDefinitionParams) (uint64, error) {
	res, err := r.q.CreateVulnerabilityDefinition(ctx, dbgen.CreateVulnerabilityDefinitionParams{
		TenantID:    in.TenantID,
		OrgID:       in.OrgID,
		ProjectID:   in.ProjectID,
		RuleID:      in.RuleID,
		CveID:       in.CVEID,
		Title:       in.Title,
		Description: in.Description,
		Severity:    in.Severity,
		CpePattern:  in.CPEPattern,
		Remediation: in.Remediation,
		Source:      in.Source,
		Enabled:     in.Enabled,
		CreatedBy:   in.ActorID,
		UpdatedBy:   in.ActorID,
	})
	if err != nil {
		return 0, err
	}
	return resultID(res)
}

func (r *sqlcRepository) GetDefinitionByID(ctx context.Context, projectID, id uint64) (*VulnerabilityDefinition, error) {
	row, err := r.q.GetVulnerabilityDefinitionByID(ctx, dbgen.GetVulnerabilityDefinitionByIDParams{ID: id, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toDefinition(row), nil
}

func (r *sqlcRepository) GetDefinitionByRuleID(ctx context.Context, projectID uint64, ruleID string) (*VulnerabilityDefinition, error) {
	row, err := r.q.GetVulnerabilityDefinitionByRuleID(ctx, dbgen.GetVulnerabilityDefinitionByRuleIDParams{ProjectID: projectID, RuleID: ruleID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toDefinition(row), nil
}

func (r *sqlcRepository) ListDefinitions(ctx context.Context, projectID uint64) ([]*VulnerabilityDefinition, error) {
	rows, err := r.q.ListVulnerabilityDefinitionsByProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*VulnerabilityDefinition, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDefinition(row))
	}
	return out, nil
}

func (r *sqlcRepository) CreateRule(ctx context.Context, in CreateRuleParams) (uint64, error) {
	res, err := r.q.CreateRiskRule(ctx, dbgen.CreateRiskRuleParams{
		TenantID:    in.TenantID,
		OrgID:       in.OrgID,
		ProjectID:   in.ProjectID,
		RuleID:      in.RuleID,
		Name:        in.Name,
		Description: in.Description,
		RiskType:    in.RiskType,
		Severity:    in.Severity,
		MatchType:   in.MatchType,
		MatchValue:  in.MatchValue,
		Remediation: in.Remediation,
		Source:      in.Source,
		Enabled:     in.Enabled,
		CreatedBy:   in.ActorID,
		UpdatedBy:   in.ActorID,
	})
	if err != nil {
		return 0, err
	}
	return resultID(res)
}

func (r *sqlcRepository) GetRuleByID(ctx context.Context, projectID, id uint64) (*RiskRule, error) {
	row, err := r.q.GetRiskRuleByID(ctx, dbgen.GetRiskRuleByIDParams{ID: id, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toRule(row), nil
}

func (r *sqlcRepository) GetRuleByRuleID(ctx context.Context, projectID uint64, ruleID string) (*RiskRule, error) {
	row, err := r.q.GetRiskRuleByRuleID(ctx, dbgen.GetRiskRuleByRuleIDParams{ProjectID: projectID, RuleID: ruleID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toRule(row), nil
}

func (r *sqlcRepository) ListEnabledRules(ctx context.Context, projectID uint64) ([]*RiskRule, error) {
	rows, err := r.q.ListEnabledRiskRules(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*RiskRule, 0, len(rows))
	for _, row := range rows {
		out = append(out, toRule(row))
	}
	return out, nil
}

func (r *sqlcRepository) SetRuleEnabled(ctx context.Context, projectID, id uint64, enabled bool, actorID string) error {
	res, err := r.q.SetRiskRuleEnabled(ctx, dbgen.SetRiskRuleEnabledParams{
		Enabled: enabled, UpdatedBy: actorID, ID: id, ProjectID: projectID,
	})
	return rowsAffectedErr(res, err)
}

func (r *sqlcRepository) CreateRisk(ctx context.Context, in UpsertRiskParams) (uint64, error) {
	observedAt := observedAt(in.ObservedAt)
	res, err := r.q.CreateRisk(ctx, dbgen.CreateRiskParams{
		TenantID:          in.TenantID,
		OrgID:             in.OrgID,
		ProjectID:         in.ProjectID,
		AssetID:           in.AssetID,
		ExposureID:        nullInt64(in.ExposureID),
		VulnDefinitionID:  nullInt64(in.VulnDefinitionID),
		RiskKey:           in.RiskKey,
		RiskType:          in.RiskType,
		Title:             in.Title,
		Severity:          in.Severity,
		Score:             in.Score,
		ScoreLevel:        in.ScoreLevel,
		ScoreModelVersion: in.ScoreModelVersion,
		ScoreFactorsJson:  in.ScoreFactors,
		ScoredAt:          riskTimeForDB(in.ScoredAt),
		RuleID:            in.RuleID,
		Source:            in.Source,
		EvidenceSummary:   in.EvidenceSummary,
		EvidenceRef:       in.EvidenceRef,
		Status:            in.Status,
		Owner:             in.Owner,
		BusinessUnit:      in.BusinessUnit,
		SlaDueAt:          riskTimeForDB(in.SLADueAt),
		Suppressed:        in.Suppressed,
		SuppressionRuleID: nullInt64(in.SuppressionRuleID),
		SuppressedUntil:   riskTimeForDB(in.SuppressedUntil),
		FirstSeen:         observedAt,
		LastSeen:          observedAt,
		ConfirmedAt:       riskTimeForDB(time.Time{}),
		FixedAt:           riskTimeForDB(time.Time{}),
		CreatedBy:         in.ActorID,
		UpdatedBy:         in.ActorID,
	})
	if err != nil {
		return 0, err
	}
	return resultID(res)
}

func (r *sqlcRepository) GetRiskByID(ctx context.Context, projectID, id uint64) (*Risk, error) {
	row, err := r.q.GetRiskByID(ctx, dbgen.GetRiskByIDParams{ID: id, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toRisk(row), nil
}

func (r *sqlcRepository) GetRiskByIDForUpdate(ctx context.Context, projectID, id uint64) (*Risk, error) {
	row, err := r.q.GetRiskByIDForUpdate(ctx, dbgen.GetRiskByIDForUpdateParams{ID: id, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toRisk(row), nil
}

func (r *sqlcRepository) GetRiskByKey(ctx context.Context, projectID uint64, riskKey string) (*Risk, error) {
	row, err := r.q.GetRiskByKey(ctx, dbgen.GetRiskByKeyParams{ProjectID: projectID, RiskKey: riskKey})
	if err != nil {
		return nil, mapErr(err)
	}
	return toRisk(row), nil
}

func (r *sqlcRepository) ListRisks(ctx context.Context, projectID uint64, limit, offset int32) ([]*Risk, error) {
	rows, err := r.q.ListRisksByProject(ctx, dbgen.ListRisksByProjectParams{ProjectID: projectID, Limit: limit, Offset: offset})
	if err != nil {
		return nil, err
	}
	out := make([]*Risk, 0, len(rows))
	for _, row := range rows {
		out = append(out, toRisk(row))
	}
	return out, nil
}

func (r *sqlcRepository) CountRisks(ctx context.Context, projectID uint64) (int64, error) {
	return r.q.CountRisksByProject(ctx, projectID)
}

func (r *sqlcRepository) RefreshRisk(ctx context.Context, in UpsertRiskParams) error {
	res, err := r.q.RefreshRisk(ctx, dbgen.RefreshRiskParams{
		Title:             in.Title,
		Severity:          in.Severity,
		Score:             in.Score,
		ScoreLevel:        in.ScoreLevel,
		ScoreModelVersion: in.ScoreModelVersion,
		ScoreFactorsJson:  in.ScoreFactors,
		ScoredAt:          riskTimeForDB(in.ScoredAt),
		Source:            in.Source,
		EvidenceSummary:   in.EvidenceSummary,
		EvidenceRef:       in.EvidenceRef,
		Owner:             in.Owner,
		BusinessUnit:      in.BusinessUnit,
		Suppressed:        in.Suppressed,
		SuppressionRuleID: nullInt64(in.SuppressionRuleID),
		SuppressedUntil:   riskTimeForDB(in.SuppressedUntil),
		LastSeen:          observedAt(in.ObservedAt),
		UpdatedBy:         in.ActorID,
		ID:                in.ID,
		ProjectID:         in.ProjectID,
	})
	return rowsAffectedErr(res, err)
}

func (r *sqlcRepository) ReopenRisk(ctx context.Context, in UpsertRiskParams) error {
	res, err := r.q.ReopenRisk(ctx, dbgen.ReopenRiskParams{
		Title:             in.Title,
		Severity:          in.Severity,
		Score:             in.Score,
		ScoreLevel:        in.ScoreLevel,
		ScoreModelVersion: in.ScoreModelVersion,
		ScoreFactorsJson:  in.ScoreFactors,
		ScoredAt:          riskTimeForDB(in.ScoredAt),
		Source:            in.Source,
		EvidenceSummary:   in.EvidenceSummary,
		EvidenceRef:       in.EvidenceRef,
		Owner:             in.Owner,
		BusinessUnit:      in.BusinessUnit,
		Suppressed:        in.Suppressed,
		SuppressionRuleID: nullInt64(in.SuppressionRuleID),
		SuppressedUntil:   riskTimeForDB(in.SuppressedUntil),
		LastSeen:          observedAt(in.ObservedAt),
		UpdatedBy:         in.ActorID,
		ID:                in.ID,
		ProjectID:         in.ProjectID,
	})
	return rowsAffectedErr(res, err)
}

func (r *sqlcRepository) UpdateRiskScore(ctx context.Context, in ScoreUpdateParams) error {
	res, err := r.q.UpdateRiskScore(ctx, dbgen.UpdateRiskScoreParams{
		Score:             in.Score,
		ScoreLevel:        in.ScoreLevel,
		ScoreModelVersion: in.ScoreModelVersion,
		ScoreFactorsJson:  in.ScoreFactors,
		ScoredAt:          riskTimeForDB(in.ScoredAt),
		UpdatedBy:         in.ActorID,
		ID:                in.RiskID,
		ProjectID:         in.ProjectID,
	})
	return rowsAffectedErr(res, err)
}

func (r *sqlcRepository) InsertScoreHistory(ctx context.Context, in ScoreHistoryParams) error {
	_, err := r.q.InsertRiskScoreHistory(ctx, dbgen.InsertRiskScoreHistoryParams{
		TenantID:          in.TenantID,
		OrgID:             in.OrgID,
		ProjectID:         in.ProjectID,
		RiskID:            in.RiskID,
		Score:             in.Score,
		ScoreLevel:        in.ScoreLevel,
		ScoreModelVersion: in.ScoreModelVersion,
		ScoreFactorsJson:  in.ScoreFactors,
		Reason:            in.Reason,
		ScoredAt:          riskTimeForDB(in.ScoredAt),
		CreatedBy:         in.ActorID,
	})
	return err
}

func (r *sqlcRepository) ListScoreHistory(ctx context.Context, projectID, riskID uint64) ([]*ScoreHistory, error) {
	rows, err := r.q.ListRiskScoreHistory(ctx, dbgen.ListRiskScoreHistoryParams{ProjectID: projectID, RiskID: riskID})
	if err != nil {
		return nil, err
	}
	out := make([]*ScoreHistory, 0, len(rows))
	for _, row := range rows {
		out = append(out, toScoreHistory(row))
	}
	return out, nil
}

func (r *sqlcRepository) UpdateRiskStatus(ctx context.Context, in StatusUpdateParams) error {
	res, err := r.q.UpdateRiskStatus(ctx, dbgen.UpdateRiskStatusParams{
		Status:      in.NewStatus,
		Owner:       in.Owner,
		SlaDueAt:    riskTimeForDB(in.SLADueAt),
		ConfirmedAt: riskTimeForDB(in.ConfirmedAt),
		FixedAt:     riskTimeForDB(in.FixedAt),
		UpdatedBy:   in.ActorID,
		ID:          in.RiskID,
		ProjectID:   in.ProjectID,
		Status_2:    in.OldStatus,
	})
	return rowsAffectedErr(res, err)
}

func (r *sqlcRepository) InsertStatusHistory(ctx context.Context, in StatusHistoryParams) error {
	_, err := r.q.InsertRiskStatusHistory(ctx, dbgen.InsertRiskStatusHistoryParams{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID, RiskID: in.RiskID,
		Action: in.Action, OldStatus: in.OldStatus, NewStatus: in.NewStatus,
		ActorID: in.ActorID, Reason: in.Reason, RequestID: in.RequestID,
	})
	return err
}

func (r *sqlcRepository) ListStatusHistory(ctx context.Context, projectID, riskID uint64) ([]*RiskStatusHistory, error) {
	rows, err := r.q.ListRiskStatusHistory(ctx, dbgen.ListRiskStatusHistoryParams{ProjectID: projectID, RiskID: riskID})
	if err != nil {
		return nil, err
	}
	out := make([]*RiskStatusHistory, 0, len(rows))
	for _, row := range rows {
		out = append(out, toStatusHistory(row))
	}
	return out, nil
}

func (r *sqlcRepository) CreateSuppressionRule(ctx context.Context, in CreateSuppressionRuleParams) (uint64, error) {
	res, err := r.q.CreateSuppressionRule(ctx, dbgen.CreateSuppressionRuleParams{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		Name: in.Name, RiskType: in.RiskType, RuleID: in.RuleID, AssetID: in.AssetID,
		Reason: in.Reason, ExpiresAt: riskTimeForDB(in.ExpiresAt),
		Enabled: in.Enabled, CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	})
	if err != nil {
		return 0, err
	}
	return resultID(res)
}

func (r *sqlcRepository) GetSuppressionRuleByID(ctx context.Context, projectID, id uint64) (*SuppressionRule, error) {
	row, err := r.q.GetSuppressionRuleByID(ctx, dbgen.GetSuppressionRuleByIDParams{ID: id, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return toSuppressionRule(row), nil
}

func (r *sqlcRepository) ListActiveSuppressionRules(ctx context.Context, projectID uint64, now time.Time) ([]*SuppressionRule, error) {
	rows, err := r.q.ListActiveSuppressionRules(ctx, dbgen.ListActiveSuppressionRulesParams{ProjectID: projectID, ExpiresAt: now.UTC()})
	if err != nil {
		return nil, err
	}
	out := make([]*SuppressionRule, 0, len(rows))
	for _, row := range rows {
		out = append(out, toSuppressionRule(row))
	}
	return out, nil
}

func (r *sqlcRepository) SetSuppressionRuleEnabled(ctx context.Context, projectID, id uint64, enabled bool, actorID string) error {
	res, err := r.q.SetSuppressionRuleEnabled(ctx, dbgen.SetSuppressionRuleEnabledParams{
		Enabled: enabled, UpdatedBy: actorID, ID: id, ProjectID: projectID,
	})
	return rowsAffectedErr(res, err)
}

func (r *sqlcRepository) InsertRiskDecision(ctx context.Context, in RiskDecisionParams) error {
	_, err := r.q.InsertRiskDecision(ctx, dbgen.InsertRiskDecisionParams{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID, RiskID: in.RiskID,
		Decision: in.Decision, Reason: in.Reason, ApprovedBy: in.ApprovedBy,
		ExpiresAt: riskTimeForDB(in.ExpiresAt), ReviewRequiredAt: riskTimeForDB(in.ReviewRequiredAt),
		CreatedBy: in.ActorID,
	})
	return err
}

func (r *sqlcRepository) ListRiskDecisions(ctx context.Context, projectID, riskID uint64) ([]*RiskDecision, error) {
	rows, err := r.q.ListRiskDecisions(ctx, dbgen.ListRiskDecisionsParams{ProjectID: projectID, RiskID: riskID})
	if err != nil {
		return nil, err
	}
	out := make([]*RiskDecision, 0, len(rows))
	for _, row := range rows {
		out = append(out, toRiskDecision(row))
	}
	return out, nil
}

func (r *sqlcRepository) ListExpiredRiskDecisions(ctx context.Context, projectID uint64, now time.Time, limit int32) ([]*RiskDecision, error) {
	rows, err := r.q.ListExpiredRiskDecisions(ctx, dbgen.ListExpiredRiskDecisionsParams{
		ProjectID: projectID, ExpiresAt: now.UTC(), ReviewRequiredAt: now.UTC(), Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]*RiskDecision, 0, len(rows))
	for _, row := range rows {
		out = append(out, toRiskDecision(row))
	}
	return out, nil
}

func (r *sqlcRepository) UpsertSLAPolicy(ctx context.Context, in SLAPolicyParams) error {
	_, err := r.q.UpsertSLAPolicy(ctx, dbgen.UpsertSLAPolicyParams{
		TenantID: in.TenantID, OrgID: in.OrgID, ProjectID: in.ProjectID,
		Severity: in.Severity, BusinessUnit: in.BusinessUnit,
		ResponseHours: in.ResponseHours, ResolutionHours: in.ResolutionHours,
		Enabled: in.Enabled, CreatedBy: in.ActorID, UpdatedBy: in.ActorID,
	})
	return err
}

func (r *sqlcRepository) GetSLAPolicy(ctx context.Context, projectID uint64, severity, businessUnit string) (*SLAPolicy, error) {
	row, err := r.q.GetSLAPolicy(ctx, dbgen.GetSLAPolicyParams{ProjectID: projectID, Severity: severity, BusinessUnit: businessUnit})
	if err != nil {
		return nil, mapErr(err)
	}
	return toSLAPolicy(row), nil
}

func (r *sqlcRepository) ListSLAPolicies(ctx context.Context, projectID uint64) ([]*SLAPolicy, error) {
	rows, err := r.q.ListSLAPoliciesByProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*SLAPolicy, 0, len(rows))
	for _, row := range rows {
		out = append(out, toSLAPolicy(row))
	}
	return out, nil
}

func (r *sqlcRepository) ListOpenRisksForSLARecalc(ctx context.Context, projectID uint64, limit int32) ([]*Risk, error) {
	rows, err := r.q.ListOpenRisksForSLARecalc(ctx, dbgen.ListOpenRisksForSLARecalcParams{ProjectID: projectID, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]*Risk, 0, len(rows))
	for _, row := range rows {
		out = append(out, toRisk(row))
	}
	return out, nil
}

func (r *sqlcRepository) CountOverdueRisks(ctx context.Context, projectID uint64, now time.Time) (int64, error) {
	return r.q.CountOverdueRisks(ctx, dbgen.CountOverdueRisksParams{ProjectID: projectID, SlaDueAt: now.UTC()})
}

func (r *sqlcRepository) InsertChangeEvent(ctx context.Context, in ChangeEventParams) error {
	_, err := r.q.InsertRiskChangeEvent(ctx, dbgen.InsertRiskChangeEventParams{
		TenantID:   in.TenantID,
		OrgID:      in.OrgID,
		ProjectID:  in.ProjectID,
		EntityType: in.EntityType,
		EntityID:   in.EntityID,
		ChangeType: in.ChangeType,
		Severity:   in.Severity,
		Title:      in.Title,
		Summary:    in.Summary,
		Source:     in.Source,
		BeforeJson: in.Before,
		AfterJson:  in.After,
		DetectedAt: in.DetectedAt,
	})
	return err
}

func toDefinition(row dbgen.VulnerabilityDefinition) *VulnerabilityDefinition {
	return &VulnerabilityDefinition{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		RuleID: row.RuleID, CVEID: row.CveID, Title: row.Title, Description: row.Description,
		Severity: row.Severity, CPEPattern: row.CpePattern, Remediation: row.Remediation,
		Source: row.Source, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		CreatedBy: row.CreatedBy, UpdatedBy: row.UpdatedBy,
	}
}

func toRule(row dbgen.RiskRule) *RiskRule {
	return &RiskRule{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		RuleID: row.RuleID, Name: row.Name, Description: row.Description, RiskType: row.RiskType,
		Severity: row.Severity, MatchType: row.MatchType, MatchValue: row.MatchValue,
		Remediation: row.Remediation, Source: row.Source, Enabled: row.Enabled,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, CreatedBy: row.CreatedBy, UpdatedBy: row.UpdatedBy,
	}
}

func toRisk(row dbgen.Risk) *Risk {
	return &Risk{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		AssetID: row.AssetID, ExposureID: uint64FromNull(row.ExposureID), VulnDefinitionID: uint64FromNull(row.VulnDefinitionID),
		RiskKey: row.RiskKey, RiskType: row.RiskType, Title: row.Title, Severity: row.Severity, Score: row.Score,
		ScoreLevel: row.ScoreLevel, ScoreModelVersion: row.ScoreModelVersion, ScoreFactors: row.ScoreFactorsJson, ScoredAt: row.ScoredAt,
		RuleID: row.RuleID, Source: row.Source, EvidenceSummary: row.EvidenceSummary, EvidenceRef: row.EvidenceRef,
		Status: row.Status, Owner: row.Owner, BusinessUnit: row.BusinessUnit, SLADueAt: row.SlaDueAt,
		Suppressed: row.Suppressed, SuppressionRuleID: uint64FromNull(row.SuppressionRuleID), SuppressedUntil: row.SuppressedUntil,
		FirstSeen: row.FirstSeen, LastSeen: row.LastSeen, ConfirmedAt: row.ConfirmedAt, FixedAt: row.FixedAt,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, CreatedBy: row.CreatedBy, UpdatedBy: row.UpdatedBy,
	}
}

func toSuppressionRule(row dbgen.SuppressionRule) *SuppressionRule {
	return &SuppressionRule{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		Name: row.Name, RiskType: row.RiskType, RuleID: row.RuleID, AssetID: row.AssetID,
		Reason: row.Reason, ExpiresAt: row.ExpiresAt, Enabled: row.Enabled,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, CreatedBy: row.CreatedBy, UpdatedBy: row.UpdatedBy,
	}
}

func toRiskDecision(row dbgen.RiskDecision) *RiskDecision {
	return &RiskDecision{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		RiskID: row.RiskID, Decision: row.Decision, Reason: row.Reason, ApprovedBy: row.ApprovedBy,
		ExpiresAt: row.ExpiresAt, ReviewRequiredAt: row.ReviewRequiredAt, CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy,
	}
}

func toSLAPolicy(row dbgen.SlaPolicy) *SLAPolicy {
	return &SLAPolicy{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		Severity: row.Severity, BusinessUnit: row.BusinessUnit,
		ResponseHours: row.ResponseHours, ResolutionHours: row.ResolutionHours, Enabled: row.Enabled,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, CreatedBy: row.CreatedBy, UpdatedBy: row.UpdatedBy,
	}
}

func toScoreHistory(row dbgen.RiskScoreHistory) *ScoreHistory {
	return &ScoreHistory{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		RiskID: row.RiskID, Score: row.Score, ScoreLevel: row.ScoreLevel,
		ScoreModelVersion: row.ScoreModelVersion, ScoreFactors: row.ScoreFactorsJson,
		Reason: row.Reason, ScoredAt: row.ScoredAt, CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy,
	}
}

func toStatusHistory(row dbgen.RiskStatusHistory) *RiskStatusHistory {
	return &RiskStatusHistory{
		ID: row.ID, TenantID: row.TenantID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		RiskID: row.RiskID, Action: row.Action, OldStatus: row.OldStatus, NewStatus: row.NewStatus,
		ActorID: row.ActorID, Reason: row.Reason, RequestID: row.RequestID, CreatedAt: row.CreatedAt,
	}
}

func nullInt64(v uint64) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	if v > uint64(^uint64(0)>>1) {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(v), Valid: true} //nolint:gosec // bounded above.
}

func uint64FromNull(v sql.NullInt64) uint64 {
	if !v.Valid || v.Int64 < 0 {
		return 0
	}
	return uint64(v.Int64) //nolint:gosec // negative checked above.
}

func resultID(res sql.Result) (uint64, error) {
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if id < 0 {
		return 0, fmt.Errorf("risk: negative insert id %d", id)
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

func observedAt(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}

func riskTimeForDB(t time.Time) time.Time {
	if t.IsZero() {
		return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return t.UTC()
}

func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
