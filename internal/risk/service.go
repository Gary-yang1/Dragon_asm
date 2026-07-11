//revive:disable:exported

package risk

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/exposure"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var (
	ErrInvalidProjectID        = errors.New("risk: invalid project id")
	ErrInvalidAssetID          = errors.New("risk: invalid asset id")
	ErrInvalidActorID          = errors.New("risk: invalid actor id")
	ErrInvalidRuleID           = errors.New("risk: invalid rule id")
	ErrInvalidSeverity         = errors.New("risk: invalid severity")
	ErrInvalidRiskType         = errors.New("risk: invalid risk_type")
	ErrInvalidMatchType        = errors.New("risk: invalid match_type")
	ErrInvalidMatchValue       = errors.New("risk: invalid match_value")
	ErrInvalidStatusAction     = errors.New("risk: invalid status action")
	ErrInvalidStatusTransition = errors.New("risk: invalid status transition")
	ErrReasonRequired          = errors.New("risk: reason required")
	ErrOwnerRequired           = errors.New("risk: owner required")
	ErrSLARequired             = errors.New("risk: sla due_at required")
	ErrApprovedByRequired      = errors.New("risk: approved_by required")
	ErrReviewRequiredAtMissing = errors.New("risk: review_required_at required")
	ErrInvalidSLAHours         = errors.New("risk: invalid sla hours")
	ErrDefinitionDisabled      = errors.New("risk: vulnerability definition disabled")
	ErrCPENotMatched           = errors.New("risk: cpe does not match definition")
	ErrFieldTooLong            = errors.New("risk: field too long")
)

type auditRecorder interface {
	Record(ctx context.Context, e audit.Event) error
}

type Service struct {
	repo       Repository
	db         *sql.DB
	auditSink  auditRecorder
	now        func() time.Time
	scoreModel ScoreModel
}

type ServiceOption func(*Service)

type ScoreModel struct {
	Version                 string
	Severity                map[string]uint8
	InternetExposure        uint8
	ManagementEntry         uint8
	BusinessUnitCriticality map[string]uint8
}

func WithDB(db *sql.DB) ServiceOption {
	return func(s *Service) { s.db = db }
}

func WithAuditSink(sink auditRecorder) ServiceOption {
	return func(s *Service) { s.auditSink = sink }
}

func WithNow(fn func() time.Time) ServiceOption {
	return func(s *Service) {
		if fn != nil {
			s.now = fn
		}
	}
}

func WithScoreModel(model ScoreModel) ServiceOption {
	return func(s *Service) {
		if model.Version != "" {
			s.scoreModel = normalizeScoreModel(model)
		}
	}
}

func NewService(repo Repository, opts ...ServiceOption) *Service {
	s := &Service{repo: repo, now: func() time.Time { return time.Now().UTC() }, scoreModel: defaultScoreModel()}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Service) CreateDefinition(ctx context.Context, in CreateDefinitionInput) (*VulnerabilityDefinition, error) {
	if in.ProjectID == 0 {
		return nil, ErrInvalidProjectID
	}
	in.RuleID = strings.TrimSpace(in.RuleID)
	if in.RuleID == "" || len(in.RuleID) > 128 {
		return nil, ErrInvalidRuleID
	}
	if in.ActorID == "" || len(in.ActorID) > 64 {
		return nil, ErrInvalidActorID
	}
	in.Severity = defaultString(strings.TrimSpace(in.Severity), SeverityMedium)
	if !validSeverity(in.Severity) {
		return nil, ErrInvalidSeverity
	}
	if err := checkDefinitionLengths(in); err != nil {
		return nil, err
	}
	id, err := s.repo.CreateDefinition(ctx, CreateDefinitionParams(in))
	if err != nil {
		return nil, err
	}
	return s.repo.GetDefinitionByID(ctx, in.ProjectID, id)
}

func (s *Service) CreateRule(ctx context.Context, in CreateRuleInput) (*RiskRule, error) {
	if in.ProjectID == 0 {
		return nil, ErrInvalidProjectID
	}
	in.RuleID = strings.TrimSpace(in.RuleID)
	if in.RuleID == "" || len(in.RuleID) > 128 {
		return nil, ErrInvalidRuleID
	}
	if in.ActorID == "" || len(in.ActorID) > 64 {
		return nil, ErrInvalidActorID
	}
	in.MatchType = strings.TrimSpace(strings.ToLower(in.MatchType))
	if !validMatchType(in.MatchType) {
		return nil, ErrInvalidMatchType
	}
	in.MatchValue = strings.TrimSpace(in.MatchValue)
	if in.MatchValue == "" || len(in.MatchValue) > 255 {
		return nil, ErrInvalidMatchValue
	}
	if in.MatchType == RuleMatchPort {
		port, ok := parseRulePort(in.MatchValue)
		if !ok || port == 0 {
			return nil, ErrInvalidMatchValue
		}
		in.MatchValue = fmt.Sprintf("%d", port)
	}
	in.Severity = defaultString(strings.TrimSpace(in.Severity), SeverityHigh)
	if !validSeverity(in.Severity) {
		return nil, ErrInvalidSeverity
	}
	in.RiskType = defaultString(strings.TrimSpace(in.RiskType), defaultRiskTypeForMatch(in.MatchType))
	if !validRuleRiskType(in.RiskType) {
		return nil, ErrInvalidRiskType
	}
	in.Enabled = true
	if err := checkRuleLengths(in); err != nil {
		return nil, err
	}
	id, err := s.repo.CreateRule(ctx, CreateRuleParams(in))
	if err != nil {
		return nil, err
	}
	return s.repo.GetRuleByID(ctx, in.ProjectID, id)
}

func (s *Service) SetRuleEnabled(ctx context.Context, projectID, id uint64, enabled bool, actorID string) error {
	if projectID == 0 {
		return ErrInvalidProjectID
	}
	if id == 0 {
		return ErrInvalidRuleID
	}
	if actorID == "" || len(actorID) > 64 {
		return ErrInvalidActorID
	}
	return s.repo.SetRuleEnabled(ctx, projectID, id, enabled, actorID)
}

func (s *Service) CreateSuppressionRule(ctx context.Context, in CreateSuppressionRuleInput) (*SuppressionRule, error) {
	if in.ProjectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if in.ActorID == "" || len(in.ActorID) > 64 {
		return nil, ErrInvalidActorID
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 255 {
		return nil, ErrFieldTooLong
	}
	in.RiskType = strings.TrimSpace(in.RiskType)
	if in.RiskType != "" && !validRiskType(in.RiskType) {
		return nil, ErrInvalidRiskType
	}
	in.RuleID = strings.TrimSpace(in.RuleID)
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" {
		return nil, ErrReasonRequired
	}
	if len(in.RuleID) > 128 || len(in.Reason) > 1024 {
		return nil, ErrFieldTooLong
	}
	in.Enabled = true
	id, err := s.repo.CreateSuppressionRule(ctx, CreateSuppressionRuleParams(in))
	if err != nil {
		return nil, err
	}
	return s.repo.GetSuppressionRuleByID(ctx, in.ProjectID, id)
}

func (s *Service) SetSuppressionRuleEnabled(ctx context.Context, projectID, id uint64, enabled bool, actorID string) error {
	if projectID == 0 {
		return ErrInvalidProjectID
	}
	if id == 0 {
		return ErrInvalidRuleID
	}
	if actorID == "" || len(actorID) > 64 {
		return ErrInvalidActorID
	}
	return s.repo.SetSuppressionRuleEnabled(ctx, projectID, id, enabled, actorID)
}

func (s *Service) ListEnabledRules(ctx context.Context, projectID uint64) ([]*RiskRule, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.ListEnabledRules(ctx, projectID)
}

func (s *Service) UpsertSLAPolicy(ctx context.Context, in UpsertSLAPolicyInput) error {
	if in.ProjectID == 0 {
		return ErrInvalidProjectID
	}
	in.Severity = strings.TrimSpace(in.Severity)
	if !validSeverity(in.Severity) {
		return ErrInvalidSeverity
	}
	in.BusinessUnit = strings.TrimSpace(in.BusinessUnit)
	if in.ResolutionHours == 0 {
		return ErrInvalidSLAHours
	}
	if in.ActorID == "" || len(in.ActorID) > 64 {
		return ErrInvalidActorID
	}
	if len(in.TenantID) > 64 || len(in.OrgID) > 64 || len(in.BusinessUnit) > 128 {
		return ErrFieldTooLong
	}
	in.Enabled = true
	return s.repo.UpsertSLAPolicy(ctx, SLAPolicyParams(in))
}

func (s *Service) ListSLAPolicies(ctx context.Context, projectID uint64) ([]*SLAPolicy, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.ListSLAPolicies(ctx, projectID)
}

func (s *Service) ResolveDueAt(ctx context.Context, projectID uint64, severity, businessUnit string, from time.Time) (time.Time, error) {
	if projectID == 0 {
		return time.Time{}, ErrInvalidProjectID
	}
	policy, err := s.findSLAPolicy(ctx, projectID, severity, businessUnit)
	if err != nil {
		return time.Time{}, err
	}
	return from.UTC().Add(time.Duration(policy.ResolutionHours) * time.Hour), nil
}

func (s *Service) RecalculateSLADueAt(ctx context.Context, projectID uint64, limit int32, actorID string) ([]*Risk, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if actorID == "" || len(actorID) > 64 {
		return nil, ErrInvalidActorID
	}
	limit = clampLimit(limit)
	rows, err := s.repo.ListOpenRisksForSLARecalc(ctx, projectID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]*Risk, 0, len(rows))
	for _, r := range rows {
		from := r.FirstSeen
		if from.IsZero() {
			from = s.now()
		}
		dueAt, err := s.ResolveDueAt(ctx, projectID, r.Severity, r.BusinessUnit, from)
		if err != nil {
			return nil, err
		}
		if err := s.repo.UpdateRiskStatus(ctx, StatusUpdateParams{
			ProjectID: projectID, RiskID: r.ID, OldStatus: r.Status, NewStatus: r.Status,
			Owner: r.Owner, SLADueAt: dueAt, ConfirmedAt: r.ConfirmedAt, FixedAt: r.FixedAt,
			ActorID: actorID,
		}); err != nil {
			return nil, err
		}
		after, err := s.repo.GetRiskByID(ctx, projectID, r.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, after)
	}
	return out, nil
}

func (s *Service) CountOverdue(ctx context.Context, projectID uint64, now time.Time) (int64, error) {
	if projectID == 0 {
		return 0, ErrInvalidProjectID
	}
	if now.IsZero() {
		now = s.now()
	}
	return s.repo.CountOverdueRisks(ctx, projectID, now)
}

func (s *Service) ApplyDefinitionMatches(ctx context.Context, projectID, definitionID uint64, matches []MatchInput, actorID string) (ApplyDefinitionResult, error) {
	if projectID == 0 || definitionID == 0 {
		return ApplyDefinitionResult{}, ErrInvalidProjectID
	}
	if actorID == "" || len(actorID) > 64 {
		return ApplyDefinitionResult{}, ErrInvalidActorID
	}
	def, err := s.repo.GetDefinitionByID(ctx, projectID, definitionID)
	if err != nil {
		return ApplyDefinitionResult{}, err
	}
	if !def.Enabled {
		return ApplyDefinitionResult{}, ErrDefinitionDisabled
	}

	var result ApplyDefinitionResult
	err = s.runInTx(ctx, func(ctx context.Context, repo Repository) error {
		for _, match := range matches {
			r, outcome, err := s.applyMatch(ctx, repo, def, match, actorID)
			if err != nil {
				return err
			}
			result.Risks = append(result.Risks, r)
			switch outcome {
			case ChangeTypeNew:
				result.Created++
			case ChangeTypeReopened:
				result.Reopened++
			default:
				result.Updated++
			}
		}
		return nil
	})
	return result, err
}

func (s *Service) ApplyRules(ctx context.Context, projectID uint64, targets []RuleTarget, actorID string) (ApplyRulesResult, error) {
	if projectID == 0 {
		return ApplyRulesResult{}, ErrInvalidProjectID
	}
	if actorID == "" || len(actorID) > 64 {
		return ApplyRulesResult{}, ErrInvalidActorID
	}
	rules, err := s.repo.ListEnabledRules(ctx, projectID)
	if err != nil {
		return ApplyRulesResult{}, err
	}
	var result ApplyRulesResult
	err = s.runInTx(ctx, func(ctx context.Context, repo Repository) error {
		for _, target := range targets {
			if target.ProjectID == 0 {
				target.ProjectID = projectID
			}
			if target.ProjectID != projectID {
				return ErrInvalidProjectID
			}
			if target.AssetID == 0 {
				return ErrInvalidAssetID
			}
			for _, rule := range rules {
				if !ruleMatchesTarget(rule, target) {
					continue
				}
				params := buildRuleRiskParams(rule, target, actorID, observedAtOrNow(s.now, target.ObservedAt))
				s.applyScore(&params, params.ObservedAt)
				r, outcome, err := s.upsertRisk(ctx, repo, params, params.Source, params.ObservedAt)
				if err != nil {
					return err
				}
				result.Risks = append(result.Risks, r)
				switch outcome {
				case ChangeTypeNew:
					result.Created++
				case ChangeTypeReopened:
					result.Reopened++
				default:
					result.Updated++
				}
			}
		}
		return nil
	})
	return result, err
}

func (s *Service) ReportCertificateFinding(ctx context.Context, finding exposure.CertificateFinding) (exposure.CertificateRiskResult, error) {
	if finding.ProjectID == 0 {
		return exposure.CertificateRiskResult{}, ErrInvalidProjectID
	}
	if finding.AssetID == 0 {
		return exposure.CertificateRiskResult{}, ErrInvalidAssetID
	}
	actorID := defaultString(finding.ActorID, "engine")
	if len(actorID) > 64 {
		return exposure.CertificateRiskResult{}, ErrInvalidActorID
	}
	observedAt := observedAtOrNow(s.now, finding.ObservedAt)
	params := certificateRiskParams(finding, actorID, observedAt)
	s.applyScore(&params, observedAt)
	var out exposure.CertificateRiskResult
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository) error {
		r, outcome, err := s.upsertRisk(ctx, repo, params, params.Source, observedAt)
		if err != nil {
			return err
		}
		out.RiskID = r.ID
		out.Outcome = outcome
		return nil
	})
	return out, err
}

func (s *Service) GetByID(ctx context.Context, projectID, id uint64) (*Risk, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	return s.repo.GetRiskByID(ctx, projectID, id)
}

func (s *Service) List(ctx context.Context, projectID uint64, limit, offset int32) ([]*Risk, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	limit = clampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	return s.repo.ListRisks(ctx, projectID, limit, offset)
}

func (s *Service) Count(ctx context.Context, projectID uint64) (int64, error) {
	if projectID == 0 {
		return 0, ErrInvalidProjectID
	}
	return s.repo.CountRisks(ctx, projectID)
}

func (s *Service) RecalculateScores(ctx context.Context, projectID uint64, riskIDs []uint64, actorID, reason string) ([]*Risk, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if actorID == "" || len(actorID) > 64 {
		return nil, ErrInvalidActorID
	}
	reason = defaultString(strings.TrimSpace(reason), "recalculate")
	if len(reason) > 255 {
		return nil, ErrFieldTooLong
	}
	out := make([]*Risk, 0, len(riskIDs))
	err := s.runInTx(ctx, func(ctx context.Context, repo Repository) error {
		for _, id := range riskIDs {
			if id == 0 {
				return ErrNotFound
			}
			r, err := repo.GetRiskByID(ctx, projectID, id)
			if err != nil {
				return err
			}
			scoredAt := s.now()
			score := s.scoreRisk(UpsertRiskParams{
				ProjectID: r.ProjectID, ExposureID: r.ExposureID, RiskType: r.RiskType,
				Severity: r.Severity, BusinessUnit: r.BusinessUnit,
			}, scoredAt)
			if err := repo.UpdateRiskScore(ctx, ScoreUpdateParams{
				ProjectID: r.ProjectID, RiskID: r.ID, Score: score.Score, ScoreLevel: score.ScoreLevel,
				ScoreModelVersion: score.ScoreModelVersion, ScoreFactors: score.ScoreFactors,
				ScoredAt: score.ScoredAt, ActorID: actorID,
			}); err != nil {
				return err
			}
			if err := repo.InsertScoreHistory(ctx, scoreHistoryParams(r, score, reason, actorID)); err != nil {
				return err
			}
			after, err := repo.GetRiskByID(ctx, projectID, id)
			if err != nil {
				return err
			}
			out = append(out, after)
		}
		return nil
	})
	return out, err
}

func (s *Service) ListScoreHistory(ctx context.Context, projectID, riskID uint64) ([]*ScoreHistory, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if riskID == 0 {
		return nil, ErrNotFound
	}
	return s.repo.ListScoreHistory(ctx, projectID, riskID)
}

func (s *Service) TransitionStatus(ctx context.Context, in StatusTransitionInput) (*Risk, error) {
	if in.ProjectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if in.RiskID == 0 {
		return nil, ErrNotFound
	}
	if in.ActorID == "" || len(in.ActorID) > 64 {
		return nil, ErrInvalidActorID
	}
	in.Action = strings.TrimSpace(in.Action)
	if !validStatusAction(in.Action) {
		return nil, ErrInvalidStatusAction
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if len(in.Reason) > 1024 || len(in.Meta.RequestID) > 128 {
		return nil, ErrFieldTooLong
	}
	var after *Risk
	err := s.runInTxWithAudit(ctx, func(ctx context.Context, repo Repository, sink auditRecorder) error {
		before, err := repo.GetRiskByIDForUpdate(ctx, in.ProjectID, in.RiskID)
		if err != nil {
			return err
		}
		next, err := nextRiskStatus(in.Action, before.Status)
		if err != nil {
			return err
		}
		if err := validateTransitionInput(in, next); err != nil {
			return err
		}
		update := buildStatusUpdate(before, in, next, s.now())
		if update.SLADueAt.IsZero() || isZeroTime(update.SLADueAt) {
			dueAt, err := s.ResolveDueAt(ctx, before.ProjectID, before.Severity, before.BusinessUnit, s.now())
			if err == nil {
				update.SLADueAt = dueAt
			} else if next == StatusAssigned {
				if errors.Is(err, ErrNotFound) {
					return ErrSLARequired
				}
				return err
			}
		}
		if err := repo.UpdateRiskStatus(ctx, update); err != nil {
			return err
		}
		after, err = repo.GetRiskByID(ctx, in.ProjectID, in.RiskID)
		if err != nil {
			return err
		}
		if err := repo.InsertStatusHistory(ctx, StatusHistoryParams{
			TenantID: before.TenantID, OrgID: before.OrgID, ProjectID: before.ProjectID, RiskID: before.ID,
			Action: in.Action, OldStatus: before.Status, NewStatus: next,
			ActorID: in.ActorID, Reason: in.Reason, RequestID: in.Meta.RequestID,
		}); err != nil {
			return err
		}
		if isDecisionStatus(next) {
			if err := repo.InsertRiskDecision(ctx, RiskDecisionParams{
				TenantID: before.TenantID, OrgID: before.OrgID, ProjectID: before.ProjectID, RiskID: before.ID,
				Decision: next, Reason: in.Reason, ApprovedBy: in.ApprovedBy,
				ExpiresAt: in.ExpiresAt, ReviewRequiredAt: in.ReviewRequiredAt, ActorID: in.ActorID,
			}); err != nil {
				return err
			}
		}
		return recordStatusAudit(ctx, sink, before, after, in)
	})
	return after, err
}

func (s *Service) ListStatusHistory(ctx context.Context, projectID, riskID uint64) ([]*RiskStatusHistory, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if riskID == 0 {
		return nil, ErrNotFound
	}
	return s.repo.ListStatusHistory(ctx, projectID, riskID)
}

func (s *Service) ListRiskDecisions(ctx context.Context, projectID, riskID uint64) ([]*RiskDecision, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if riskID == 0 {
		return nil, ErrNotFound
	}
	return s.repo.ListRiskDecisions(ctx, projectID, riskID)
}

func (s *Service) ReopenExpiredDecisions(ctx context.Context, projectID uint64, limit int32, actorID string) (ApplyRulesResult, error) {
	if projectID == 0 {
		return ApplyRulesResult{}, ErrInvalidProjectID
	}
	if actorID == "" || len(actorID) > 64 {
		return ApplyRulesResult{}, ErrInvalidActorID
	}
	limit = clampLimit(limit)
	decisions, err := s.repo.ListExpiredRiskDecisions(ctx, projectID, s.now(), limit)
	if err != nil {
		return ApplyRulesResult{}, err
	}
	var result ApplyRulesResult
	for _, d := range decisions {
		r, err := s.TransitionStatus(ctx, StatusTransitionInput{
			ProjectID: projectID, RiskID: d.RiskID, Action: StatusActionReopen,
			ActorID: actorID, Reason: "risk decision expired or requires review",
		})
		if err != nil {
			if errors.Is(err, ErrInvalidStatusTransition) {
				continue
			}
			return result, err
		}
		result.Risks = append(result.Risks, r)
		result.Reopened++
	}
	return result, nil
}

func (s *Service) applyMatch(ctx context.Context, repo Repository, def *VulnerabilityDefinition, match MatchInput, actorID string) (*Risk, string, error) {
	if match.ProjectID == 0 {
		match.ProjectID = def.ProjectID
	}
	if match.ProjectID != def.ProjectID {
		return nil, "", ErrInvalidProjectID
	}
	if match.AssetID == 0 {
		return nil, "", ErrInvalidAssetID
	}
	if !cpeMatches(def.CPEPattern, match.CPE) {
		return nil, "", ErrCPENotMatched
	}
	observedAt := match.ObservedAt
	if observedAt.IsZero() {
		observedAt = s.now()
	}
	params := buildRiskParams(def, match, actorID, observedAt)
	s.applyScore(&params, observedAt)
	return s.upsertRisk(ctx, repo, params, params.Source, observedAt)
}

func (s *Service) upsertRisk(ctx context.Context, repo Repository, params UpsertRiskParams, eventSource string, observedAt time.Time) (*Risk, string, error) {
	if err := s.applySuppression(ctx, repo, &params, observedAt); err != nil {
		return nil, "", err
	}
	existing, err := repo.GetRiskByKey(ctx, params.ProjectID, params.RiskKey)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, "", err
	}
	if errors.Is(err, ErrNotFound) {
		id, err := repo.CreateRisk(ctx, params)
		if err != nil {
			return nil, "", err
		}
		created, err := repo.GetRiskByID(ctx, params.ProjectID, id)
		if err != nil {
			return nil, "", err
		}
		if err := repo.InsertScoreHistory(ctx, scoreHistoryParams(created, scoreFromRisk(created), "create", params.ActorID)); err != nil {
			return nil, "", err
		}
		return created, ChangeTypeNew, repo.InsertChangeEvent(ctx, riskChangeEvent(eventSource, nil, created, ChangeTypeNew, observedAt))
	}

	params.ID = existing.ID
	if existing.Status == StatusFixed {
		if err := repo.ReopenRisk(ctx, params); err != nil {
			return nil, "", err
		}
		after, err := repo.GetRiskByID(ctx, params.ProjectID, existing.ID)
		if err != nil {
			return nil, "", err
		}
		if err := repo.InsertScoreHistory(ctx, scoreHistoryParams(after, scoreFromRisk(after), "reopen", params.ActorID)); err != nil {
			return nil, "", err
		}
		return after, ChangeTypeReopened, repo.InsertChangeEvent(ctx, riskChangeEvent(eventSource, existing, after, ChangeTypeReopened, observedAt))
	}
	if err := repo.RefreshRisk(ctx, params); err != nil {
		return nil, "", err
	}
	after, err := repo.GetRiskByID(ctx, params.ProjectID, existing.ID)
	if err != nil {
		return nil, "", err
	}
	if err := repo.InsertScoreHistory(ctx, scoreHistoryParams(after, scoreFromRisk(after), "refresh", params.ActorID)); err != nil {
		return nil, "", err
	}
	return after, "", nil
}

func (s *Service) runInTx(ctx context.Context, fn func(context.Context, Repository) error) error {
	if s.db == nil {
		return fn(ctx, s.repo)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	repo := NewRepository(dbgen.New(tx))
	if err := fn(ctx, repo); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Service) runInTxWithAudit(ctx context.Context, fn func(context.Context, Repository, auditRecorder) error) error {
	if s.db == nil {
		return fn(ctx, s.repo, s.auditSink)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	repo := NewRepository(dbgen.New(tx))
	txAudit := audit.NewService(audit.NewRepository(dbgen.New(tx)))
	if err := fn(ctx, repo, txAudit); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Service) applySuppression(ctx context.Context, repo Repository, params *UpsertRiskParams, observedAt time.Time) error {
	rules, err := repo.ListActiveSuppressionRules(ctx, params.ProjectID, observedAt)
	if err != nil {
		return err
	}
	params.Suppressed = false
	params.SuppressionRuleID = 0
	params.SuppressedUntil = time.Time{}
	for _, rule := range rules {
		if suppressionMatches(rule, *params) {
			params.Suppressed = true
			params.SuppressionRuleID = rule.ID
			params.SuppressedUntil = rule.ExpiresAt
			return nil
		}
	}
	return nil
}

func (s *Service) findSLAPolicy(ctx context.Context, projectID uint64, severity, businessUnit string) (*SLAPolicy, error) {
	severity = strings.TrimSpace(severity)
	if !validSeverity(severity) {
		return nil, ErrInvalidSeverity
	}
	businessUnit = strings.TrimSpace(businessUnit)
	if businessUnit != "" {
		policy, err := s.repo.GetSLAPolicy(ctx, projectID, severity, businessUnit)
		if err == nil {
			return policy, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	return s.repo.GetSLAPolicy(ctx, projectID, severity, "")
}

func buildRiskParams(def *VulnerabilityDefinition, match MatchInput, actorID string, observedAt time.Time) UpsertRiskParams {
	source := defaultString(match.Source, def.Source)
	return UpsertRiskParams{
		TenantID: match.TenantID, OrgID: match.OrgID, ProjectID: def.ProjectID, AssetID: match.AssetID,
		ExposureID: match.ExposureID, VulnDefinitionID: def.ID,
		RiskKey:  riskKey(def.RuleID, match.AssetID, match.ExposureID),
		RiskType: TypeVulnerability, Title: def.Title, Severity: def.Severity,
		Score: severityScore(def.Severity), RuleID: def.RuleID, Source: source,
		EvidenceSummary: match.EvidenceSummary, EvidenceRef: match.EvidenceRef,
		Status: StatusNew, Owner: match.Owner, BusinessUnit: match.BusinessUnit,
		ObservedAt: observedAt, ActorID: actorID,
	}
}

func buildRuleRiskParams(rule *RiskRule, target RuleTarget, actorID string, observedAt time.Time) UpsertRiskParams {
	source := defaultString(target.Source, rule.Source)
	return UpsertRiskParams{
		TenantID: target.TenantID, OrgID: target.OrgID, ProjectID: rule.ProjectID, AssetID: target.AssetID,
		ExposureID: target.ExposureID, VulnDefinitionID: 0,
		RiskKey:  ruleRiskKey(rule.RuleID, target.AssetID, target.ExposureID),
		RiskType: rule.RiskType, Title: rule.Name, Severity: rule.Severity,
		Score: severityScore(rule.Severity), RuleID: rule.RuleID, Source: source,
		EvidenceSummary: defaultString(target.EvidenceSummary, ruleEvidenceSummary(rule, target)),
		EvidenceRef:     target.EvidenceRef,
		Status:          StatusNew, Owner: target.Owner, BusinessUnit: target.BusinessUnit,
		ObservedAt: observedAt, ActorID: actorID,
	}
}

func certificateRiskParams(finding exposure.CertificateFinding, actorID string, observedAt time.Time) UpsertRiskParams {
	severity := SeverityHigh
	title := "Certificate expiring soon"
	if finding.State == "expired" {
		severity = SeverityCritical
		title = "Certificate expired"
	}
	summary := strings.TrimSpace(finding.EvidenceSummary)
	if summary == "" {
		summary = fmt.Sprintf("certificate %q expires at %s", finding.CertSubject, finding.CertNotAfter.UTC().Format(time.RFC3339))
	}
	return UpsertRiskParams{
		TenantID: finding.TenantID, OrgID: finding.OrgID, ProjectID: finding.ProjectID,
		AssetID: finding.AssetID, ExposureID: finding.ExposureID,
		RiskKey:  fmt.Sprintf("certificate:expiry:asset:%d:exposure:%d", finding.AssetID, finding.ExposureID),
		RiskType: TypeExpiredCertificate, Title: title, Severity: severity,
		Score: severityScore(severity), RuleID: "builtin:certificate_expiry", Source: defaultString(finding.Source, "discovery"),
		EvidenceSummary: summary, EvidenceRef: finding.ExposureKey,
		Status: StatusNew, Owner: finding.Owner, BusinessUnit: finding.BusinessUnit,
		ObservedAt: observedAt, ActorID: actorID,
	}
}

func riskKey(ruleID string, assetID, exposureID uint64) string {
	return fmt.Sprintf("vuln:%s:asset:%d:exposure:%d", ruleID, assetID, exposureID)
}

func ruleRiskKey(ruleID string, assetID, exposureID uint64) string {
	return fmt.Sprintf("rule:%s:asset:%d:exposure:%d", ruleID, assetID, exposureID)
}

func riskChangeEvent(source string, before, after *Risk, changeType string, detectedAt time.Time) ChangeEventParams {
	beforeJSON := riskSnapshot(before)
	afterJSON := riskSnapshot(after)
	title := "Risk discovered"
	if changeType == ChangeTypeReopened {
		title = "Risk reopened"
	}
	return ChangeEventParams{
		TenantID: after.TenantID, OrgID: after.OrgID, ProjectID: after.ProjectID,
		EntityType: EntityTypeRisk, EntityID: after.ID, ChangeType: changeType,
		Severity: after.Severity, Title: title, Summary: after.Title, Source: source,
		Before: beforeJSON, After: afterJSON, DetectedAt: detectedAt,
	}
}

func nextRiskStatus(action, current string) (string, error) {
	switch action {
	case StatusActionConfirm:
		if current == StatusNew || current == StatusReopened {
			return StatusConfirmed, nil
		}
	case StatusActionAssign:
		if current == StatusConfirmed || current == StatusReopened {
			return StatusAssigned, nil
		}
	case StatusActionStartFix:
		if current == StatusAssigned {
			return StatusFixing, nil
		}
	case StatusActionMarkFixed:
		if current == StatusFixing || current == StatusAssigned {
			return StatusFixed, nil
		}
	case StatusActionReopen:
		if current == StatusFixed || current == StatusRiskAccepted || current == StatusFalsePositive {
			return StatusReopened, nil
		}
	case StatusActionAccept:
		if current == StatusConfirmed || current == StatusAssigned || current == StatusFixing {
			return StatusRiskAccepted, nil
		}
	case StatusActionFalsePositive:
		if current == StatusNew || current == StatusConfirmed || current == StatusAssigned || current == StatusFixing {
			return StatusFalsePositive, nil
		}
	}
	return "", ErrInvalidStatusTransition
}

func validStatusAction(action string) bool {
	switch action {
	case StatusActionConfirm, StatusActionAssign, StatusActionStartFix, StatusActionMarkFixed,
		StatusActionReopen, StatusActionAccept, StatusActionFalsePositive:
		return true
	default:
		return false
	}
}

func validateTransitionInput(in StatusTransitionInput, next string) error {
	switch next {
	case StatusAssigned:
		if strings.TrimSpace(in.Owner) == "" {
			return ErrOwnerRequired
		}
	case StatusFixed, StatusReopened, StatusRiskAccepted, StatusFalsePositive:
		if strings.TrimSpace(in.Reason) == "" {
			return ErrReasonRequired
		}
		if isDecisionStatus(next) {
			if strings.TrimSpace(in.ApprovedBy) == "" {
				return ErrApprovedByRequired
			}
			if in.ExpiresAt.IsZero() && in.ReviewRequiredAt.IsZero() {
				return ErrReviewRequiredAtMissing
			}
		}
	}
	return nil
}

func isDecisionStatus(status string) bool {
	return status == StatusRiskAccepted || status == StatusFalsePositive
}

func buildStatusUpdate(before *Risk, in StatusTransitionInput, next string, now time.Time) StatusUpdateParams {
	owner := before.Owner
	slaDueAt := before.SLADueAt
	if next == StatusAssigned {
		owner = strings.TrimSpace(in.Owner)
		slaDueAt = in.SLADueAt
	}
	confirmedAt := before.ConfirmedAt
	if next == StatusConfirmed && isZeroTime(confirmedAt) {
		confirmedAt = now
	}
	fixedAt := before.FixedAt
	switch next {
	case StatusFixed:
		fixedAt = now
	case StatusReopened:
		fixedAt = time.Time{}
	}
	return StatusUpdateParams{
		ProjectID: before.ProjectID, RiskID: before.ID, OldStatus: before.Status, NewStatus: next,
		Owner: owner, SLADueAt: slaDueAt, ConfirmedAt: confirmedAt, FixedAt: fixedAt, ActorID: in.ActorID,
	}
}

func recordStatusAudit(ctx context.Context, sink auditRecorder, before, after *Risk, in StatusTransitionInput) error {
	if sink == nil {
		return nil
	}
	return sink.Record(ctx, audit.Event{
		TenantID:     after.TenantID,
		OrgID:        after.OrgID,
		ProjectID:    after.ProjectID,
		ActorID:      in.ActorID,
		ActorType:    audit.ActorUser,
		Action:       ActionRiskStatusChange,
		ResourceType: ResourceTypeRisk,
		ResourceID:   fmt.Sprintf("%d", after.ID),
		Result:       audit.ResultSuccess,
		IP:           in.Meta.IP,
		UserAgent:    in.Meta.UserAgent,
		RequestID:    in.Meta.RequestID,
		Before:       before,
		After:        after,
		Metadata: map[string]any{
			"action": in.Action, "old_status": before.Status, "new_status": after.Status,
			"reason": in.Reason, "approved_by": in.ApprovedBy,
			"expires_at": in.ExpiresAt, "review_required_at": in.ReviewRequiredAt,
			"request_id": in.Meta.RequestID,
		},
	})
}

func suppressionMatches(rule *SuppressionRule, params UpsertRiskParams) bool {
	if rule.ProjectID != params.ProjectID || !rule.Enabled {
		return false
	}
	if rule.RiskType != "" && rule.RiskType != params.RiskType {
		return false
	}
	if rule.RuleID != "" && rule.RuleID != params.RuleID {
		return false
	}
	if rule.AssetID != 0 && rule.AssetID != params.AssetID {
		return false
	}
	return true
}

func isZeroTime(t time.Time) bool {
	return t.IsZero() || t.Equal(time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC))
}

func riskSnapshot(r *Risk) json.RawMessage {
	if r == nil {
		return nil
	}
	raw, _ := json.Marshal(map[string]any{
		"id": r.ID, "risk_key": r.RiskKey, "status": r.Status, "severity": r.Severity,
		"score": r.Score, "asset_id": r.AssetID, "exposure_id": r.ExposureID,
		"vuln_definition_id": r.VulnDefinitionID,
	})
	return raw
}

func cpeMatches(pattern, cpe string) bool {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	cpe = strings.TrimSpace(strings.ToLower(cpe))
	if pattern == "" || pattern == "*" {
		return true
	}
	if cpe == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(cpe, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == cpe
}

func validSeverity(v string) bool {
	switch v {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func validRiskType(v string) bool {
	switch v {
	case TypeVulnerability, TypeWeakConfig, TypeSensitiveExposure, TypeUnknownAsset, TypeExpiredCertificate,
		TypeHighRiskPort, TypeHighRiskExposure, TypeShadowIT, TypeVendorExposure:
		return true
	default:
		return false
	}
}

func validRuleRiskType(v string) bool {
	return v != TypeVulnerability && validRiskType(v)
}

func validMatchType(v string) bool {
	switch v {
	case RuleMatchPort, RuleMatchService, RuleMatchWeb, RuleMatchFingerprint:
		return true
	default:
		return false
	}
}

func severityScore(severity string) uint8 {
	switch severity {
	case SeverityCritical:
		return 95
	case SeverityHigh:
		return 80
	case SeverityMedium:
		return 50
	case SeverityLow:
		return 25
	default:
		return 5
	}
}

func defaultScoreModel() ScoreModel {
	return normalizeScoreModel(ScoreModel{
		Version:          "basic-v1",
		InternetExposure: 20,
		ManagementEntry:  10,
		Severity: map[string]uint8{
			SeverityCritical: 40,
			SeverityHigh:     32,
			SeverityMedium:   20,
			SeverityLow:      8,
			SeverityInfo:     2,
		},
	})
}

func normalizeScoreModel(model ScoreModel) ScoreModel {
	if model.Version == "" {
		model.Version = "basic-v1"
	}
	if model.Severity == nil {
		model.Severity = defaultScoreModel().Severity
	}
	if model.BusinessUnitCriticality == nil {
		model.BusinessUnitCriticality = map[string]uint8{}
	}
	normalizedBU := make(map[string]uint8, len(model.BusinessUnitCriticality))
	for k, v := range model.BusinessUnitCriticality {
		normalizedBU[strings.ToLower(strings.TrimSpace(k))] = clampScore(v)
	}
	model.BusinessUnitCriticality = normalizedBU
	return model
}

func (s *Service) applyScore(params *UpsertRiskParams, scoredAt time.Time) {
	score := s.scoreRisk(*params, scoredAt)
	params.Score = score.Score
	params.ScoreLevel = score.ScoreLevel
	params.ScoreModelVersion = score.ScoreModelVersion
	params.ScoreFactors = score.ScoreFactors
	params.ScoredAt = score.ScoredAt
}

func (s *Service) scoreRisk(params UpsertRiskParams, scoredAt time.Time) ScoreResult {
	factors := map[string]int{
		"severity":             int(s.scoreModel.Severity[params.Severity]),
		"internet_exposure":    0,
		"asset_criticality":    int(s.scoreModel.BusinessUnitCriticality[strings.ToLower(strings.TrimSpace(params.BusinessUnit))]),
		"management_entry":     0,
		"exploit_maturity":     0,
		"threat_intel":         0,
		"compensating_control": 0,
		"exposure_age":         0,
	}
	if params.ExposureID != 0 {
		factors["internet_exposure"] = int(s.scoreModel.InternetExposure)
	}
	if isManagementRisk(params) {
		factors["management_entry"] = int(s.scoreModel.ManagementEntry)
	}
	total := 0
	for _, v := range factors {
		total += v
	}
	score := clampScoreInt(total)
	raw, _ := json.Marshal(factors)
	return ScoreResult{
		Score: score, ScoreLevel: scoreLevel(score), ScoreModelVersion: s.scoreModel.Version,
		ScoreFactors: raw, ScoredAt: observedAtOrNow(s.now, scoredAt),
	}
}

func isManagementRisk(params UpsertRiskParams) bool {
	if params.RiskType == TypeHighRiskPort || params.RiskType == TypeHighRiskExposure {
		return true
	}
	title := strings.ToLower(params.Title)
	return strings.Contains(title, "admin") || strings.Contains(title, "management") || strings.Contains(title, "console")
}

func scoreLevel(score uint8) string {
	switch {
	case score >= 90:
		return SeverityCritical
	case score >= 70:
		return SeverityHigh
	case score >= 40:
		return SeverityMedium
	case score >= 10:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func clampScore(v uint8) uint8 {
	if v > 100 {
		return 100
	}
	return v
}

func clampScoreInt(v int) uint8 {
	if v <= 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return uint8(v)
}

func scoreFromRisk(r *Risk) ScoreResult {
	return ScoreResult{
		Score: r.Score, ScoreLevel: r.ScoreLevel, ScoreModelVersion: r.ScoreModelVersion,
		ScoreFactors: r.ScoreFactors, ScoredAt: r.ScoredAt,
	}
}

func scoreHistoryParams(r *Risk, score ScoreResult, reason, actorID string) ScoreHistoryParams {
	return ScoreHistoryParams{
		TenantID: r.TenantID, OrgID: r.OrgID, ProjectID: r.ProjectID, RiskID: r.ID,
		Score: score.Score, ScoreLevel: score.ScoreLevel, ScoreModelVersion: score.ScoreModelVersion,
		ScoreFactors: score.ScoreFactors, Reason: reason, ScoredAt: score.ScoredAt, ActorID: actorID,
	}
}

func defaultRiskTypeForMatch(matchType string) string {
	if matchType == RuleMatchPort {
		return TypeHighRiskPort
	}
	return TypeHighRiskExposure
}

func parseRulePort(value string) (uint32, bool) {
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil || port > 65535 {
		return 0, false
	}
	return uint32(port), true
}

func ruleMatchesTarget(rule *RiskRule, target RuleTarget) bool {
	matchValue := strings.ToLower(strings.TrimSpace(rule.MatchValue))
	switch rule.MatchType {
	case RuleMatchPort:
		port, ok := parseRulePort(rule.MatchValue)
		return ok && target.Port == port
	case RuleMatchService:
		return strings.EqualFold(strings.TrimSpace(target.Service), rule.MatchValue)
	case RuleMatchWeb:
		return containsFold(target.URL, matchValue) || containsFold(target.Name, matchValue) || containsFold(target.Value, matchValue)
	case RuleMatchFingerprint:
		return containsFold(target.Fingerprint, matchValue) || containsFold(target.Name, matchValue) || containsFold(target.Value, matchValue)
	default:
		return false
	}
}

func containsFold(value, needle string) bool {
	return needle != "" && strings.Contains(strings.ToLower(value), needle)
}

func ruleEvidenceSummary(rule *RiskRule, target RuleTarget) string {
	switch rule.MatchType {
	case RuleMatchPort:
		return fmt.Sprintf("high-risk port %d matched rule %s", target.Port, rule.RuleID)
	case RuleMatchService:
		return fmt.Sprintf("service %q matched rule %s", target.Service, rule.RuleID)
	case RuleMatchWeb:
		return fmt.Sprintf("web exposure matched rule %s", rule.RuleID)
	default:
		return fmt.Sprintf("fingerprint matched rule %s", rule.RuleID)
	}
}

func observedAtOrNow(now func() time.Time, t time.Time) time.Time {
	if t.IsZero() {
		return now()
	}
	return t.UTC()
}

func checkDefinitionLengths(in CreateDefinitionInput) error {
	for _, f := range []struct {
		v string
		n int
	}{
		{in.TenantID, 64}, {in.OrgID, 64}, {in.RuleID, 128}, {in.CVEID, 32},
		{in.Title, 255}, {in.Description, 2048}, {in.CPEPattern, 255},
		{in.Remediation, 2048}, {in.Source, 64}, {in.ActorID, 64},
	} {
		if len(f.v) > f.n {
			return ErrFieldTooLong
		}
	}
	return nil
}

func checkRuleLengths(in CreateRuleInput) error {
	for _, f := range []struct {
		v string
		n int
	}{
		{in.TenantID, 64}, {in.OrgID, 64}, {in.RuleID, 128}, {in.Name, 255},
		{in.Description, 2048}, {in.RiskType, 64}, {in.Severity, 32},
		{in.MatchType, 32}, {in.MatchValue, 255}, {in.Remediation, 2048},
		{in.Source, 64}, {in.ActorID, 64},
	} {
		if len(f.v) > f.n {
			return ErrFieldTooLong
		}
	}
	return nil
}

const (
	defaultPageSize int32 = 50
	maxPageSize     int32 = 200
)

func clampLimit(limit int32) int32 {
	if limit <= 0 {
		return defaultPageSize
	}
	if limit > maxPageSize {
		return maxPageSize
	}
	return limit
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
