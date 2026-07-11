//revive:disable:exported

package discovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

var ErrNotFound = errors.New("discovery: scope not found")

type Repository interface {
	CreateScope(ctx context.Context, in CreateScopeParams) (uint64, error)
	GetScope(ctx context.Context, projectID, scopeID uint64) (*Scope, error)
	ListScopes(ctx context.Context, projectID uint64) ([]*Scope, error)
	UpdateScope(ctx context.Context, in UpdateScopeParams) error
	DeactivateScope(ctx context.Context, projectID, scopeID uint64, actorID string, updatedAtNow func() time.Time) error

	InsertScopeTarget(ctx context.Context, in InsertScopeTargetParams) error
	ListScopeTargets(ctx context.Context, projectID, scopeID uint64) ([]*ScopeTarget, error)
	ClearScopeTargets(ctx context.Context, projectID, scopeID uint64, actorID string, deletedAt time.Time) error

	CreateTaskTemplate(ctx context.Context, in CreateTaskTemplateParams) (uint64, error)
	GetTaskTemplate(ctx context.Context, projectID, templateID uint64) (*TaskTemplate, error)
	ListTaskTemplates(ctx context.Context, projectID uint64) ([]*TaskTemplate, error)
	UpdateTaskTemplate(ctx context.Context, in UpdateTaskTemplateParams) error
	SetTaskTemplateEnabled(ctx context.Context, projectID, templateID uint64, enabled bool, actorID string) error
	DeleteTaskTemplate(ctx context.Context, projectID, templateID uint64, actorID string) error

	CreateTaskRun(ctx context.Context, in CreateTaskRunParams) (uint64, error)
	GetTaskRun(ctx context.Context, projectID, runID uint64) (*TaskRun, error)
	ListTaskRuns(ctx context.Context, projectID uint64) ([]*TaskRun, error)
	ListRunningRunsForReconcile(ctx context.Context, limit int32) ([]*TaskRun, error)
	MarkRunRunning(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, startedAt time.Time) error
	MarkRunDispatched(ctx context.Context, projectID, runID uint64, actorID, fromStatus, engineJobID string, now time.Time) error
	MarkRunDispatchFailed(ctx context.Context, projectID, runID uint64, actorID, fromStatus, errorSummary string, now time.Time) error
	MarkRunSucceeded(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, resultCount uint64, now time.Time) error
	MarkRunPartialSuccess(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, resultCount uint64, now time.Time) error
	MarkRunFailed(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, errorSummary string, resultCount uint64, now time.Time) error
	MarkRunCancelled(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, errorSummary string, now time.Time) error
	IncrementRunAttempt(ctx context.Context, projectID, runID uint64, actorID string, now time.Time) error
	MarkRunCallbackReceived(ctx context.Context, projectID, runID uint64, actorID string, resultCount uint64, now time.Time) error
	InsertDiscoveryCallback(ctx context.Context, in DiscoveryCallback) (bool, error)
	MarkDiscoveryCallbackEnqueued(ctx context.Context, projectID, runID, seq uint64, enqueuedAt time.Time) error
}

type CreateScopeParams struct {
	TenantID     string
	OrgID        string
	ProjectID    uint64
	Name         string
	Status       string
	AuthorizedBy string
	ValidFrom    time.Time
	ValidUntil   time.Time
	ActorID      string
}

type UpdateScopeParams struct {
	ScopeID      uint64
	TenantID     string
	OrgID        string
	ProjectID    uint64
	Name         string
	Status       string
	AuthorizedBy string
	ValidFrom    time.Time
	ValidUntil   time.Time
	ActorID      string
}

type InsertScopeTargetParams struct {
	TenantID   string
	OrgID      string
	ProjectID  uint64
	ScopeID    uint64
	TargetType string
	MatchMode  string
	Value      string
	ActorID    string
}

type CreateTaskTemplateParams struct {
	TenantID       string
	OrgID          string
	ProjectID      uint64
	ScopeID        uint64
	Name           string
	TaskType       string
	Config         string
	Schedule       string
	Enabled        bool
	TimeoutSeconds int
	RateLimit      int
	Concurrency    int
	RetryLimit     int
	ActorID        string
}

type UpdateTaskTemplateParams struct {
	TemplateID     uint64
	TenantID       string
	OrgID          string
	ProjectID      uint64
	Name           string
	TaskType       string
	Config         string
	Schedule       string
	TimeoutSeconds int
	RateLimit      int
	Concurrency    int
	RetryLimit     int
	ActorID        string
}

type CreateTaskRunParams struct {
	TenantID          string
	OrgID             string
	ProjectID         uint64
	TemplateID        uint64
	ScopeID           uint64
	TaskType          string
	Status            string
	Progress          int
	TimeoutSeconds    int
	RateLimit         int
	Concurrency       int
	RetryLimit        int
	Attempt           int
	EngineJobID       string
	DispatchedAt      time.Time
	LastCallbackAt    time.Time
	ResultCount       uint64
	CallbackSecretRef string
	StartedAt         time.Time
	FinishedAt        time.Time
	ErrorSummary      string
	ActorID           string
}

type sqlcRepository struct {
	q *dbgen.Queries
}

func NewRepository(q *dbgen.Queries) Repository {
	return &sqlcRepository{q: q}
}

func (r *sqlcRepository) CreateScope(ctx context.Context, in CreateScopeParams) (uint64, error) {
	res, err := r.q.CreateScope(ctx, dbgen.CreateScopeParams{
		TenantID:     in.TenantID,
		OrgID:        in.OrgID,
		ProjectID:    in.ProjectID,
		Name:         in.Name,
		Status:       in.Status,
		AuthorizedBy: in.AuthorizedBy,
		ValidFrom:    in.ValidFrom,
		ValidUntil:   in.ValidUntil,
		CreatedBy:    in.ActorID,
		UpdatedBy:    in.ActorID,
	})
	if err != nil {
		return 0, err
	}
	return resultID(res)
}

func (r *sqlcRepository) GetScope(ctx context.Context, projectID, scopeID uint64) (*Scope, error) {
	row, err := r.q.GetScopeByID(ctx, dbgen.GetScopeByIDParams{
		ID:        scopeID,
		ProjectID: projectID,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return toDomainScope(row), nil
}

func (r *sqlcRepository) ListScopes(ctx context.Context, projectID uint64) ([]*Scope, error) {
	rows, err := r.q.ListScopesByProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*Scope, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomainScope(row))
	}
	return out, nil
}

func (r *sqlcRepository) UpdateScope(ctx context.Context, in UpdateScopeParams) error {
	return r.q.UpdateScope(ctx, dbgen.UpdateScopeParams{
		Name:         in.Name,
		Status:       in.Status,
		AuthorizedBy: in.AuthorizedBy,
		ValidFrom:    in.ValidFrom,
		ValidUntil:   in.ValidUntil,
		UpdatedBy:    in.ActorID,
		ID:           in.ScopeID,
		ProjectID:    in.ProjectID,
	})
}

func (r *sqlcRepository) DeactivateScope(ctx context.Context, projectID, scopeID uint64, actorID string, updatedAtNow func() time.Time) error {
	if updatedAtNow == nil {
		updatedAtNow = time.Now
	}
	return r.q.UpdateScopeStatus(ctx, dbgen.UpdateScopeStatusParams{
		Status:    StatusInactive,
		UpdatedBy: actorID,
		UpdatedAt: updatedAtNow().UTC(),
		ID:        scopeID,
		ProjectID: projectID,
	})
}

func (r *sqlcRepository) InsertScopeTarget(ctx context.Context, in InsertScopeTargetParams) error {
	return r.q.InsertScopeTarget(ctx, dbgen.InsertScopeTargetParams{
		TenantID:    in.TenantID,
		OrgID:       in.OrgID,
		ProjectID:   in.ProjectID,
		ScopeID:     in.ScopeID,
		TargetType:  in.TargetType,
		MatchMode:   in.MatchMode,
		TargetValue: in.Value,
		CreatedBy:   in.ActorID,
		UpdatedBy:   in.ActorID,
	})
}

func (r *sqlcRepository) ListScopeTargets(ctx context.Context, projectID, scopeID uint64) ([]*ScopeTarget, error) {
	rows, err := r.q.ListScopeTargetsByScope(ctx, dbgen.ListScopeTargetsByScopeParams{
		ScopeID:   scopeID,
		ProjectID: projectID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]*ScopeTarget, 0, len(rows))
	for _, row := range rows {
		out = append(out, &ScopeTarget{
			ID:         row.ID,
			TenantID:   row.TenantID,
			OrgID:      row.OrgID,
			ProjectID:  row.ProjectID,
			ScopeID:    row.ScopeID,
			TargetType: row.TargetType,
			MatchMode:  row.MatchMode,
			Value:      row.TargetValue,
			CreatedAt:  row.CreatedAt,
			UpdatedAt:  row.UpdatedAt,
			CreatedBy:  row.CreatedBy,
			UpdatedBy:  row.UpdatedBy,
			DeletedAt:  row.DeletedAt,
		})
	}
	return out, nil
}

func (r *sqlcRepository) ClearScopeTargets(ctx context.Context, projectID, scopeID uint64, actorID string, deletedAt time.Time) error {
	return r.q.SoftDeleteScopeTargets(ctx, dbgen.SoftDeleteScopeTargetsParams{
		DeletedAt: deletedAt.UTC(),
		UpdatedBy: actorID,
		ScopeID:   scopeID,
		ProjectID: projectID,
	})
}

func (r *sqlcRepository) CreateTaskTemplate(ctx context.Context, in CreateTaskTemplateParams) (uint64, error) {
	res, err := r.q.CreateTaskTemplate(ctx, dbgen.CreateTaskTemplateParams{
		TenantID:       in.TenantID,
		OrgID:          in.OrgID,
		ProjectID:      in.ProjectID,
		ScopeID:        in.ScopeID,
		Name:           in.Name,
		TaskType:       in.TaskType,
		Config:         []byte(in.Config),
		Schedule:       in.Schedule,
		Enabled:        in.Enabled,
		TimeoutSeconds: int32Bounded(in.TimeoutSeconds),
		RateLimit:      int32Bounded(in.RateLimit),
		Concurrency:    int32Bounded(in.Concurrency),
		RetryLimit:     int32Bounded(in.RetryLimit),
		CreatedBy:      in.ActorID,
		UpdatedBy:      in.ActorID,
	})
	if err != nil {
		return 0, err
	}
	return resultID(res)
}

func (r *sqlcRepository) GetTaskTemplate(ctx context.Context, projectID, templateID uint64) (*TaskTemplate, error) {
	row, err := r.q.GetTaskTemplateByID(ctx, dbgen.GetTaskTemplateByIDParams{
		ID:        templateID,
		ProjectID: projectID,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return toDomainTaskTemplate(row), nil
}

func (r *sqlcRepository) ListTaskTemplates(ctx context.Context, projectID uint64) ([]*TaskTemplate, error) {
	rows, err := r.q.ListTaskTemplatesByProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*TaskTemplate, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomainTaskTemplate(row))
	}
	return out, nil
}

func (r *sqlcRepository) UpdateTaskTemplate(ctx context.Context, in UpdateTaskTemplateParams) error {
	return r.q.UpdateTaskTemplate(ctx, dbgen.UpdateTaskTemplateParams{
		Name:           in.Name,
		TaskType:       in.TaskType,
		Config:         []byte(in.Config),
		Schedule:       in.Schedule,
		TimeoutSeconds: int32Bounded(in.TimeoutSeconds),
		RateLimit:      int32Bounded(in.RateLimit),
		Concurrency:    int32Bounded(in.Concurrency),
		RetryLimit:     int32Bounded(in.RetryLimit),
		UpdatedBy:      in.ActorID,
		ID:             in.TemplateID,
		ProjectID:      in.ProjectID,
	})
}

func (r *sqlcRepository) SetTaskTemplateEnabled(ctx context.Context, projectID, templateID uint64, enabled bool, actorID string) error {
	return r.q.SetTaskTemplateEnabled(ctx, dbgen.SetTaskTemplateEnabledParams{
		Enabled:   enabled,
		UpdatedBy: actorID,
		ID:        templateID,
		ProjectID: projectID,
	})
}

func (r *sqlcRepository) DeleteTaskTemplate(ctx context.Context, projectID, templateID uint64, actorID string) error {
	return r.q.SoftDeleteTaskTemplate(ctx, dbgen.SoftDeleteTaskTemplateParams{
		DeletedAt: time.Now().UTC(),
		UpdatedBy: actorID,
		ID:        templateID,
		ProjectID: projectID,
	})
}

func (r *sqlcRepository) CreateTaskRun(ctx context.Context, in CreateTaskRunParams) (uint64, error) {
	res, err := r.q.CreateTaskRun(ctx, dbgen.CreateTaskRunParams{
		TenantID:          in.TenantID,
		OrgID:             in.OrgID,
		ProjectID:         in.ProjectID,
		TemplateID:        in.TemplateID,
		ScopeID:           in.ScopeID,
		TaskType:          in.TaskType,
		Status:            in.Status,
		Progress:          int32Bounded(in.Progress),
		TimeoutSeconds:    int32Bounded(in.TimeoutSeconds),
		RateLimit:         int32Bounded(in.RateLimit),
		Concurrency:       int32Bounded(in.Concurrency),
		RetryLimit:        int32Bounded(in.RetryLimit),
		Attempt:           int32Bounded(in.Attempt),
		EngineJobID:       in.EngineJobID,
		DispatchedAt:      in.DispatchedAt,
		LastCallbackAt:    in.LastCallbackAt,
		ResultCount:       in.ResultCount,
		CallbackSecretRef: in.CallbackSecretRef,
		StartedAt:         in.StartedAt,
		FinishedAt:        in.FinishedAt,
		ErrorSummary:      in.ErrorSummary,
		CreatedBy:         in.ActorID,
		UpdatedBy:         in.ActorID,
	})
	if err != nil {
		return 0, err
	}
	return resultID(res)
}

func (r *sqlcRepository) GetTaskRun(ctx context.Context, projectID, runID uint64) (*TaskRun, error) {
	row, err := r.q.GetTaskRunByID(ctx, dbgen.GetTaskRunByIDParams{
		ID:        runID,
		ProjectID: projectID,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return toDomainTaskRun(row), nil
}

func (r *sqlcRepository) ListTaskRuns(ctx context.Context, projectID uint64) ([]*TaskRun, error) {
	rows, err := r.q.ListTaskRunsByProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*TaskRun, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomainTaskRun(row))
	}
	return out, nil
}

func (r *sqlcRepository) ListRunningRunsForReconcile(ctx context.Context, limit int32) ([]*TaskRun, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.q.ListRunningTaskRunsForReconcile(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]*TaskRun, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomainTaskRun(row))
	}
	return out, nil
}

func (r *sqlcRepository) MarkRunRunning(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, startedAt time.Time) error {
	res, err := r.q.MarkTaskRunRunning(ctx, dbgen.MarkTaskRunRunningParams{
		UpdatedBy: actorID,
		StartedAt: startedAt.UTC(),
		Status:    TaskRunStatusRunning,
		ID:        runID,
		ProjectID: projectID,
		Status_2:  fromStatus,
	})
	return markRunUpdateResultError(res, err)
}

func (r *sqlcRepository) MarkRunDispatched(ctx context.Context, projectID, runID uint64, actorID, fromStatus, engineJobID string, now time.Time) error {
	res, err := r.q.MarkTaskRunDispatched(ctx, dbgen.MarkTaskRunDispatchedParams{
		Status:       TaskRunStatusRunning,
		EngineJobID:  engineJobID,
		DispatchedAt: now.UTC(),
		StartedAt:    now.UTC(),
		UpdatedBy:    actorID,
		ID:           runID,
		ProjectID:    projectID,
		Status_2:     fromStatus,
	})
	return markRunUpdateResultError(res, err)
}

func (r *sqlcRepository) MarkRunDispatchFailed(ctx context.Context, projectID, runID uint64, actorID, fromStatus, errorSummary string, now time.Time) error {
	res, err := r.q.MarkTaskRunDispatchFailed(ctx, dbgen.MarkTaskRunDispatchFailedParams{
		Status:       TaskRunStatusFailed,
		ErrorSummary: errorSummary,
		FinishedAt:   now.UTC(),
		UpdatedBy:    actorID,
		ID:           runID,
		ProjectID:    projectID,
		Status_2:     fromStatus,
	})
	return markRunUpdateResultError(res, err)
}

func (r *sqlcRepository) MarkRunSucceeded(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, resultCount uint64, now time.Time) error {
	res, err := r.q.MarkTaskRunSucceeded(ctx, dbgen.MarkTaskRunSucceededParams{
		Status:       TaskRunStatusSuccess,
		Progress:     100,
		ResultCount:  resultCount,
		ErrorSummary: "",
		FinishedAt:   now.UTC(),
		UpdatedBy:    actorID,
		ID:           runID,
		ProjectID:    projectID,
		Status_2:     fromStatus,
	})
	return markRunUpdateResultError(res, err)
}

func (r *sqlcRepository) MarkRunPartialSuccess(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, resultCount uint64, now time.Time) error {
	res, err := r.q.MarkTaskRunPartialSuccess(ctx, dbgen.MarkTaskRunPartialSuccessParams{
		Status:       TaskRunStatusPartial,
		Progress:     100,
		ResultCount:  resultCount,
		ErrorSummary: "",
		FinishedAt:   now.UTC(),
		UpdatedBy:    actorID,
		ID:           runID,
		ProjectID:    projectID,
		Status_2:     fromStatus,
	})
	return markRunUpdateResultError(res, err)
}

func (r *sqlcRepository) MarkRunFailed(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, errorSummary string, resultCount uint64, now time.Time) error {
	res, err := r.q.MarkTaskRunFailed(ctx, dbgen.MarkTaskRunFailedParams{
		Status:       TaskRunStatusFailed,
		Progress:     0,
		ResultCount:  resultCount,
		ErrorSummary: errorSummary,
		FinishedAt:   now.UTC(),
		UpdatedBy:    actorID,
		ID:           runID,
		ProjectID:    projectID,
		Status_2:     fromStatus,
	})
	return markRunUpdateResultError(res, err)
}

func (r *sqlcRepository) MarkRunCancelled(ctx context.Context, projectID, runID uint64, actorID, fromStatus string, errorSummary string, now time.Time) error {
	res, err := r.q.MarkTaskRunCancelled(ctx, dbgen.MarkTaskRunCancelledParams{
		Status:       TaskRunStatusCancelled,
		Progress:     0,
		ErrorSummary: errorSummary,
		FinishedAt:   now.UTC(),
		UpdatedBy:    actorID,
		ID:           runID,
		ProjectID:    projectID,
		Status_2:     fromStatus,
	})
	return markRunUpdateResultError(res, err)
}

func markRunUpdateResultError(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	if result == nil {
		return ErrInvalidRunTransition
	}
	resultCount, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if resultCount == 0 {
		return ErrInvalidRunTransition
	}
	return nil
}

func (r *sqlcRepository) IncrementRunAttempt(ctx context.Context, projectID, runID uint64, actorID string, now time.Time) error {
	return r.q.IncrementTaskRunAttempt(ctx, dbgen.IncrementTaskRunAttemptParams{
		Attempt:   1,
		UpdatedBy: actorID,
		UpdatedAt: now.UTC(),
		ID:        runID,
		ProjectID: projectID,
	})
}

func (r *sqlcRepository) MarkRunCallbackReceived(ctx context.Context, projectID, runID uint64, actorID string, resultCount uint64, now time.Time) error {
	res, err := r.q.MarkTaskRunCallbackReceived(ctx, dbgen.MarkTaskRunCallbackReceivedParams{
		LastCallbackAt: now.UTC(),
		ResultCount:    resultCount,
		UpdatedBy:      actorID,
		ID:             runID,
		ProjectID:      projectID,
		Status:         TaskRunStatusRunning,
	})
	return markRunUpdateResultError(res, err)
}

func (r *sqlcRepository) InsertDiscoveryCallback(ctx context.Context, in DiscoveryCallback) (bool, error) {
	res, err := r.q.InsertDiscoveryCallback(ctx, dbgen.InsertDiscoveryCallbackParams{
		TenantID:     in.TenantID,
		OrgID:        in.OrgID,
		ProjectID:    in.ProjectID,
		RunID:        in.RunID,
		Seq:          in.Seq,
		Phase:        in.Phase,
		Status:       in.Status,
		PayloadHash:  in.PayloadHash,
		ResultCount:  in.ResultCount,
		ErrorSummary: in.ErrorSummary,
		ReceivedAt:   in.ReceivedAt.UTC(),
	})
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func (r *sqlcRepository) MarkDiscoveryCallbackEnqueued(ctx context.Context, projectID, runID, seq uint64, enqueuedAt time.Time) error {
	return r.q.MarkDiscoveryCallbackEnqueued(ctx, dbgen.MarkDiscoveryCallbackEnqueuedParams{
		EnqueuedAt: enqueuedAt.UTC(),
		ProjectID:  projectID,
		RunID:      runID,
		Seq:        seq,
	})
}

func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func toDomainScope(row dbgen.Scope) *Scope {
	return &Scope{
		ID:           row.ID,
		TenantID:     row.TenantID,
		OrgID:        row.OrgID,
		ProjectID:    row.ProjectID,
		Name:         row.Name,
		Status:       row.Status,
		AuthorizedBy: row.AuthorizedBy,
		ValidFrom:    row.ValidFrom,
		ValidUntil:   row.ValidUntil,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
		CreatedBy:    row.CreatedBy,
		UpdatedBy:    row.UpdatedBy,
		DeletedAt:    row.DeletedAt,
	}
}

func toDomainTaskTemplate(row dbgen.TaskTemplate) *TaskTemplate {
	return &TaskTemplate{
		ID:             row.ID,
		TenantID:       row.TenantID,
		OrgID:          row.OrgID,
		ProjectID:      row.ProjectID,
		ScopeID:        row.ScopeID,
		Name:           row.Name,
		TaskType:       row.TaskType,
		Config:         string(row.Config),
		Schedule:       row.Schedule,
		Enabled:        row.Enabled,
		TimeoutSeconds: int(row.TimeoutSeconds),
		RateLimit:      int(row.RateLimit),
		Concurrency:    int(row.Concurrency),
		RetryLimit:     int(row.RetryLimit),
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
		CreatedBy:      row.CreatedBy,
		UpdatedBy:      row.UpdatedBy,
		DeletedAt:      row.DeletedAt,
	}
}

func toDomainTaskRun(row dbgen.TaskRun) *TaskRun {
	return &TaskRun{
		ID:                row.ID,
		TenantID:          row.TenantID,
		OrgID:             row.OrgID,
		ProjectID:         row.ProjectID,
		TemplateID:        row.TemplateID,
		ScopeID:           row.ScopeID,
		TaskType:          row.TaskType,
		Status:            row.Status,
		Progress:          int(row.Progress),
		TimeoutSeconds:    int(row.TimeoutSeconds),
		RateLimit:         int(row.RateLimit),
		Concurrency:       int(row.Concurrency),
		RetryLimit:        int(row.RetryLimit),
		Attempt:           int(row.Attempt),
		EngineJobID:       row.EngineJobID,
		DispatchedAt:      row.DispatchedAt,
		LastCallbackAt:    row.LastCallbackAt,
		ResultCount:       uint64(row.ResultCount),
		CallbackSecretRef: row.CallbackSecretRef,
		StartedAt:         row.StartedAt,
		FinishedAt:        row.FinishedAt,
		ErrorSummary:      row.ErrorSummary,
		CreatedBy:         row.CreatedBy,
		UpdatedBy:         row.UpdatedBy,
		DeletedAt:         row.DeletedAt,
	}
}

func resultID(res sql.Result) (uint64, error) {
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if id < 0 {
		return 0, fmt.Errorf("discovery: negative insert id %d", id)
	}
	return uint64(id), nil
}

func int32Bounded(v int) int32 {
	if v > math.MaxInt32 || v < math.MinInt32 {
		return 0
	}
	return int32(v)
}
