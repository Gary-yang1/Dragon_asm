package discovery

import (
	"context"
	"strconv"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

func (h *ManagementHandler) retryNetworkEnrichment(c *gin.Context) {
	pid, p, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRun)
	if !ok {
		return
	}
	if _, _, _, ok = h.authorize(c, asmcasbin.PermAssetRead); !ok {
		return
	}
	if p.Status != "active" {
		httpx.Conflict(c, errCodeProjectNotActive, "项目未启用")
		return
	}
	runID, ok := managementID(c, "run_id")
	if !ok {
		return
	}
	n, err := h.svc.RetryNetworkEnrichment(c.Request.Context(), pid, runID, c.GetString(auth.CtxUserID), managementMeta(c))
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.OK(c, map[string]int64{"queued": n})
}

func (s *Service) RetryNetworkEnrichment(ctx context.Context, projectID, runID uint64, actor string, meta AuditMeta) (int64, error) {
	run, err := s.repo.GetTaskRun(ctx, projectID, runID)
	if err != nil {
		return 0, err
	}
	if run.Status != TaskRunStatusSuccess && run.Status != TaskRunStatusPartial {
		return 0, ErrInvalidRunTransition
	}
	if s.db == nil {
		return 0, errNetworkEnrichment
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE web_network_enrichment e JOIN discovery_observation o ON o.id=e.observation_id AND o.project_id=e.project_id AND o.run_id=e.run_id
 JOIN project p ON p.id=e.project_id JOIN task_run r ON r.id=e.run_id AND r.project_id=e.project_id SET e.state='pending',e.attempts=0,e.lease_token='',e.lease_until='1970-01-01 00:00:00',
 e.next_attempt_at=UTC_TIMESTAMP(3),e.error_summary='',e.source_hash=SHA2(CAST(o.normalized_json AS CHAR),256)
 WHERE e.project_id=? AND e.run_id=? AND (e.state='failed' OR (e.state='complete' AND e.source_hash<>SHA2(CAST(o.normalized_json AS CHAR),256))) AND o.deleted_at='1970-01-01 00:00:00' AND o.ingest_status='materialized'
 AND p.status='active' AND p.deleted_at='1970-01-01 00:00:00' AND r.deleted_at='1970-01-01 00:00:00' AND r.status IN ('success','partial_success')`, projectID, runID)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err = audit.NewService(audit.NewRepository(dbgen.New(tx))).Record(ctx, audit.Event{TenantID: run.TenantID, OrgID: run.OrgID, ActorID: actor, ActorType: audit.ActorUser, Action: "discovery.network_enrichment.retry", ResourceType: "task_run", ResourceID: strconv.FormatUint(runID, 10), IP: meta.IP, UserAgent: meta.UserAgent, RequestID: meta.RequestID, Metadata: map[string]any{"project_id": projectID, "queued": n}}); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}
