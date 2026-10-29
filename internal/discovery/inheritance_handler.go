package discovery

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

type derivedSelectionRequest struct {
	ObservationIDs   []uint64 `json:"observation_ids" binding:"required,min=1,max=100,dive,gt=0"`
	ScopeFingerprint string   `json:"scope_fingerprint" binding:"required,len=64"`
	TaskType         string   `json:"task_type" binding:"omitempty,oneof=passive_intel dns port_probe web_probe fingerprint"`
	Reason           string   `json:"reason" binding:"max=500"`
}

func (h *ManagementHandler) listDerivedTargets(c *gin.Context) {
	pid, _, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRead)
	if !ok {
		return
	}
	// This endpoint exposes source asset values as well as run metadata.
	if _, _, _, ok = h.authorize(c, asmcasbin.PermAssetRead); !ok {
		return
	}
	if _, _, _, ok = h.authorize(c, asmcasbin.PermScopeRead); !ok {
		return
	}
	id, ok := managementID(c, "run_id")
	if !ok {
		return
	}
	cursor, err := strconv.ParseUint(c.DefaultQuery("after_id", "0"), 10, 64)
	if err != nil {
		httpx.BadRequest(c, "invalid cursor")
		return
	}
	result, err := h.svc.ListDerivedTargets(c.Request.Context(), pid, id, cursor)
	if err != nil {
		writeManagementError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	httpx.OK(c, result)
}
func (h *ManagementHandler) createContinuation(c *gin.Context) {
	pid, p, _, ok := h.authorize(c, asmcasbin.PermDiscoveryRun)
	if !ok {
		return
	}
	if _, _, _, ok = h.authorize(c, asmcasbin.PermAssetRead); !ok {
		return
	}
	if !p.IsActive() {
		httpx.Conflict(c, errCodeProjectNotActive, "project is not active")
		return
	}
	if _, _, _, ok = h.authorize(c, asmcasbin.PermScopeRead); !ok {
		return
	}
	id, ok := managementID(c, "run_id")
	if !ok {
		return
	}
	var req derivedSelectionRequest
	if c.ShouldBindJSON(&req) != nil || req.TaskType == "" {
		httpx.BadRequest(c, "invalid continuation request")
		return
	}
	item, err := h.svc.CreateContinuationTemplate(c.Request.Context(), CreateContinuationInput{ProjectID: pid, SourceRunID: id, TaskType: req.TaskType, ObservationIDs: req.ObservationIDs, ScopeFingerprint: req.ScopeFingerprint, ActorID: c.GetString(auth.CtxUserID), Meta: managementMeta(c)})
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.OK(c, templateDTO(item))
}
func (h *ManagementHandler) authorizeDerivedTargets(c *gin.Context) {
	pid, p, _, ok := h.authorize(c, asmcasbin.PermScopeWrite)
	if !ok {
		return
	}
	if _, _, _, ok = h.authorize(c, asmcasbin.PermDiscoveryRead); !ok {
		return
	}
	if _, _, _, ok = h.authorize(c, asmcasbin.PermAssetRead); !ok {
		return
	}
	if !p.IsActive() {
		httpx.Conflict(c, errCodeProjectNotActive, "project is not active")
		return
	}
	if _, _, _, ok = h.authorize(c, asmcasbin.PermScopeRead); !ok {
		return
	}
	id, ok := managementID(c, "run_id")
	if !ok {
		return
	}
	var req derivedSelectionRequest
	if c.ShouldBindJSON(&req) != nil || req.Reason == "" {
		httpx.BadRequest(c, "invalid authorization request")
		return
	}
	scope, err := h.svc.AuthorizeDerivedTargets(c.Request.Context(), AuthorizeDerivedInput{ProjectID: pid, SourceRunID: id, ObservationIDs: req.ObservationIDs, ScopeFingerprint: req.ScopeFingerprint, Reason: req.Reason, ActorID: c.GetString(auth.CtxUserID), Meta: managementMeta(c)})
	if err != nil {
		writeManagementError(c, err)
		return
	}
	httpx.OK(c, scopeDTO(scope))
}
