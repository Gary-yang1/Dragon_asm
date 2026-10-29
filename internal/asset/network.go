package asset

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	asmcasbin "github.com/Gary-yang1/Dragon_asm/internal/platform/auth/casbin"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

// maxNetworkLookup bounds one batch to a page of the asset list.
const maxNetworkLookup = 100

// ErrNetworkLookupUnavailable means the service was built without a database.
var ErrNetworkLookupUnavailable = errors.New("asset: network attribution store unavailable")

// NetworkInfo is what the platform knows about where an asset sits on the
// network: the engine's identified CDN judgement, if any, and how many live
// names resolve to it. Absence of a role means unknown, not "own origin".
type NetworkInfo struct {
	AssetID     uint64 `json:"asset_id"`
	Role        string `json:"role,omitempty"`
	Provider    string `json:"provider,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	RuleVersion string `json:"rule_version,omitempty"`
	SourceRunID uint64 `json:"source_run_id,omitempty"`
	ObservedAt  string `json:"observed_at,omitempty"`
	// ResolvedBy counts distinct live names with a resolves_to edge to the asset.
	ResolvedBy int64 `json:"resolved_by"`
	// Shared is ResolvedBy >= SharedIPMinNames on an address with no CDN role.
	Shared bool `json:"shared"`
}

// NetworkInfo returns network attribution for the requested assets of one
// project. Assets outside the project are silently absent from the result.
func (s *Service) NetworkInfo(ctx context.Context, projectID uint64, assetIDs []uint64) ([]NetworkInfo, error) {
	if projectID == 0 {
		return nil, ErrInvalidProjectID
	}
	if s.db == nil {
		return nil, ErrNetworkLookupUnavailable
	}
	out := make([]NetworkInfo, 0, len(assetIDs))
	if len(assetIDs) == 0 {
		return out, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(assetIDs)), ",")
	args := make([]any, 0, len(assetIDs)+1)
	args = append(args, projectID)
	for _, id := range assetIDs {
		args = append(args, id)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.id, a.asset_type,
 COALESCE(n.role,''), COALESCE(n.provider,''), COALESCE(n.evidence,''), COALESCE(n.rule_version,''),
 COALESCE(n.source_run_id,0), n.observed_at,
 (SELECT COUNT(DISTINCT r.from_asset_id) FROM asset_relation r
   JOIN asset f ON f.id = r.from_asset_id AND f.deleted_at = '1970-01-01 00:00:00.000'
   WHERE r.project_id = a.project_id AND r.to_asset_id = a.id
     AND r.relation_type = 'resolves_to' AND r.deleted_at = '1970-01-01 00:00:00.000')
 FROM asset a
 LEFT JOIN asset_network_attribution n ON n.project_id = a.project_id AND n.asset_id = a.id
 WHERE a.project_id = ? AND a.deleted_at = '1970-01-01 00:00:00.000' AND a.id IN (`+placeholders+`)
 ORDER BY a.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item NetworkInfo
		var assetType string
		var observed *time.Time
		if err := rows.Scan(&item.AssetID, &assetType, &item.Role, &item.Provider, &item.Evidence, &item.RuleVersion,
			&item.SourceRunID, &observed, &item.ResolvedBy); err != nil {
			return nil, err
		}
		if observed != nil {
			item.ObservedAt = observed.UTC().Format(timeRFC3339Millis)
		}
		item.Shared = assetType == TypeIP && item.Role == "" && item.ResolvedBy >= SharedIPMinNames
		out = append(out, item)
	}
	return out, rows.Err()
}

func parseAssetIDList(raw string) ([]uint64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxNetworkLookup {
		return nil, false
	}
	seen := make(map[uint64]bool, len(parts))
	ids := make([]uint64, 0, len(parts))
	for _, part := range parts {
		id, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil || id == 0 {
			return nil, false
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, true
}

// network serves GET /projects/:project_id/assets/network?asset_ids=1,2,3 so a
// list page reads every row's network attribution in one request.
func (h *Handler) network(c *gin.Context) {
	pid, ok := parseProjectID(c)
	if !ok {
		return
	}
	_, role, ok := h.access(c, pid)
	if !ok || !h.permit(c, role, pid, asmcasbin.PermAssetRead) {
		return
	}
	ids, ok := parseAssetIDList(c.Query("asset_ids"))
	if !ok {
		httpx.BadRequest(c, "asset_ids must list 1-100 positive integers")
		return
	}
	items, err := h.svc.NetworkInfo(c.Request.Context(), pid, ids)
	if err != nil {
		httpx.Internal(c)
		return
	}
	httpx.OK(c, gin.H{"items": items})
}
