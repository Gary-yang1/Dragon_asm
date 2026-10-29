package discovery

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

type webBlueprintAsset struct {
	ID          uint64
	Kind, Value string
}
type webBlueprintAssetReader interface {
	listWebBlueprintAssets(context.Context, uint64, uint64) ([]webBlueprintAsset, error)
}
type webBlueprintTargets struct {
	URLs      []string
	Truncated bool
}

func (r *sqlcRepository) listWebBlueprintAssets(ctx context.Context, projectID, afterID uint64) ([]webBlueprintAsset, error) {
	rows, err := r.q.ListWebBlueprintAssets(ctx, dbgen.ListWebBlueprintAssetsParams{ProjectID: projectID, AfterID: afterID})
	if err != nil {
		return nil, err
	}
	values := make([]webBlueprintAsset, 0, len(rows))
	for _, row := range rows {
		values = append(values, webBlueprintAsset{ID: row.ID, Kind: row.AssetType, Value: row.Value})
	}
	return values, nil
}

// Resolve only known project hosts and explicitly authorized protocols/ports.
// No DNS lookup or engine call occurs during this local preview.
func (s *Service) resolveWebBlueprintTargets(ctx context.Context, scope *Scope) (webBlueprintTargets, error) {
	result := webBlueprintTargets{URLs: []string{}}
	seen := map[string]bool{}
	add := func(raw string) {
		parsed, err := parseTarget(raw)
		if err != nil || parsed.kind != TargetTypeURL || scopeMatchDecision(scope.Targets, parsed) != ReasonAllowed {
			return
		}
		port := parsed.port
		if port == 0 {
			port = 80
			if parsed.scheme == "https" {
				port = 443
			}
		}
		// The existing scope and dispatch model normalizes URLs to whole-site
		// endpoints. Use the same origin here; paths/queries are not separate
		// baseline targets, and omitted default ports identify the same endpoint.
		key := parsed.scheme + "://" + parsed.domain + ":" + strconv.Itoa(port)
		if seen[key] {
			return
		}
		seen[key] = true
		result.URLs = append(result.URLs, parsed.value)
	}
	addHost := func(host string) {
		add("http://" + host + ":80")
		add("https://" + host + ":443")
	}
	dynamic := false
	for _, target := range scope.Targets {
		if target.MatchMode != MatchModeInclude {
			continue
		}
		switch target.TargetType {
		case TargetTypeDomain:
			addHost(target.Value)
			dynamic = true
		case TargetTypeURL:
			for _, seed := range scopeURLSeeds(target) {
				add(seed)
			}
			dynamic = dynamic || (target.URLRule != nil && target.URLRule.IncludeSubdomains)
		}
	}
	if !dynamic {
		sort.Strings(result.URLs)
		return result, nil
	}
	reader, ok := s.repo.(webBlueprintAssetReader)
	if !ok {
		return result, nil
	}
	var afterID uint64
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		assets, err := reader.listWebBlueprintAssets(ctx, scope.ProjectID, afterID)
		if err != nil {
			return result, err
		}
		if len(assets) == 0 {
			break
		}
		for _, asset := range assets {
			if asset.ID <= afterID {
				return result, errors.New("discovery: asset pagination did not advance")
			}
			afterID = asset.ID
			host := asset.Value
			if asset.Kind == "web" {
				parsed, err := url.Parse(asset.Value)
				if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
					continue
				}
				add(asset.Value)
				host = parsed.Hostname()
			}
			host, err = normalizeDomain(host)
			if err != nil {
				continue
			}
			addHost(host)
			for _, target := range scope.Targets {
				if target.TargetType != TargetTypeURL || target.MatchMode != MatchModeInclude || target.URLRule == nil || !target.URLRule.IncludeSubdomains {
					continue
				}
				anchor, err := url.Parse(target.Value)
				if err != nil {
					continue
				}
				root := strings.ToLower(strings.TrimSuffix(anchor.Hostname(), "."))
				if host != root && !strings.HasSuffix(host, "."+root) {
					continue
				}
				copyTarget := *target
				copyRule := *target.URLRule
				copyRule.IncludeRoot = true
				copyTarget.URLRule = &copyRule
				copyTarget.Value = "https://" + host
				for _, seed := range scopeURLSeeds(&copyTarget) {
					add(seed)
				}
			}
		}
	}
	sort.Strings(result.URLs)
	return result, nil
}
