package discovery

import (
	"context"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
)

// hostClassifier decides whether a website host is a domain or a subdomain
// asset. It follows the rule passive collection already uses — a scope root is
// a domain and every host beneath one is a subdomain — so a host probed by the
// active engine lands on the same asset key passive discovery produced, instead
// of a second "domain:" record for the same name.
type hostClassifier struct {
	roots map[string]struct{}
}

func newHostClassifier(roots []string) hostClassifier {
	set := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if root = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(root)), "."); root != "" {
			set[root] = struct{}{}
		}
	}
	return hostClassifier{roots: set}
}

// assetType returns asset.TypeDomain or asset.TypeSubdomain for a DNS name.
// Hosts outside every scope root fall back to the public suffix list: the
// registrable name itself is a domain, anything longer is a subdomain.
func (c hostClassifier) assetType(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if _, ok := c.roots[host]; ok {
		return asset.TypeDomain
	}
	for root := range c.roots {
		if strings.HasSuffix(host, "."+root) {
			return asset.TypeSubdomain
		}
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || registrable == host {
		return asset.TypeDomain
	}
	return asset.TypeSubdomain
}

// projectHostClassifier builds a classifier from the domain targets of every
// live scope in the project. All scopes are used, not just the run's, because a
// web probe usually runs on a URL scope while the domains were collected
// passively under a different, domain-typed scope.
func (s *Service) projectHostClassifier(ctx context.Context, projectID uint64) (hostClassifier, error) {
	scopes, err := s.ListScopes(ctx, projectID)
	if err != nil {
		return hostClassifier{}, err
	}
	var roots []string
	for _, scope := range scopes {
		for _, target := range scope.Targets {
			if target.TargetType == TargetTypeDomain && target.MatchMode == MatchModeInclude {
				roots = append(roots, target.Value)
			}
		}
	}
	return newHostClassifier(roots), nil
}
