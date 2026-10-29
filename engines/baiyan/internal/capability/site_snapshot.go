package capability

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"baiyan/internal/contract"
)

// siteSnapshotConfidence is lower than a direct observation: the record is the
// search engine's last crawl, not something this job saw.
const siteSnapshotConfidence = 70

// SiteSnapshot is one website a search engine has indexed under a root domain.
// It carries what the engine recorded on its last crawl; nothing is fetched.
type SiteSnapshot struct {
	Host   string
	Scheme string
	Port   int
	Title  string
	Server string
}

// SiteSnapshotProvider is a passive provider whose results also describe the
// websites it indexed. Providers without such data implement only Discover.
type SiteSnapshotProvider interface {
	DiscoverSites(ctx context.Context, rootDomain string) ([]string, []SiteSnapshot, error)
}

// siteURL is the website identity ASM uses for web assets: scheme, host and an
// explicit port, the same form active web probing records, so a crawled and a
// probed site resolve to one asset.
func (s SiteSnapshot) siteURL() string {
	scheme := s.scheme()
	port := s.port()
	if scheme == "" || port < 1 || port > 65535 || s.Host == "" {
		return ""
	}
	return scheme + "://" + net.JoinHostPort(s.Host, strconv.Itoa(port))
}

func (s SiteSnapshot) scheme() string {
	scheme := strings.ToLower(strings.TrimSpace(s.Scheme))
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return scheme
}

// port defaults to the scheme's standard port when the engine omitted it.
func (s SiteSnapshot) port() int {
	if s.Port != 0 {
		return s.Port
	}
	if s.scheme() == "https" {
		return 443
	}
	return 80
}

// cleanSnapshotText makes crawled text safe to store: control characters become
// spaces, runs of whitespace collapse, and the result fits limit bytes without
// splitting a UTF-8 sequence.
func cleanSnapshotText(value string, limit int) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.Join(strings.FieldsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }), " ")
	for len(value) > limit {
		_, size := utf8.DecodeLastRuneInString(value)
		value = value[:len(value)-size]
	}
	return value
}

// siteFacts turns snapshots into a web asset, the host-contains-web relation
// and a web exposure carrying the crawled title. hostKey maps an accepted host
// to the natural key and client ref of its asset; snapshots for hosts that were
// not accepted (out of scope, over the result cap) are dropped.
func siteFacts(provider string, sites []SiteSnapshot, hostKey func(string) (string, string, bool), observed time.Time) ([]contract.AssetFact, []contract.RelationFact, []contract.ExposureFact) {
	var assets []contract.AssetFact
	var relations []contract.RelationFact
	var exposures []contract.ExposureFact
	seen := map[string]bool{}
	for _, site := range sites {
		site.Host = normalizeDomain(site.Host)
		hostNatural, hostRef, ok := hostKey(site.Host)
		if !ok {
			continue
		}
		siteURL := site.siteURL()
		if siteURL == "" || seen[siteURL] {
			continue
		}
		seen[siteURL] = true
		webRef := stableRef("site", provider, siteURL)
		webNatural := "web:" + siteURL
		assets = append(assets, assetFact(webRef, webNatural, "web", siteURL, provider, observed))
		relations = append(relations, relationFact(stableRef("site-contains", provider, siteURL), "contains", hostRef, hostNatural, webRef, webNatural, provider, observed))

		title := cleanSnapshotText(site.Title, 255)
		server := cleanSnapshotText(site.Server, 512)
		exposure := contract.ExposureFact{
			FactMeta: contract.FactMeta{
				ClientRef: stableRef("site-web", provider, siteURL), NaturalKey: "web:" + provider + ":" + siteURL,
				Source: "baiyan", Provider: provider, ObservedAt: observed, Confidence: siteSnapshotConfidence, ActiveProbe: false,
				EvidenceHash: evidenceHash(provider, "web", siteURL, title, server), EvidenceRef: provider + ":" + siteURL,
			},
			Parent:       contract.FactReference{ClientRef: webRef, NaturalKey: webNatural},
			ExposureType: "web",
			Name:         title,
			// The crawl does not report a status code; ASM treats "unknown" as such.
			Value:       "unknown",
			Protocol:    site.scheme(),
			Port:        uint32(site.port()), // #nosec G115 -- bounded by siteURL
			URL:         siteURL,
			Fingerprint: server,
		}
		exposures = append(exposures, exposure)
	}
	return assets, relations, exposures
}
