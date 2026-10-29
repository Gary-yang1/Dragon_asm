package project

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Domain ownership verification.
//
// Scanning authorisation used to rest on two self-asserted fields: a free-text
// scope `authorized_by`, and a `ownership_status` the caller could simply set to
// "verified". Neither is evidence. Before active probing is enabled, the platform
// needs a fact it can check itself — that whoever configured the domain also
// controls its DNS.
//
// The challenge is the standard one: publish a TXT record containing a token the
// platform issues, and the platform resolves it. It proves DNS control, which is
// the closest practical proxy for "authorised to be scanned".

const (
	// ownershipTXTPrefix is the label the token is published under.
	ownershipTXTPrefix = "_asm-verify"
	// ownershipTokenPrefix namespaces the record so an unrelated TXT value cannot
	// be mistaken for a token.
	// #nosec G101 -- a public namespace label for the TXT record, not a credential.
	ownershipTokenPrefix = "asm-site-verification="
	// ownershipLookupTimeout bounds one verification attempt.
	ownershipLookupTimeout = 10 * time.Second
	// maxTXTRecords caps how many records are examined, so a domain publishing
	// thousands of TXT entries cannot turn verification into a memory sink.
	maxTXTRecords = 50
)

// TXTResolver looks up TXT records. Injected so tests do not need real DNS.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type netTXTResolver struct{ resolver *net.Resolver }

func (r netTXTResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.resolver.LookupTXT(ctx, name)
}

// NewSystemTXTResolver returns a resolver backed by the system DNS.
func NewSystemTXTResolver() TXTResolver { return netTXTResolver{resolver: net.DefaultResolver} }

// OwnershipChallenge is what an operator has to publish.
type OwnershipChallenge struct {
	Domain     string `json:"domain"`
	RecordName string `json:"record_name"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
}

// OwnershipToken derives the challenge value for one project and domain.
//
// It is an HMAC over the pair, so it is stable (an operator can publish it once
// and re-verify later), unguessable without the platform secret, and useless on
// another project or domain — a token published for a domain in project A does
// not verify the same domain in project B, which stops one tenant riding on
// another's proof.
func OwnershipToken(secret []byte, projectID uint64, domain string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatUint(projectID, 10)))
	mac.Write([]byte{0})
	mac.Write([]byte(normalizeDomainForToken(domain)))
	return ownershipTokenPrefix + hex.EncodeToString(mac.Sum(nil))
}

// BuildOwnershipChallenge describes the record the operator must publish.
func BuildOwnershipChallenge(secret []byte, projectID uint64, domain string) OwnershipChallenge {
	normalized := normalizeDomainForToken(domain)
	return OwnershipChallenge{
		Domain:     normalized,
		RecordName: ownershipTXTPrefix + "." + normalized,
		RecordType: "TXT",
		Value:      OwnershipToken(secret, projectID, domain),
	}
}

// CheckOwnershipTXT resolves the challenge record and reports whether the
// expected token is present.
//
// Comparison is constant-time. The token is a MAC, so a timing oracle would let
// a caller discover a valid token for a domain they do not control.
func CheckOwnershipTXT(ctx context.Context, resolver TXTResolver, secret []byte, projectID uint64, domain string) error {
	if resolver == nil {
		return ErrOwnershipChallengeFailed
	}
	challenge := BuildOwnershipChallenge(secret, projectID, domain)

	ctx, cancel := context.WithTimeout(ctx, ownershipLookupTimeout)
	defer cancel()

	records, err := resolver.LookupTXT(ctx, challenge.RecordName)
	if err != nil {
		// The DNS error is not surfaced: it carries the resolver's view of the
		// operator's infrastructure and adds nothing the operator cannot see.
		return fmt.Errorf("%w: %s not found", ErrOwnershipChallengeFailed, challenge.RecordName)
	}
	expected := []byte(challenge.Value)
	for i, record := range records {
		if i >= maxTXTRecords {
			break
		}
		if hmac.Equal([]byte(strings.TrimSpace(record)), expected) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s does not contain the expected token", ErrOwnershipChallengeFailed, challenge.RecordName)
}

func normalizeDomainForToken(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// IsDomainOwnershipVerified reports whether the project holds a verified
// ownership proof covering this domain. It satisfies the discovery package's
// OwnershipChecker, which is the gate on active scanning.
//
// A proof on a registrable domain covers its subdomains: proving control of
// example.com is what authorises probing api.example.com, and demanding a
// separate proof per subdomain would make the control unusable in practice.
func (s *Service) IsDomainOwnershipVerified(ctx context.Context, projectID uint64, domain string) (bool, error) {
	if s.workspace == nil {
		return false, ErrWorkspaceUnavailable
	}
	normalized := normalizeDomainForToken(domain)
	if normalized == "" {
		return false, nil
	}
	count, err := s.workspace.CountVerifiedDomainOwnership(ctx, projectID, normalized)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
