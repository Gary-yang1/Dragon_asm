package project

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubTXTResolver struct {
	records map[string][]string
	err     error
	queried []string
}

func (s *stubTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	s.queried = append(s.queried, name)
	if s.err != nil {
		return nil, s.err
	}
	records, ok := s.records[name]
	if !ok {
		return nil, errors.New("no such host")
	}
	return records, nil
}

var testSecret = []byte("ownership-challenge-secret-0123456789")

func TestOwnershipTokenIsBoundToProjectAndDomain(t *testing.T) {
	base := OwnershipToken(testSecret, 1, "example.com")

	assert.Equal(t, base, OwnershipToken(testSecret, 1, "example.com"), "the token must be stable so it can be published once")
	assert.Equal(t, base, OwnershipToken(testSecret, 1, "EXAMPLE.COM."), "normalisation must not change the token")

	// A token published for one project must not verify the same domain elsewhere,
	// otherwise one tenant could ride on another tenant's proof.
	assert.NotEqual(t, base, OwnershipToken(testSecret, 2, "example.com"))
	assert.NotEqual(t, base, OwnershipToken(testSecret, 1, "other.com"))
	// And it must depend on the platform secret, or anyone could compute it.
	assert.NotEqual(t, base, OwnershipToken([]byte("different-secret"), 1, "example.com"))

	assert.True(t, strings.HasPrefix(base, "asm-site-verification="),
		"the value is namespaced so an unrelated TXT record cannot be mistaken for a token")
}

func TestBuildOwnershipChallengeDescribesTheRecord(t *testing.T) {
	challenge := BuildOwnershipChallenge(testSecret, 7, " Example.COM. ")

	assert.Equal(t, "example.com", challenge.Domain)
	assert.Equal(t, "_asm-verify.example.com", challenge.RecordName)
	assert.Equal(t, "TXT", challenge.RecordType)
	assert.Equal(t, OwnershipToken(testSecret, 7, "example.com"), challenge.Value)
}

func TestCheckOwnershipTXTAcceptsTheMatchingRecord(t *testing.T) {
	token := OwnershipToken(testSecret, 1, "example.com")
	resolver := &stubTXTResolver{records: map[string][]string{
		"_asm-verify.example.com": {"v=spf1 -all", "  " + token + "  "},
	}}

	require.NoError(t, CheckOwnershipTXT(context.Background(), resolver, testSecret, 1, "example.com"))
	assert.Equal(t, []string{"_asm-verify.example.com"}, resolver.queried)
}

func TestCheckOwnershipTXTRejectsWrongOrMissingToken(t *testing.T) {
	t.Run("no record at all", func(t *testing.T) {
		resolver := &stubTXTResolver{records: map[string][]string{}}
		err := CheckOwnershipTXT(context.Background(), resolver, testSecret, 1, "example.com")
		assert.ErrorIs(t, err, ErrOwnershipChallengeFailed)
	})

	t.Run("unrelated records only", func(t *testing.T) {
		resolver := &stubTXTResolver{records: map[string][]string{
			"_asm-verify.example.com": {"v=spf1 -all", "google-site-verification=abc"},
		}}
		err := CheckOwnershipTXT(context.Background(), resolver, testSecret, 1, "example.com")
		assert.ErrorIs(t, err, ErrOwnershipChallengeFailed)
	})

	t.Run("another project's token does not verify this project", func(t *testing.T) {
		resolver := &stubTXTResolver{records: map[string][]string{
			"_asm-verify.example.com": {OwnershipToken(testSecret, 999, "example.com")},
		}}
		err := CheckOwnershipTXT(context.Background(), resolver, testSecret, 1, "example.com")
		assert.ErrorIs(t, err, ErrOwnershipChallengeFailed)
	})

	t.Run("resolver failure is not treated as proof", func(t *testing.T) {
		resolver := &stubTXTResolver{err: errors.New("dial udp 10.0.0.53:53: timeout")}
		err := CheckOwnershipTXT(context.Background(), resolver, testSecret, 1, "example.com")
		assert.ErrorIs(t, err, ErrOwnershipChallengeFailed)
		// The resolver's view of internal infrastructure must not leak outward.
		assert.NotContains(t, err.Error(), "10.0.0.53")
	})

	t.Run("no resolver fails closed", func(t *testing.T) {
		err := CheckOwnershipTXT(context.Background(), nil, testSecret, 1, "example.com")
		assert.ErrorIs(t, err, ErrOwnershipChallengeFailed)
	})
}

// The whole point of the challenge: a caller must not be able to declare a domain
// verified. Before this, ownership_status came straight from the request body.
func TestOwnershipCannotBeSelfAsserted(t *testing.T) {
	in := DomainInput{ProjectID: 1, Domain: "example.com", OwnershipStatus: VerificationVerified}
	err := normalizeDomainInput(&in)
	assert.ErrorIs(t, err, ErrOwnershipNotSelfAssertable)

	for _, status := range []string{VerificationUnverified, VerificationMismatch, ""} {
		t.Run("allowed/"+status, func(t *testing.T) {
			candidate := DomainInput{ProjectID: 1, Domain: "example.com", OwnershipStatus: status}
			assert.NoError(t, normalizeDomainInput(&candidate))
		})
	}
}
