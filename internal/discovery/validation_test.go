package discovery

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeDomainAndTargetNormalization(t *testing.T) {
	// Lowercase + trim and strip trailing dot.
	t1, err := normalizeScopeTarget(ScopeTargetInput{
		TargetType: TargetTypeDomain,
		MatchMode:  MatchModeInclude,
		Value:      " Example.COM. ",
	}, "actor-01")
	require.NoError(t, err)
	assert.Equal(t, TargetTypeDomain, t1.TargetType)
	assert.Equal(t, MatchModeInclude, t1.MatchMode)
	assert.Equal(t, "example.com", t1.Value)

	_, err = normalizeScopeTarget(ScopeTargetInput{
		TargetType: TargetTypeDomain,
		MatchMode:  MatchModeInclude,
		Value:      "localhost",
	}, "actor-01")
	assert.ErrorIs(t, err, ErrDangerousTarget)
}

func TestValidateScopeTargetsRejectsBadInputAndLength(t *testing.T) {
	_, err := validateScopeTargets([]ScopeTargetInput{
		{TargetType: "bad-type", MatchMode: MatchModeInclude, Value: "example.com"},
	}, "actor-01")
	assert.ErrorIs(t, err, ErrInvalidTargetType)

	_, err = validateScopeTargets([]ScopeTargetInput{
		{TargetType: TargetTypeDomain, MatchMode: "bad-mode", Value: "example.com"},
	}, "actor-01")
	assert.ErrorIs(t, err, ErrInvalidMatchMode)

	// Duplicate targets are deduplicated by normalized form.
	_, err = validateScopeTargets([]ScopeTargetInput{
		{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "Example.Com"},
		{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: "example.com."},
	}, "actor-01")
	assert.ErrorIs(t, err, ErrDuplicateTargets)

	longDomain := make([]byte, maxDomainLen+1)
	for i := range longDomain {
		longDomain[i] = 'a'
	}
	_, err = validateScopeTargets([]ScopeTargetInput{
		{TargetType: TargetTypeDomain, MatchMode: MatchModeInclude, Value: string(longDomain)},
	}, "actor-01")
	assert.ErrorIs(t, err, ErrInvalidTarget)
}

func TestNormalizeDangerousIPAndCIDRRejected(t *testing.T) {
	t.Run("ip", func(t *testing.T) {
		_, err := normalizeScopeTarget(ScopeTargetInput{
			TargetType: TargetTypeIP,
			MatchMode:  MatchModeInclude,
			Value:      "127.0.0.1",
		}, "actor-01")
		assert.ErrorIs(t, err, ErrDangerousTarget)

		_, err = normalizeScopeTarget(ScopeTargetInput{
			TargetType: TargetTypeIP,
			MatchMode:  MatchModeInclude,
			Value:      "169.254.169.254",
		}, "actor-01")
		assert.ErrorIs(t, err, ErrDangerousTarget)

		tgt, err := normalizeScopeTarget(ScopeTargetInput{
			TargetType: TargetTypeIP,
			MatchMode:  MatchModeInclude,
			Value:      "1.2.3.4",
		}, "actor-01")
		require.NoError(t, err)
		assert.Equal(t, "1.2.3.4", tgt.Value)
	})

	t.Run("cidr", func(t *testing.T) {
		_, err := normalizeScopeTarget(ScopeTargetInput{
			TargetType: TargetTypeCIDR,
			MatchMode:  MatchModeInclude,
			Value:      "10.0.0.0/8",
		}, "actor-01")
		assert.ErrorIs(t, err, ErrDangerousTarget)

		tgt, err := normalizeScopeTarget(ScopeTargetInput{
			TargetType: TargetTypeCIDR,
			MatchMode:  MatchModeInclude,
			Value:      "1.1.1.1/32",
		}, "actor-01")
		require.NoError(t, err)
		assert.Equal(t, "1.1.1.1/32", tgt.Value)
	})
}

func TestNormalizeURLAndDangerousHost(t *testing.T) {
	tgt, err := normalizeScopeTarget(ScopeTargetInput{
		TargetType: TargetTypeURL,
		MatchMode:  MatchModeInclude,
		Value:      "https://Example.COM/path?x=1",
	}, "actor-01")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com", tgt.Value)

	_, err = normalizeScopeTarget(ScopeTargetInput{
		TargetType: TargetTypeURL,
		MatchMode:  MatchModeInclude,
		Value:      "tcp://example.com",
	}, "actor-01")
	assert.ErrorIs(t, err, ErrInvalidTarget)

	_, err = normalizeScopeTarget(ScopeTargetInput{
		TargetType: TargetTypeURL,
		MatchMode:  MatchModeInclude,
		Value:      "https://localhost",
	}, "actor-01")
	assert.ErrorIs(t, err, ErrDangerousTarget)
}

func TestValidationWindowAndProjectActorFields(t *testing.T) {
	now := time.Now().UTC()
	require.NoError(t, validateScopeWindow(now, now.Add(time.Hour)))
	assert.ErrorIs(t, validateScopeWindow(now.Add(time.Hour), now), ErrInvalidTimeRange)
	assert.ErrorIs(t, validateScopeMeta("t1", "o1", "", "owner", "actor"), ErrInvalidName)
	assert.ErrorIs(t, validateScopeMeta("t1", "o1", "scope", "", "actor"), ErrInvalidAuthorizedBy)
	assert.ErrorIs(t, validateScopeMeta("t1", "o1", "scope", "owner", ""), ErrInvalidActorID)
}

func TestValidateStatusDefaultsToInactive(t *testing.T) {
	status, err := validateStatus("")
	require.NoError(t, err)
	assert.Equal(t, StatusInactive, status)
}
