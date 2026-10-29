package discovery

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

func TestNormalizeScopeTargetCoverageMode(t *testing.T) {
	exact, err := normalizeScopeTarget(ScopeTargetInput{
		TargetType: TargetTypeDomain,
		MatchMode:  MatchModeInclude,
		Value:      "example.com",
	}, "actor-01")
	require.NoError(t, err)
	assert.Equal(t, CoverageModeExact, exact.CoverageMode)

	withSubdomains, err := normalizeScopeTarget(ScopeTargetInput{
		TargetType:   TargetTypeDomain,
		MatchMode:    MatchModeInclude,
		CoverageMode: CoverageModeSubdomains,
		Value:        "example.com",
	}, "actor-01")
	require.NoError(t, err)
	assert.Equal(t, CoverageModeSubdomains, withSubdomains.CoverageMode)

	_, err = normalizeScopeTarget(ScopeTargetInput{
		TargetType:   TargetTypeIP,
		MatchMode:    MatchModeInclude,
		CoverageMode: CoverageModeSubdomains,
		Value:        "1.1.1.1",
	}, "actor-01")
	assert.ErrorIs(t, err, ErrInvalidCoverageMode)
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

// Non-canonical IPv4 literals are rejected by netip.ParseAddr but expanded by
// the resolver, so before this guard they slipped through the domain path and
// never met the IP denylist. Each value below resolves to loopback, 0.0.0.0, or
// RFC1918 space.
func TestNormalizeRejectsNonCanonicalIPLiteralsOnDomainAndURLPaths(t *testing.T) {
	literals := []string{
		"127.1",         // short-form loopback
		"2130706433",    // decimal loopback
		"0x7f000001",    // hex loopback
		"010.0.0.1",     // octal-looking RFC1918
		"0",             // expands to 0.0.0.0
		"127.0.0.1",     // dotted-quad routed through the domain type
		"instance-data", // bare internal hostname
	}

	for _, value := range literals {
		t.Run("domain/"+value, func(t *testing.T) {
			_, err := normalizeScopeTarget(ScopeTargetInput{
				TargetType: TargetTypeDomain,
				MatchMode:  MatchModeInclude,
				Value:      value,
			}, "actor-01")
			require.Error(t, err, "%q must not be accepted as a scope domain", value)
		})

		t.Run("url/"+value, func(t *testing.T) {
			_, err := normalizeScopeTarget(ScopeTargetInput{
				TargetType: TargetTypeURL,
				MatchMode:  MatchModeInclude,
				Value:      "http://" + value,
			}, "actor-01")
			require.Error(t, err, "http://%s must not be accepted as a scope URL", value)
		})
	}

	// Real domains, including a punycode IDN TLD whose label contains digits,
	// must still pass — the all-numeric rule applies to the whole label.
	for _, value := range []string{"example.com", "sub.example.co.uk", "例子.xn--fiqs8s"} {
		normalized := value
		if value == "例子.xn--fiqs8s" {
			normalized = "xn--fsqu00a.xn--fiqs8s" // already-punycoded form
		}
		t.Run("allowed/"+normalized, func(t *testing.T) {
			tgt, err := normalizeScopeTarget(ScopeTargetInput{
				TargetType: TargetTypeDomain,
				MatchMode:  MatchModeInclude,
				Value:      normalized,
			}, "actor-01")
			require.NoError(t, err)
			assert.Equal(t, normalized, tgt.Value)
		})
	}
}

func TestNormalizeRejectsSpecialUseDomainSuffixes(t *testing.T) {
	for _, value := range []string{
		"metadata.google.internal",
		"db.internal",
		"printer.local",
		"host.localdomain",
		"router.home.arpa",
		"foo.localhost",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := normalizeScopeTarget(ScopeTargetInput{
				TargetType: TargetTypeDomain,
				MatchMode:  MatchModeInclude,
				Value:      value,
			}, "actor-01")
			assert.ErrorIs(t, err, ErrDangerousTarget)
		})
	}
}

func TestNormalizeRejectsIPv6TransitionRanges(t *testing.T) {
	for _, value := range []string{
		"64:ff9b::7f00:1",  // NAT64-embedded loopback
		"2002:7f00:1::",    // 6to4-embedded loopback
		"::127.0.0.1",      // IPv4-compatible loopback
		"2001:0:1::",       // Teredo
		"64:ff9b:1::a00:1", // NAT64 local-use with RFC1918 inside
	} {
		t.Run(value, func(t *testing.T) {
			_, err := normalizeScopeTarget(ScopeTargetInput{
				TargetType: TargetTypeIP,
				MatchMode:  MatchModeInclude,
				Value:      value,
			}, "actor-01")
			assert.ErrorIs(t, err, ErrDangerousTarget)
		})
	}

	// An ordinary global IPv6 address is still allowed.
	tgt, err := normalizeScopeTarget(ScopeTargetInput{
		TargetType: TargetTypeIP,
		MatchMode:  MatchModeInclude,
		Value:      "2606:4700:4700::1111",
	}, "actor-01")
	require.NoError(t, err)
	assert.Equal(t, "2606:4700:4700::1111", tgt.Value)
}

func TestSanitizeEngineErrorSummary(t *testing.T) {
	t.Run("strips the internal engine URL from a transport error", func(t *testing.T) {
		err := &url.Error{
			Op:  "Post",
			URL: "http://engine-internal:9090/scan",
			Err: errors.New("dial tcp 10.20.30.40:9090: connect: connection refused"),
		}
		got := sanitizeEngineErrorSummary(err, "engine dispatch failed")
		assert.NotContains(t, got, "engine-internal", "the internal engine host must not reach project readers")
		assert.NotContains(t, got, "/scan")
		assert.Contains(t, got, "connection refused", "the diagnosable cause is kept")
	})

	t.Run("falls back when there is no error", func(t *testing.T) {
		assert.Equal(t, "engine dispatch failed", sanitizeEngineErrorSummary(nil, "engine dispatch failed"))
	})

	t.Run("truncates to the column width without splitting a rune", func(t *testing.T) {
		// 2000 multi-byte runes: byte-slicing would corrupt the last character.
		long := strings.Repeat("界", 2000)
		got := truncateErrorSummary(long)
		assert.Equal(t, maxErrorSummaryLen, len([]rune(got)))
		assert.True(t, utf8.ValidString(got), "truncation must not split a rune")
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

	// An authorisation is a legal permission with an expiry date. Without a cap a
	// scope could be authorised until the year 3000 and never revisited.
	require.NoError(t, validateScopeWindow(now, now.Add(MaxScopeWindow)))
	assert.ErrorIs(t, validateScopeWindow(now, now.Add(MaxScopeWindow+time.Hour)), ErrScopeWindowTooLong)
	assert.ErrorIs(t, validateScopeMeta("t1", "o1", "", "owner", "actor"), ErrInvalidName)
	assert.ErrorIs(t, validateScopeMeta("t1", "o1", "scope", "", "actor"), ErrInvalidAuthorizedBy)
	assert.ErrorIs(t, validateScopeMeta("t1", "o1", "scope", "owner", ""), ErrInvalidActorID)
}

func TestValidateStatusDefaultsToInactive(t *testing.T) {
	status, err := validateStatus("")
	require.NoError(t, err)
	assert.Equal(t, StatusInactive, status)
}

func TestNormalizeTemplateConfigDefaultsToEmptyJSONObject(t *testing.T) {
	cfg, err := normalizeTemplateConfig("")
	require.NoError(t, err)
	assert.Equal(t, "{}", cfg)

	cfg, err = normalizeTemplateConfig("  {\"target\":\"example.com\"} ")
	require.NoError(t, err)
	assert.Equal(t, `{"target":"example.com"}`, cfg)
}

func TestNormalizeTemplateConfigRejectsInvalidJSONAndSensitiveFields(t *testing.T) {
	_, err := normalizeTemplateConfig("{bad json}")
	assert.ErrorIs(t, err, ErrInvalidTaskConfig)

	_, err = normalizeTemplateConfig(`{"authorization":"abc"}`)
	assert.ErrorIs(t, err, ErrInvalidTaskConfig)
}

func TestParseDispatchConfigNormalizesTargetsAndOptions(t *testing.T) {
	config, err := parseDispatchConfig(`{
		"targets":[
			{"type":"domain","value":"Example.COM."},
			{"type":"url","value":"https://API.EXAMPLE.COM/path"}
		],
		"options":{"profile":"standard"}
	}`)
	require.NoError(t, err)
	assert.Equal(t, []DispatchTarget{
		{Type: TargetTypeDomain, Value: "example.com"},
		{Type: TargetTypeURL, Value: "https://api.example.com"},
	}, config.Targets)
	assert.Equal(t, "standard", config.Options["profile"])
}

func TestParseDispatchConfigRejectsMissingTargetsAndInvalidTarget(t *testing.T) {
	_, err := parseDispatchConfig(`{"options":{}}`)
	assert.ErrorIs(t, err, ErrInvalidTaskConfig)

	_, err = parseDispatchConfig(`{"targets":[{"type":"bad","value":"example.com"}]}`)
	assert.ErrorIs(t, err, ErrInvalidTargetType)

	_, err = parseDispatchConfig(`{"targets":[{"type":"ip","value":"127.0.0.1"}]}`)
	assert.ErrorIs(t, err, ErrDangerousTarget)
}

// Engine-backed types pass capability validation. Release policy is checked by
// the service, so active types can be explicitly enabled without making
// vocabulary-only task types appear runnable.
func TestValidateTaskTypeRejectsUndispatchableTypes(t *testing.T) {
	unsupported := []string{
		TaskTypeCTLog, TaskTypeCloudSync, TaskTypeImport, TaskTypeDirScan,
	}
	for _, taskType := range unsupported {
		t.Run("unsupported/"+taskType, func(t *testing.T) {
			_, err := validateTaskType(taskType)
			assert.ErrorIs(t, err, ErrTaskTypeUnsupported)
			// It must not be reported as an unknown value: the distinction is what
			// tells an operator "not built yet" rather than "you typed it wrong".
			assert.NotErrorIs(t, err, ErrInvalidTaskType)
		})
	}

	for _, taskType := range []string{
		TaskTypePassiveIntel, TaskTypeDNS, TaskTypeOrgIntel,
		TaskTypePortProbe, TaskTypeWebProbe, TaskTypeFingerprint,
	} {
		t.Run("supported/"+taskType, func(t *testing.T) {
			got, err := validateTaskType(taskType)
			require.NoError(t, err)
			assert.Equal(t, taskType, got)
		})
	}

	_, err := validateTaskType("not-a-type")
	assert.ErrorIs(t, err, ErrInvalidTaskType)
}

// The Baiyan adapter owns only passive routes. Active routes can exist in the
// internal router without becoming operator-dispatchable prematurely.
func TestBaiyanEngineGuardAcceptsOnlyPassiveRoutes(t *testing.T) {
	for _, taskType := range []string{TaskTypePassiveIntel, TaskTypeDNS, TaskTypeOrgIntel} {
		assert.True(t, validEngineV1JobType(taskType), "Baiyan rejected %q", taskType)
	}
	for _, taskType := range []string{
		TaskTypePortProbe, TaskTypeWebProbe, TaskTypeFingerprint, TaskTypeDirScan,
		TaskTypeCTLog, TaskTypeCloudSync, TaskTypeImport,
	} {
		assert.False(t, validEngineV1JobType(taskType), "Baiyan accepted %q", taskType)
	}
}

func TestCredentialGuardDoesNotRejectWordsInsideTargetHostnames(t *testing.T) {
	for _, raw := range []string{
		`{"targets":[{"type":"url","value":"https://tokenhub.example.com:443"}]}`,
		`{"targets":[{"type":"domain","value":"passwordreset.example.com"}]}`,
	} {
		_, err := normalizeTemplateConfig(raw)
		require.NoError(t, err)
	}
	for _, raw := range []string{
		`{"targets":[{"type":"url","value":"https://tokenhub.example.com:443"}],"options":{"token":"credential"}}`,
		`{"targets":[{"type":"url","value":"https://example.com?token=credential"}]}`,
		`{"options":{"\u0074oken":"credential"}}`,
		`{"options":{"headers":"Authorization: Bearer credential"}}`,
	} {
		_, err := normalizeTemplateConfig(raw)
		require.ErrorIs(t, err, ErrInvalidTaskConfig)
	}
}
