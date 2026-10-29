package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsActiveTaskType(t *testing.T) {
	active := []string{TaskTypePortProbe, TaskTypeWebProbe, TaskTypeFingerprint, TaskTypeDirScan}
	for _, taskType := range active {
		assert.True(t, IsActiveTaskType(taskType), "%s puts packets on someone else's network", taskType)
	}
	// Passive collection only queries third-party datasets.
	for _, taskType := range []string{TaskTypePassiveIntel, TaskTypeDNS, TaskTypeCTLog, TaskTypeImport, TaskTypeCloudSync} {
		assert.False(t, IsActiveTaskType(taskType), "%s must not be gated as active", taskType)
	}
}

func TestDefaultActiveDispatchPolicyFailsClosed(t *testing.T) {
	policy := DefaultActiveDispatchPolicy()
	assert.False(t, policy.Enabled)
	assert.True(t, policy.RequireApproval)
	assert.True(t, policy.RequireOwnership)
}

func TestValidateActiveTaskLimits(t *testing.T) {
	// Passive types keep the general ceilings.
	require.NoError(t, ValidateActiveTaskLimits(TaskTypePassiveIntel, 10000, 500))

	assert.ErrorIs(t, ValidateActiveTaskLimits(TaskTypePortProbe, MaxActiveRateLimit+1, 1), ErrActiveLimitsTooHigh)
	assert.ErrorIs(t, ValidateActiveTaskLimits(TaskTypeDirScan, 1, MaxActiveConcurrency+1), ErrActiveLimitsTooHigh)
	require.NoError(t, ValidateActiveTaskLimits(TaskTypePortProbe, MaxActiveRateLimit, MaxActiveConcurrency))
}

func TestValidateActiveApproval(t *testing.T) {
	// Passive runs need no approver.
	require.NoError(t, ValidateActiveApproval(TaskTypePassiveIntel, ActiveApproval{ActorID: "1"}))

	assert.ErrorIs(t, ValidateActiveApproval(TaskTypePortProbe, ActiveApproval{ActorID: "1"}), ErrActiveApprovalRequired)
	assert.ErrorIs(t,
		ValidateActiveApproval(TaskTypePortProbe, ActiveApproval{ActorID: "1", ApprovedBy: "1"}),
		ErrActiveApprovalRequired, "the person starting the scan cannot approve it")
	require.NoError(t, ValidateActiveApproval(TaskTypePortProbe, ActiveApproval{ActorID: "1", ApprovedBy: "2"}))
}

func TestValidateActiveDispatchConfig(t *testing.T) {
	require.NoError(t, validateActiveDispatchConfig(
		TaskTypePortProbe,
		`{"targets":[{"type":"ip","value":"1.1.1.1"}],"options":{"ports":"80,443"}}`,
	))
	require.NoError(t, validateActiveDispatchConfig(
		TaskTypeWebProbe,
		`{"targets":[{"type":"url","value":"https://example.com"}],"options":{}}`,
	))
	require.NoError(t, validateActiveDispatchConfig(
		TaskTypeFingerprint,
		`{"targets":[{"type":"url","value":"https://example.com"}],"options":{"node_id":"node-1"}}`,
	))

	for name, config := range map[string]string{
		"port target must be IP": `{"targets":[{"type":"url","value":"https://example.com"}],"options":{"ports":"80"}}`,
		"ports are required":     `{"targets":[{"type":"ip","value":"1.1.1.1"}],"options":{}}`,
		"all ports is forbidden": `{"targets":[{"type":"ip","value":"1.1.1.1"}],"options":{"ports":"all"}}`,
		"node id is bounded":     `{"targets":[{"type":"url","value":"https://example.com"}],"options":{"node_id":"node one"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			taskType := TaskTypePortProbe
			if name == "node id is bounded" {
				taskType = TaskTypeWebProbe
			}
			assert.ErrorIs(t, validateActiveDispatchConfig(taskType, config), ErrInvalidTaskConfig)
		})
	}
}

type stubOwnership struct {
	verified map[string]bool
	err      error
	asked    []string
}

func (s *stubOwnership) IsDomainOwnershipVerified(_ context.Context, _ uint64, domain string) (bool, error) {
	s.asked = append(s.asked, domain)
	if s.err != nil {
		return false, s.err
	}
	return s.verified[domain], nil
}

// The gate that matters: an active run must not reach the engine unless the
// platform itself verified control of every target domain. Scope membership only
// says an operator typed the target in.
func TestRequireVerifiedOwnership(t *testing.T) {
	targets := []DispatchTarget{{Type: TargetTypeDomain, Value: "example.com"}}

	t.Run("passive types are not gated", func(t *testing.T) {
		svc := &Service{}
		require.NoError(t, svc.requireVerifiedOwnership(context.Background(), 1, TaskTypePassiveIntel, targets))
	})

	t.Run("fails closed with no checker configured", func(t *testing.T) {
		svc := &Service{}
		err := svc.requireVerifiedOwnership(context.Background(), 1, TaskTypePortProbe, targets)
		assert.ErrorIs(t, err, ErrOwnershipRequired,
			"a deployment that forgot to wire verification must not be able to probe")
	})

	t.Run("unverified domain is refused", func(t *testing.T) {
		svc := &Service{ownership: &stubOwnership{verified: map[string]bool{}}}
		err := svc.requireVerifiedOwnership(context.Background(), 1, TaskTypePortProbe, targets)
		assert.ErrorIs(t, err, ErrOwnershipRequired)
	})

	t.Run("verified domain is allowed", func(t *testing.T) {
		checker := &stubOwnership{verified: map[string]bool{"example.com": true}}
		svc := &Service{ownership: checker}
		require.NoError(t, svc.requireVerifiedOwnership(context.Background(), 1, TaskTypeDirScan, targets))
		assert.Equal(t, []string{"example.com"}, checker.asked)
	})

	t.Run("one unverified target refuses the whole run", func(t *testing.T) {
		svc := &Service{ownership: &stubOwnership{verified: map[string]bool{"example.com": true}}}
		mixed := []DispatchTarget{
			{Type: TargetTypeDomain, Value: "example.com"},
			{Type: TargetTypeDomain, Value: "not-mine.com"},
		}
		err := svc.requireVerifiedOwnership(context.Background(), 1, TaskTypeWebProbe, mixed)
		assert.ErrorIs(t, err, ErrOwnershipRequired)
	})

	t.Run("url targets are attributed to their host", func(t *testing.T) {
		checker := &stubOwnership{verified: map[string]bool{"example.com": true}}
		svc := &Service{ownership: checker}
		urls := []DispatchTarget{{Type: TargetTypeURL, Value: "https://example.com:8443/app"}}
		require.NoError(t, svc.requireVerifiedOwnership(context.Background(), 1, TaskTypeWebProbe, urls))
		assert.Equal(t, []string{"example.com"}, checker.asked)
	})

	t.Run("bare IP and CIDR cannot be attributed and are refused", func(t *testing.T) {
		svc := &Service{ownership: &stubOwnership{verified: map[string]bool{}}}
		for _, target := range []DispatchTarget{
			{Type: TargetTypeIP, Value: "203.0.113.10"},
			{Type: TargetTypeCIDR, Value: "203.0.113.0/24"},
		} {
			err := svc.requireVerifiedOwnership(context.Background(), 1, TaskTypePortProbe, []DispatchTarget{target})
			assert.ErrorIs(t, err, ErrOwnershipRequired, "%s has no ownership proof available", target.Value)
		}
	})

	t.Run("a lookup failure is not treated as verified", func(t *testing.T) {
		wantErr := errors.New("db down")
		svc := &Service{ownership: &stubOwnership{err: wantErr}}
		err := svc.requireVerifiedOwnership(context.Background(), 1, TaskTypePortProbe, targets)
		assert.ErrorIs(t, err, wantErr)
	})
}
