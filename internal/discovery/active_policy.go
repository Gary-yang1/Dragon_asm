//revive:disable:exported

package discovery

import (
	"context"
	"errors"
	"strings"
)

// Guardrails for actively-probing task types.
//
// Passive collection only ever queries third-party datasets, so a mistake there
// leaks nothing and touches nobody. An active probe sends packets to somebody's
// infrastructure, which makes it a legal question rather than a technical one.
// These rules exist so that enabling active scanning is a configuration change,
// not a rewrite: the guardrails are in force before the capability arrives.
var (
	// ErrOwnershipRequired marks an active task whose targets are not covered by a
	// verified domain-ownership proof.
	ErrOwnershipRequired = errors.New("discovery: active scanning requires verified domain ownership")
	// ErrActiveApprovalRequired marks an active run started without a distinct approver.
	ErrActiveApprovalRequired = errors.New("discovery: active scanning requires approval by a second person")
	// ErrActiveLimitsTooHigh marks active task limits above the active-specific caps.
	ErrActiveLimitsTooHigh = errors.New("discovery: rate limit or concurrency exceeds the active scanning cap")
)

// activeTaskTypes are the task types that put packets on someone else's network.
//
// dirscan is included deliberately: directory brute force is the noisiest and
// legally least defensible thing this platform can do, so it must never sit
// outside the same gate as the rest.
var activeTaskTypes = map[string]bool{
	TaskTypePortProbe:   true,
	TaskTypeWebProbe:    true,
	TaskTypeFingerprint: true,
	TaskTypeDirScan:     true,
}

// IsActiveTaskType reports whether a task type actively probes a target.
func IsActiveTaskType(v string) bool { return activeTaskTypes[strings.TrimSpace(v)] }

// Platform-side template caps for active tasks. The active API contract does
// not currently accept per-task rate/concurrency settings; actual engine
// execution limits remain the responsibility of the selected node.
const (
	MaxActiveRateLimit   = 100
	MaxActiveConcurrency = 20
)

// ActiveDispatchPolicy controls release gates around the active-engine route.
// Scope membership, dangerous-address rejection, project isolation, platform
// template caps, auditing, and the adapter's nopoc=true behavior are
// unconditional and are deliberately not represented here.
type ActiveDispatchPolicy struct {
	Enabled          bool `json:"enabled"`
	RequireApproval  bool `json:"require_approval"`
	RequireOwnership bool `json:"require_ownership"`
}

// DefaultActiveDispatchPolicy is fail-closed for deployments that have not
// explicitly opted into active scanning.
func DefaultActiveDispatchPolicy() ActiveDispatchPolicy {
	return ActiveDispatchPolicy{
		Enabled:          false,
		RequireApproval:  true,
		RequireOwnership: true,
	}
}

// ValidateActiveTaskLimits applies the active-specific ceilings on top of the
// general ones.
func ValidateActiveTaskLimits(taskType string, rateLimit, concurrency int) error {
	if !IsActiveTaskType(taskType) {
		return nil
	}
	if rateLimit > MaxActiveRateLimit || concurrency > MaxActiveConcurrency {
		return ErrActiveLimitsTooHigh
	}
	return nil
}

// validateActiveDispatchConfig rejects templates the active adapter cannot
// execute before they can be enabled or queued. UI validation is only a
// convenience; the public API remains the security and correctness boundary.
func validateActiveDispatchConfig(taskType, raw string) error {
	if !IsActiveTaskType(taskType) {
		return nil
	}
	config, err := parseDispatchConfig(raw)
	if err != nil {
		return err
	}

	nodeID, err := activeAPIStringOption(config.Options, "node_id")
	if err != nil || !validActiveAPINodeID(nodeID) {
		return ErrInvalidTaskConfig
	}
	targets := make([]Target, 0, len(config.Targets))
	for _, target := range config.Targets {
		targets = append(targets, Target(target))
	}

	switch taskType {
	case TaskTypePortProbe:
		ports, optionErr := activeAPIStringOption(config.Options, "ports")
		if optionErr != nil || !validActiveAPIPorts(ports) {
			return ErrInvalidTaskConfig
		}
		if _, targetErr := activeAPIPortTargets(targets); targetErr != nil {
			return ErrInvalidTaskConfig
		}
	case TaskTypeWebProbe, TaskTypeFingerprint:
		if _, targetErr := activeAPIWebTargets(targets); targetErr != nil {
			return ErrInvalidTaskConfig
		}
	default:
		return ErrTaskTypeUnsupported
	}
	return nil
}

// OwnershipChecker reports whether a domain has a verified ownership proof in a
// project. It is satisfied by the project workspace service.
type OwnershipChecker interface {
	IsDomainOwnershipVerified(ctx context.Context, projectID uint64, domain string) (bool, error)
}

// ActiveApproval records who authorised one active run.
type ActiveApproval struct {
	ActorID    string
	ApprovedBy string
}

// ValidateActiveApproval enforces separation of duties on active runs: the person
// starting the scan cannot be the person approving it.
//
// This mirrors the risk-acceptance rule, and has the same known limitation —
// ApprovedBy is not yet resolved to a real account, so it blocks the degenerate
// self-approval rather than proving a second human signed off.
func ValidateActiveApproval(taskType string, approval ActiveApproval) error {
	if !IsActiveTaskType(taskType) {
		return nil
	}
	approver := strings.TrimSpace(approval.ApprovedBy)
	if approver == "" {
		return ErrActiveApprovalRequired
	}
	if strings.EqualFold(approver, strings.TrimSpace(approval.ActorID)) {
		return ErrActiveApprovalRequired
	}
	return nil
}
