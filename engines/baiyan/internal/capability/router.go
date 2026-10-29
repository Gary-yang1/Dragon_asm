package capability

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"baiyan/internal/contract"
	"baiyan/internal/job"
)

// ErrJobTypeUnsupported marks a job the engine has no executor for.
//
// It is deliberately distinct from a scan that ran and found nothing: ASM needs
// to tell "this engine cannot do that" apart from "there was nothing there",
// because only the first is a deployment problem.
var ErrJobTypeUnsupported = errors.New("baiyan: job type is not supported by this engine")

// Router dispatches a job to the executor registered for its type.
//
// Until now the engine had exactly one executor and every job went to it,
// which meant an unsupported job type was handled by the passive executor and
// silently produced nothing. Routing makes the set of capabilities explicit:
// what is not registered is refused, and what is registered is advertised.
type Router struct {
	executors map[string]job.Executor
}

// NewRouter builds a router over the given executors, keyed by job type.
func NewRouter(executors map[string]job.Executor) (*Router, error) {
	routed := make(map[string]job.Executor, len(executors))
	for jobType, executor := range executors {
		normalized := strings.ToLower(strings.TrimSpace(jobType))
		if normalized == "" {
			return nil, errors.New("baiyan: router job type is empty")
		}
		if executor == nil {
			return nil, fmt.Errorf("baiyan: router executor for %s is nil", normalized)
		}
		if _, exists := routed[normalized]; exists {
			return nil, fmt.Errorf("baiyan: router job type %s is registered twice", normalized)
		}
		routed[normalized] = executor
	}
	return &Router{executors: routed}, nil
}

// SupportedJobTypes lists what this engine can run, sorted for stable output.
func (r *Router) SupportedJobTypes() []string {
	types := make([]string, 0, len(r.executors))
	for jobType := range r.executors {
		types = append(types, jobType)
	}
	sort.Strings(types)
	return types
}

// Supports reports whether a job type has an executor.
func (r *Router) Supports(jobType string) bool {
	_, ok := r.executors[strings.ToLower(strings.TrimSpace(jobType))]
	return ok
}

// Execute routes one request. An unknown job type fails immediately rather than
// falling through to whichever executor happens to be first.
func (r *Router) Execute(ctx context.Context, request contract.ScanRequest) (job.ExecutionResult, error) {
	executor, ok := r.executors[strings.ToLower(strings.TrimSpace(request.JobType))]
	if !ok {
		return job.ExecutionResult{}, fmt.Errorf("%w: %s", ErrJobTypeUnsupported, request.JobType)
	}
	return executor.Execute(ctx, request)
}
