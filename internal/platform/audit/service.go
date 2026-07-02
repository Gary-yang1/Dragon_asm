package audit

import "context"

// Service writes audit events. It is the only entry point for callers; direct
// repository access from outside this package is intentionally unavailable.
type Service struct {
	repo Repository
}

// NewService creates a Service backed by the given repository.
func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

// Record writes one audit event. It fills in default values for ActorType and
// Result when the caller omits them, then delegates to the repository.
//
// Errors from the repository are returned as-is; the caller decides whether to
// log and continue or surface the failure.
func (s *Service) Record(ctx context.Context, e Event) error {
	if e.ActorType == "" {
		e.ActorType = ActorUser
	}
	if e.Result == "" {
		e.Result = ResultSuccess
	}
	return s.repo.Insert(ctx, e)
}
