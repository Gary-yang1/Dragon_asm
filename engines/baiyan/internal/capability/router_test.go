package capability

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"baiyan/internal/contract"
	"baiyan/internal/job"
)

type recordingExecutor struct {
	name  string
	calls []string
	err   error
}

func (e *recordingExecutor) Execute(_ context.Context, request contract.ScanRequest) (job.ExecutionResult, error) {
	e.calls = append(e.calls, request.JobType)
	if e.err != nil {
		return job.ExecutionResult{}, e.err
	}
	return job.ExecutionResult{Status: "success", ResultCount: 1, ErrorSummary: e.name}, nil
}

func TestRouterSendsEachJobTypeToItsOwnExecutor(t *testing.T) {
	passive := &recordingExecutor{name: "passive"}
	dns := &recordingExecutor{name: "dns"}
	router, err := NewRouter(map[string]job.Executor{"passive_intel": passive, "dns": dns})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	result, err := router.Execute(context.Background(), contract.ScanRequest{JobType: "dns"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.ErrorSummary != "dns" {
		t.Fatalf("routed to %q, want the dns executor", result.ErrorSummary)
	}
	if len(passive.calls) != 0 {
		t.Fatalf("the passive executor was called for a dns job: %v", passive.calls)
	}
}

// The point of routing: a job type nobody registered must be refused, not
// quietly handed to whichever executor exists and reported as an empty result.
func TestRouterRefusesUnsupportedJobTypes(t *testing.T) {
	passive := &recordingExecutor{name: "passive"}
	router, err := NewRouter(map[string]job.Executor{"passive_intel": passive})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	for _, jobType := range []string{"port_probe", "dirscan", "fingerprint", "", "unknown"} {
		_, err := router.Execute(context.Background(), contract.ScanRequest{JobType: jobType})
		if !errors.Is(err, ErrJobTypeUnsupported) {
			t.Fatalf("job type %q: got %v, want ErrJobTypeUnsupported", jobType, err)
		}
	}
	if len(passive.calls) != 0 {
		t.Fatalf("an unsupported job reached an executor: %v", passive.calls)
	}
}

func TestRouterNormalizesJobTypeLookup(t *testing.T) {
	router, err := NewRouter(map[string]job.Executor{"  Passive_Intel  ": &recordingExecutor{name: "passive"}})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	if !router.Supports("passive_intel") || !router.Supports(" PASSIVE_INTEL ") {
		t.Fatal("lookup must not depend on case or surrounding space")
	}
	if _, err := router.Execute(context.Background(), contract.ScanRequest{JobType: "PASSIVE_INTEL"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
}

func TestRouterReportsWhatTheEngineCanDo(t *testing.T) {
	router, err := NewRouter(map[string]job.Executor{
		"passive_intel": &recordingExecutor{}, "dns": &recordingExecutor{},
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	// Sorted, so ASM sees a stable capability list rather than map order.
	if got := router.SupportedJobTypes(); !reflect.DeepEqual(got, []string{"dns", "passive_intel"}) {
		t.Fatalf("SupportedJobTypes returned %v", got)
	}
}

func TestNewRouterRejectsBrokenRegistrations(t *testing.T) {
	if _, err := NewRouter(map[string]job.Executor{"": &recordingExecutor{}}); err == nil {
		t.Fatal("an empty job type must be refused")
	}
	if _, err := NewRouter(map[string]job.Executor{"dns": nil}); err == nil {
		t.Fatal("a nil executor must be refused rather than panicking at dispatch time")
	}
	// Two keys that normalise to the same type would make routing depend on map
	// iteration order.
	if _, err := NewRouter(map[string]job.Executor{"dns": &recordingExecutor{}, "DNS": &recordingExecutor{}}); err == nil {
		t.Fatal("duplicate job types must be refused")
	}
}

func TestRouterPropagatesExecutorErrors(t *testing.T) {
	wantErr := errors.New("provider unavailable")
	router, err := NewRouter(map[string]job.Executor{"dns": &recordingExecutor{err: wantErr}})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	if _, err := router.Execute(context.Background(), contract.ScanRequest{JobType: "dns"}); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want the executor's own error", err)
	}
}

// The router has to satisfy the same interface the job service already consumes,
// or wiring it in would mean changing the job service too.
var _ job.Executor = (*Router)(nil)
