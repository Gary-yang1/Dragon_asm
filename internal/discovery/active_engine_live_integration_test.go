//go:build integration

package discovery

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	platformdb "github.com/Gary-yang1/Dragon_asm/internal/platform/db"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
	"github.com/stretchr/testify/require"
)

// TestActiveEngineLiveReadiness is an opt-in, read-only integration check. It
// validates the real AK/SK signature against /scan/nodes but never creates a
// scan task. Supply the DISCOVERY_ACTIVE_ENGINE_* variables and run:
//
//	go test -tags=integration ./internal/discovery -run TestActiveEngineLiveReadiness
func TestActiveEngineLiveReadiness(t *testing.T) {
	adapter := newLiveActiveEngineAdapter(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	readiness, err := adapter.CheckReadiness(ctx)
	require.NoError(t, err)
	require.True(t, readiness.Ready(), "active API is healthy but has no online scan node")
}

// TestActiveEngineLivePortResult is an opt-in, low-impact write integration
// check. It scans only TCP 80 and 443 on the explicitly supplied authorized
// public IP, waits for the terminal state, and validates the real paged result
// contract. It never persists the target or result in the repository.
func TestActiveEngineLivePortResult(t *testing.T) {
	target := strings.TrimSpace(os.Getenv("DISCOVERY_ACTIVE_ENGINE_TEST_TARGET"))
	if target == "" {
		t.Skip("DISCOVERY_ACTIVE_ENGINE_TEST_TARGET is not set")
	}
	normalizedTarget, err := normalizeTargetValue(TargetTypeIP, target)
	require.NoError(t, err, "test target must be an authorized, non-dangerous public IP")

	adapter := newLiveActiveEngineAdapter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	nodeID := liveNodeForCapability(t, ctx, adapter, "portscan")

	taskID, err := adapter.Dispatch(ctx, ScanJob{
		RunID:     uint64(time.Now().UnixNano()),
		ProjectID: 1,
		ScopeID:   1,
		JobType:   TaskTypePortProbe,
		Targets:   []Target{{Type: TargetTypeIP, Value: normalizedTarget}},
		Options: map[string]any{
			"node_id": nodeID,
			"ports":   "80,443",
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, taskID)
	t.Logf("active port task accepted: task_id=%s", taskID)

	status := waitForLiveActiveTerminal(t, ctx, adapter, taskID)
	require.Contains(t, []string{EngineJobStatusSuccess, EngineJobStatusPartialSuccess}, status.Status)

	page, err := adapter.FetchResultPage(ctx, taskID, TaskTypePortProbe, 1, activeAPIResultPageSize)
	require.NoError(t, err)
	require.Equal(t, taskID, page.TaskID)
	require.Equal(t, 1, page.TotalTargets)
	require.Equal(t, 1, page.FinishedTargets)
	require.Len(t, page.PortResults, 1)
	require.Equal(t, normalizedTarget, page.PortResults[0].Target)
	t.Logf("active port result received: task_id=%s result_targets=%d", taskID, len(page.PortResults))
}

// TestActiveEngineLiveWebResult is the Web/fingerprint equivalent of the port
// check. The production adapter always sends nopoc=true and only exposes the
// bounded fingerprint subset to this test.
func TestActiveEngineLiveWebResult(t *testing.T) {
	rawURL := strings.TrimSpace(os.Getenv("DISCOVERY_ACTIVE_ENGINE_TEST_WEB_URL"))
	if rawURL == "" {
		t.Skip("DISCOVERY_ACTIVE_ENGINE_TEST_WEB_URL is not set")
	}
	normalizedURL, err := normalizeTargetValue(TargetTypeURL, rawURL)
	require.NoError(t, err, "test URL must be an authorized, non-dangerous public URL")

	adapter := newLiveActiveEngineAdapter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	nodeID := liveNodeForCapability(t, ctx, adapter, "webscan")

	taskID, err := adapter.Dispatch(ctx, ScanJob{
		RunID:     uint64(time.Now().UnixNano()),
		ProjectID: 1,
		ScopeID:   1,
		JobType:   TaskTypeWebProbe,
		Targets:   []Target{{Type: TargetTypeURL, Value: normalizedURL}},
		Options:   map[string]any{"node_id": nodeID},
	})
	require.NoError(t, err)
	require.NotEmpty(t, taskID)
	t.Logf("active Web task accepted: task_id=%s", taskID)

	status := waitForLiveActiveTerminal(t, ctx, adapter, taskID)
	require.Contains(t, []string{EngineJobStatusSuccess, EngineJobStatusPartialSuccess}, status.Status)

	page, err := adapter.FetchResultPage(ctx, taskID, TaskTypeWebProbe, 1, activeAPIResultPageSize)
	require.NoError(t, err)
	require.Equal(t, taskID, page.TaskID)
	require.Equal(t, 1, page.TotalTargets)
	require.Equal(t, 1, page.FinishedTargets)
	require.Len(t, page.WebResults, 1)
	require.Equal(t, normalizedURL, page.WebResults[0].Target)
	t.Logf(
		"active Web result received: task_id=%s result_targets=%d fingerprints=%d",
		taskID,
		len(page.WebResults),
		len(page.WebResults[0].Fingerprints),
	)
}

// TestActiveEngineLiveReconcileExistingRun is an opt-in ASM/MySQL integration
// check for a TaskRun that already references a real active-engine job. It is
// useful for reproducing result-ingest failures without creating another scan.
func TestActiveEngineLiveReconcileExistingRun(t *testing.T) {
	rawRunID := strings.TrimSpace(os.Getenv("DISCOVERY_ACTIVE_ENGINE_TEST_RUN_ID"))
	if rawRunID == "" {
		t.Skip("DISCOVERY_ACTIVE_ENGINE_TEST_RUN_ID is not set")
	}
	runID, err := strconv.ParseUint(rawRunID, 10, 64)
	require.NoError(t, err)
	require.NotZero(t, runID)

	adapter := newLiveActiveEngineAdapter(t)
	sqlDB, err := platformdb.Open(platformdb.LoadConfigFromEnv())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })

	service := NewService(
		NewRepository(dbgen.New(sqlDB)),
		WithDB(sqlDB),
		WithEngineAdapter(adapter),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	run, err := service.ReconcileTaskRun(ctx, ReconcileTaskRunInput{
		ProjectID: 1,
		RunID:     runID,
		ActorID:   "ma7-live-integration",
	})
	require.NoError(t, err)
	require.Contains(t, []string{TaskRunStatusSuccess, TaskRunStatusPartial}, run.Status)
	t.Logf("ASM run reconciled: run_id=%d status=%s result_count=%d", run.ID, run.Status, run.ResultCount)
}

func newLiveActiveEngineAdapter(t *testing.T) *ActiveAPIEngineAdapter {
	t.Helper()
	config := EngineRouterConfig{
		ActiveBaseURL:    strings.TrimSpace(os.Getenv("DISCOVERY_ACTIVE_ENGINE_BASE_URL")),
		ActiveAccessKey:  strings.TrimSpace(os.Getenv("DISCOVERY_ACTIVE_ENGINE_ACCESS_KEY")),
		ActiveSecretKey:  os.Getenv("DISCOVERY_ACTIVE_ENGINE_SECRET_KEY"),
		ActiveProjectMap: strings.TrimSpace(os.Getenv("DISCOVERY_ACTIVE_ENGINE_PROJECT_MAP")),
	}
	if !anyConfigured(
		config.ActiveBaseURL,
		config.ActiveAccessKey,
		config.ActiveSecretKey,
		config.ActiveProjectMap,
	) {
		t.Skip("DISCOVERY_ACTIVE_ENGINE_* configuration is not set")
	}

	projectMap, err := parseActiveEngineProjectMap(config.ActiveProjectMap)
	require.NoError(t, err)
	adapter, err := NewActiveAPIEngineAdapter(
		config.ActiveBaseURL,
		config.ActiveAccessKey,
		config.ActiveSecretKey,
		projectMap,
		nil,
	)
	require.NoError(t, err)
	return adapter
}

func liveNodeForCapability(
	t *testing.T,
	ctx context.Context,
	adapter *ActiveAPIEngineAdapter,
	capability string,
) string {
	t.Helper()
	readiness, err := adapter.CheckReadiness(ctx)
	require.NoError(t, err)
	require.True(t, readiness.Ready(), "active API is healthy but has no online scan node")
	for _, node := range readiness.OnlineNodes {
		for _, candidate := range node.Capabilities {
			if candidate == capability {
				return node.NodeID
			}
		}
	}
	t.Fatalf("active API has no online node with %s capability", capability)
	return ""
}

func waitForLiveActiveTerminal(
	t *testing.T,
	ctx context.Context,
	adapter *ActiveAPIEngineAdapter,
	taskID string,
) EngineJobStatus {
	t.Helper()
	for {
		status, err := adapter.Status(ctx, taskID)
		require.NoError(t, err)
		switch status.Status {
		case EngineJobStatusSuccess, EngineJobStatusPartialSuccess,
			EngineJobStatusFailed, EngineJobStatusCancelled:
			return status
		}
		select {
		case <-ctx.Done():
			require.NoError(t, ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
}
