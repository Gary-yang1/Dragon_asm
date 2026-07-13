package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/hibiken/asynq"

	"github.com/Gary-yang1/Dragon_asm/internal/auth"
	"github.com/Gary-yang1/Dragon_asm/internal/discovery"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, err := sql.Open("mysql", mustEnv("E2E_DB_DSN"))
	must(err)
	defer func() { _ = db.Close() }()
	must(db.PingContext(ctx))
	seedProjectIdentity(ctx, db)
	redisOpt := asynq.RedisClientOpt{Addr: mustEnv("E2E_REDIS_ADDR")}
	client := asynq.NewClient(redisOpt)
	defer func() { _ = client.Close() }()

	runID := seedRun(ctx, db, "success", "example.com", 30)
	enqueueRun(ctx, client, runID)

	status, resultCount, errorSummary := waitTerminal(ctx, db, runID)
	if status != discovery.TaskRunStatusSuccess {
		must(fmt.Errorf("TaskRun ended as %s: %s", status, errorSummary))
	}
	must(waitProcessedCallbackCount(ctx, db, runID, 3))
	counts := map[string]int64{}
	for name, query := range map[string]string{
		"assets":       "SELECT COUNT(*) FROM asset WHERE project_id=1 AND deleted_at='1970-01-01 00:00:00.000'",
		"relations":    "SELECT COUNT(*) FROM asset_relation WHERE project_id=1 AND deleted_at='1970-01-01 00:00:00.000'",
		"observations": "SELECT COUNT(*) FROM discovery_observation WHERE project_id=1 AND run_id=? AND ingest_status='materialized'",
		"callbacks":    "SELECT COUNT(*) FROM discovery_callback WHERE project_id=1 AND run_id=? AND ingest_status='processed'",
		"events":       "SELECT COUNT(*) FROM change_event WHERE project_id=1",
		"audits":       "SELECT COUNT(*) FROM audit_log WHERE project_id=1",
	} {
		args := []any{}
		if name == "observations" || name == "callbacks" {
			args = append(args, runID)
		}
		var count int64
		must(db.QueryRowContext(ctx, query, args...).Scan(&count))
		counts[name] = count
	}
	if counts["assets"] != 3 || counts["relations"] != 2 || counts["observations"] < 6 || counts["callbacks"] < 3 || counts["events"] < 4 || counts["audits"] < 2 {
		must(fmt.Errorf("unexpected E2E counts: %+v", counts))
	}
	var rootID, subID, ipID uint64
	must(db.QueryRowContext(ctx, "SELECT id FROM asset WHERE project_id=1 AND asset_key='domain:example.com'").Scan(&rootID))
	must(db.QueryRowContext(ctx, "SELECT id FROM asset WHERE project_id=1 AND asset_key='subdomain:api.example.com'").Scan(&subID))
	must(db.QueryRowContext(ctx, "SELECT id FROM asset WHERE project_id=1 AND asset_key='ip:192.0.2.10'").Scan(&ipID))
	var graphEdges int64
	must(db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_relation WHERE project_id=1 AND
		((from_asset_id=? AND to_asset_id=? AND relation_type='contains') OR
		 (from_asset_id=? AND to_asset_id=? AND relation_type='resolves_to'))`, rootID, subID, subID, ipID).Scan(&graphEdges))
	if graphEdges != 2 {
		must(fmt.Errorf("expected complete graph, got %d edges", graphEdges))
	}
	must(verifyEngineDuplicate(ctx, runID))
	must(verifyCallbackDuplicateAndConflict(ctx, db, runID))

	must(configureProvider(ctx, "partial.example.com", false, true))
	partialRunID := seedRun(ctx, db, "partial", "partial.example.com", 30)
	enqueueRun(ctx, client, partialRunID)
	partialStatus, _, _ := waitTerminal(ctx, db, partialRunID)
	if partialStatus != discovery.TaskRunStatusPartial {
		must(fmt.Errorf("partial scenario ended as %s", partialStatus))
	}

	must(configureProvider(ctx, "cancel.example.com", true, false))
	cancelRunID := seedRun(ctx, db, "cancel", "cancel.example.com", 30)
	enqueueRun(ctx, client, cancelRunID)
	must(waitProviderRequests(ctx, "cancel.example.com", 1))
	must(cancelViaAPI(ctx, cancelRunID))
	cancelStatus, _, _ := waitTerminal(ctx, db, cancelRunID)
	if cancelStatus != discovery.TaskRunStatusCancelled {
		must(fmt.Errorf("cancel scenario ended as %s", cancelStatus))
	}
	must(releaseProvider(ctx, "cancel.example.com"))

	must(configureProvider(ctx, "timeout.example.com", true, false))
	timeoutRunID := seedRun(ctx, db, "timeout", "timeout.example.com", 1)
	enqueueRun(ctx, client, timeoutRunID)
	must(waitProviderRequests(ctx, "timeout.example.com", 1))
	time.Sleep(1200 * time.Millisecond)
	must(enqueueReconcile(ctx, client))
	timeoutStatus, _, timeoutSummary := waitTerminal(ctx, db, timeoutRunID)
	if timeoutStatus != discovery.TaskRunStatusFailed || !strings.Contains(timeoutSummary, "timed out") {
		must(fmt.Errorf("timeout scenario ended as %s: %s", timeoutStatus, timeoutSummary))
	}
	must(releaseProvider(ctx, "timeout.example.com"))

	must(configureProvider(ctx, "restart.example.com", true, false))
	restartRunID := seedRun(ctx, db, "engine-restart", "restart.example.com", 30)
	enqueueRun(ctx, client, restartRunID)
	must(waitProviderRequests(ctx, "restart.example.com", 1))
	must(requestHarnessAction(ctx, "engine-restart"))
	must(waitProviderRequests(ctx, "restart.example.com", 2))
	must(releaseProvider(ctx, "restart.example.com"))
	restartStatus, _, restartSummary := waitTerminal(ctx, db, restartRunID)
	if restartStatus != discovery.TaskRunStatusSuccess {
		must(fmt.Errorf("engine restart scenario ended as %s: %s", restartStatus, restartSummary))
	}

	must(configureProvider(ctx, "redis.example.com", true, false))
	redisRunID := seedRun(ctx, db, "redis-recovery", "redis.example.com", 30)
	enqueueRun(ctx, client, redisRunID)
	must(waitProviderRequests(ctx, "redis.example.com", 1))
	must(requestHarnessAction(ctx, "redis-stop"))
	must(releaseProvider(ctx, "redis.example.com"))
	must(waitCallbackPersisted(ctx, db, redisRunID, 2))
	must(requestHarnessAction(ctx, "redis-start"))
	must(enqueueCallbackRecovery(ctx, client))
	must(waitCallbackProcessed(ctx, db, redisRunID, 2))
	redisStatus, _, _, terminal := waitTerminalFor(ctx, db, redisRunID, 3*time.Second)
	if !terminal {
		must(enqueueReconcile(ctx, client))
		redisStatus, _, _ = waitTerminal(ctx, db, redisRunID)
	}
	if redisStatus != discovery.TaskRunStatusSuccess && redisStatus != discovery.TaskRunStatusFailed {
		must(fmt.Errorf("redis recovery scenario ended as %s", redisStatus))
	}

	evidence := map[string]any{
		"run_id": runID, "status": status, "result_count": resultCount,
		"counts": counts, "graph": []string{"domain:example.com", "subdomain:api.example.com", "ip:192.0.2.10"},
		"engine_duplicate": true, "callback_duplicate": true, "callback_conflict": true,
		"partial_run_id": partialRunID, "partial_status": partialStatus,
		"cancel_run_id": cancelRunID, "cancel_status": cancelStatus,
		"timeout_run_id": timeoutRunID, "timeout_status": timeoutStatus,
		"restart_run_id": restartRunID, "restart_status": restartStatus,
		"redis_run_id": redisRunID, "redis_status": redisStatus, "redis_callback_recovered": true,
	}
	raw, _ := json.Marshal(evidence)
	fmt.Println(string(raw))
}

func callbackDiagnostics(db *sql.DB, runID uint64) string {
	rows, err := db.Query(`SELECT seq,ingest_status,ingest_attempt,ingest_error FROM discovery_callback
		WHERE project_id=1 AND run_id=? ORDER BY seq`, runID)
	if err != nil {
		return err.Error()
	}
	defer func() { _ = rows.Close() }()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var seq uint64
		var status, ingestError string
		var attempt uint32
		if err := rows.Scan(&seq, &status, &attempt, &ingestError); err != nil {
			return err.Error()
		}
		items = append(items, map[string]any{"seq": seq, "status": status, "attempt": attempt, "error": ingestError})
	}
	raw, _ := json.Marshal(items)
	return string(raw)
}

func verifyEngineDuplicate(ctx context.Context, runID uint64) error {
	request := map[string]any{
		"schema_version": "1.0", "run_id": runID, "project_id": 1, "scope_id": 1, "job_type": "passive_intel",
		"targets":    []any{map[string]any{"type": "domain", "value": "example.com"}},
		"rate_limit": 10, "concurrency": 2, "timeout_seconds": 30,
		"callback_url": mustEnv("E2E_API_URL") + "/api/v1/discovery/callback?project_id=1&run_id=" + strconv.FormatUint(runID, 10),
		"options":      map[string]any{"profile": "subdomain_passive", "sources": []any{"certificate_transparency"}, "max_results": 100},
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, mustEnv("E2E_ENGINE_URL")+"/scan", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+mustEnv("E2E_ENGINE_TOKEN"))
	httpRequest.Header.Set("Idempotency-Key", strconv.FormatUint(runID, 10))
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("duplicate engine submit returned %d", response.StatusCode)
	}
	return nil
}

func verifyCallbackDuplicateAndConflict(ctx context.Context, db *sql.DB, runID uint64) error {
	var seq uint64
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT seq,payload_json FROM discovery_callback
		WHERE project_id=1 AND run_id=? AND phase IN ('completed','failed') ORDER BY seq DESC LIMIT 1`, runID).Scan(&seq, &raw)
	if err != nil {
		return err
	}
	// MySQL JSON returns a normalized representation. Re-marshal through the
	// Engine Contract field order to reproduce the engine's immutable raw body.
	var replay callbackReplay
	if err := json.Unmarshal(raw, &replay); err != nil {
		return err
	}
	raw, err = json.Marshal(replay)
	if err != nil {
		return err
	}
	status, body, err := postSignedCallback(ctx, runID, seq, raw)
	if err != nil {
		return err
	}
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"duplicate":true`)) {
		return fmt.Errorf("duplicate callback returned %d: %s", status, string(body))
	}
	var changed map[string]any
	if err := json.Unmarshal(raw, &changed); err != nil {
		return err
	}
	changed["error_summary"] = "conflicting replay"
	conflictRaw, err := json.Marshal(changed)
	if err != nil {
		return err
	}
	status, _, err = postSignedCallback(ctx, runID, seq, conflictRaw)
	if err != nil {
		return err
	}
	if status != http.StatusConflict {
		return fmt.Errorf("callback conflict returned %d", status)
	}
	return nil
}

type callbackReplay struct {
	SchemaVersion  string           `json:"schema_version"`
	RunID          uint64           `json:"run_id"`
	Seq            uint64           `json:"seq"`
	Phase          string           `json:"phase"`
	Status         string           `json:"status"`
	ResultCount    uint64           `json:"result_count"`
	ObservedAt     time.Time        `json:"observed_at"`
	Assets         []map[string]any `json:"assets"`
	Relations      []map[string]any `json:"relations"`
	Exposures      []map[string]any `json:"exposures"`
	ProviderErrors []map[string]any `json:"provider_errors"`
	ErrorSummary   string           `json:"error_summary"`
}

func postSignedCallback(ctx context.Context, runID, seq uint64, raw []byte) (int, []byte, error) {
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(mustEnv("E2E_CALLBACK_SECRET")))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write(raw)
	target := mustEnv("E2E_API_URL") + "/api/v1/discovery/callback?project_id=1&run_id=" + strconv.FormatUint(runID, 10) + "&seq=" + strconv.FormatUint(seq, 10)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Engine-ID", mustEnv("E2E_ENGINE_ID"))
	request.Header.Set("X-Timestamp", timestamp)
	request.Header.Set("X-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	return response.StatusCode, body, err
}

func enqueueRun(ctx context.Context, client *asynq.Client, runID uint64) {
	must(discovery.NewAsynqDispatchEnqueuer(client, "default").EnqueueTaskRun(ctx, discovery.DispatchTaskPayload{
		ProjectID: 1, RunID: runID, ActorID: "e2e-driver",
	}))
}

func waitTerminal(ctx context.Context, db *sql.DB, runID uint64) (string, uint64, string) {
	for {
		var status, errorSummary string
		var resultCount uint64
		err := db.QueryRowContext(ctx, "SELECT status,result_count,error_summary FROM task_run WHERE id=? AND project_id=1", runID).
			Scan(&status, &resultCount, &errorSummary)
		must(err)
		switch status {
		case discovery.TaskRunStatusSuccess, discovery.TaskRunStatusPartial, discovery.TaskRunStatusFailed, discovery.TaskRunStatusCancelled:
			return status, resultCount, errorSummary
		}
		select {
		case <-ctx.Done():
			must(fmt.Errorf("timed out waiting for TaskRun %d final status: %s", runID, callbackDiagnostics(db, runID)))
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func waitTerminalFor(ctx context.Context, db *sql.DB, runID uint64, duration time.Duration) (string, uint64, string, bool) {
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	for {
		var status, errorSummary string
		var resultCount uint64
		if err := db.QueryRowContext(ctx, "SELECT status,result_count,error_summary FROM task_run WHERE id=? AND project_id=1", runID).
			Scan(&status, &resultCount, &errorSummary); err != nil {
			return "", 0, err.Error(), false
		}
		switch status {
		case discovery.TaskRunStatusSuccess, discovery.TaskRunStatusPartial, discovery.TaskRunStatusFailed, discovery.TaskRunStatusCancelled:
			return status, resultCount, errorSummary, true
		}
		select {
		case <-ctx.Done():
			return status, resultCount, ctx.Err().Error(), false
		case <-deadline.C:
			return status, resultCount, errorSummary, false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func requestHarnessAction(ctx context.Context, action string) error {
	dir := mustEnv("E2E_CONTROL_DIR")
	requestPath := filepath.Join(dir, action+".request")
	donePath := filepath.Join(dir, action+".done")
	_ = os.Remove(donePath)
	if err := os.WriteFile(requestPath, []byte(action+"\n"), 0o600); err != nil {
		return err
	}
	for {
		if _, err := os.Stat(donePath); err == nil {
			_ = os.Remove(requestPath)
			_ = os.Remove(donePath)
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func waitCallbackPersisted(ctx context.Context, db *sql.DB, runID, seq uint64) error {
	for {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM discovery_callback WHERE project_id=1 AND run_id=? AND seq=?", runID, seq).Scan(&count); err != nil {
			return err
		}
		if count == 1 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func waitCallbackProcessed(ctx context.Context, db *sql.DB, runID, seq uint64) error {
	for {
		var status string
		err := db.QueryRowContext(ctx, "SELECT ingest_status FROM discovery_callback WHERE project_id=1 AND run_id=? AND seq=?", runID, seq).Scan(&status)
		if err == nil && status == discovery.CallbackIngestProcessed {
			return nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func waitProcessedCallbackCount(ctx context.Context, db *sql.DB, runID uint64, minimum int) error {
	for {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM discovery_callback
			WHERE project_id=1 AND run_id=? AND ingest_status='processed'`, runID).Scan(&count); err != nil {
			return err
		}
		if count >= minimum {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %d processed callbacks: %w; %s", minimum, ctx.Err(), callbackDiagnostics(db, runID))
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func configureProvider(ctx context.Context, domain string, hold, fail bool) error {
	return postProviderControl(ctx, "/control/configure", map[string]any{"domain": domain, "hold": hold, "fail": fail})
}

func releaseProvider(ctx context.Context, domain string) error {
	return postProviderControl(ctx, "/control/release", map[string]any{"domain": domain})
}

func postProviderControl(ctx context.Context, path string, body map[string]any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, mustEnv("E2E_PROVIDER_URL")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+mustEnv("E2E_PROVIDER_TOKEN"))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("provider control %s returned %d", path, response.StatusCode)
	}
	return nil
}

func waitProviderRequests(ctx context.Context, domain string, minimum int) error {
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet,
			mustEnv("E2E_PROVIDER_URL")+"/control/status?domain="+domain, nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+mustEnv("E2E_PROVIDER_TOKEN"))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return err
		}
		var status struct {
			Requests int `json:"requests"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&status)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("provider status returned %d", response.StatusCode)
		}
		if decodeErr != nil {
			return decodeErr
		}
		if status.Requests >= minimum {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func cancelViaAPI(ctx context.Context, runID uint64) error {
	manager, err := auth.NewManager(auth.Config{
		AccessSecret: mustEnv("E2E_JWT_ACCESS_SECRET"), RefreshSecret: mustEnv("E2E_JWT_REFRESH_SECRET"),
	})
	if err != nil {
		return err
	}
	token, err := manager.IssueAccessToken("1", 1)
	if err != nil {
		return err
	}
	target := fmt.Sprintf("%s/api/v1/projects/1/discovery/runs/%d/cancel", mustEnv("E2E_API_URL"), runID)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("ASM cancel returned %d: %s", response.StatusCode, string(body))
	}
	return nil
}

func enqueueReconcile(ctx context.Context, client *asynq.Client) error {
	raw, err := json.Marshal(discovery.ReconcileTimedOutRunsPayload{Limit: 100, ActorID: "e2e-reconcile"})
	if err != nil {
		return err
	}
	_, err = client.EnqueueContext(ctx, asynq.NewTask(discovery.TaskTypeReconcileTimedOutRun, raw), asynq.Queue("default"))
	return err
}

func enqueueCallbackRecovery(ctx context.Context, client *asynq.Client) error {
	raw, err := json.Marshal(discovery.RecoverCallbacksPayload{Limit: 100})
	if err != nil {
		return err
	}
	_, err = client.EnqueueContext(ctx, asynq.NewTask(discovery.TaskTypeRecoverCallbacks, raw), asynq.Queue("default"))
	return err
}

func seedProjectIdentity(ctx context.Context, db *sql.DB) {
	_, err := db.ExecContext(ctx, `INSERT INTO project (id,tenant_id,org_id,project_code,name,owner,status,created_by,updated_by)
		VALUES (1,'tenant-e2e','org-e2e','ext09','EXT09','owner','active','e2e','e2e')`)
	must(err)
	_, err = db.ExecContext(ctx, `INSERT INTO app_user (id,tenant_id,org_id,username,display_name,password_hash,status,auth_version,created_by,updated_by)
		VALUES (1,'tenant-e2e','org-e2e','ext09-operator','EXT09 Operator','e2e-not-a-login-password','active',1,'e2e','e2e')`)
	must(err)
	_, err = db.ExecContext(ctx, `INSERT INTO project_member (project_id,user_id,role,created_by,updated_by)
		VALUES (1,'1','security_ops','e2e','e2e')`)
	must(err)
}

func seedRun(ctx context.Context, db *sql.DB, name, domain string, timeoutSeconds int) uint64 {
	result, err := db.ExecContext(ctx, `INSERT INTO scope (tenant_id,org_id,project_id,name,status,authorized_by,valid_from,valid_until,created_by,updated_by)
		VALUES ('tenant-e2e','org-e2e',1,?,'active','owner',UTC_TIMESTAMP(3),DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 DAY),'e2e','e2e')`, name+" scope")
	must(err)
	scopeID, err := result.LastInsertId()
	must(err)
	_, err = db.ExecContext(ctx, `INSERT INTO scope_target (tenant_id,org_id,project_id,scope_id,target_type,match_mode,target_value,created_by,updated_by)
		VALUES ('tenant-e2e','org-e2e',1,?,'domain','include',?,'e2e','e2e')`, scopeID, domain)
	must(err)
	config := fmt.Sprintf(`{"targets":[{"type":"domain","value":%q}],"options":{"profile":"subdomain_passive","sources":["certificate_transparency"],"max_results":100}}`, domain)
	result, err = db.ExecContext(ctx, `INSERT INTO task_template (tenant_id,org_id,project_id,scope_id,name,task_type,config,enabled,timeout_seconds,rate_limit,concurrency,retry_limit,created_by,updated_by)
		VALUES ('tenant-e2e','org-e2e',1,?,?,'passive_intel',?,1,?,10,2,3,'e2e','e2e')`, scopeID, name+" template", config, timeoutSeconds)
	must(err)
	templateID, err := result.LastInsertId()
	must(err)
	result, err = db.ExecContext(ctx, `INSERT INTO task_run (tenant_id,org_id,project_id,template_id,scope_id,task_type,status,timeout_seconds,rate_limit,concurrency,retry_limit,callback_secret_ref,created_by,updated_by)
		VALUES ('tenant-e2e','org-e2e',1,?,?,'passive_intel','pending',?,10,2,3,?,'e2e','e2e')`, templateID, scopeID, timeoutSeconds, mustEnv("E2E_ENGINE_ID"))
	must(err)
	id, err := result.LastInsertId()
	must(err)
	if id <= 0 {
		must(errors.New("invalid TaskRun id"))
	}
	return uint64(id) // #nosec G115 -- positive AUTO_INCREMENT checked above
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func mustEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		must(fmt.Errorf("%s is required", key))
	}
	return value
}
