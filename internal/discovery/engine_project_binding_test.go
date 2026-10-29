package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

type projectResolverFunc func(context.Context, engineProjectAPI, uint64) (int, error)

func (f projectResolverFunc) Resolve(ctx context.Context, a engineProjectAPI, id uint64) (int, error) {
	return f(ctx, a, id)
}

func TestActiveDispatchAutomaticallyResolvesProject(t *testing.T) {
	resolved := 0
	a := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
		var body activeAPIWebScanRequest
		require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
		require.Equal(t, 99, body.ProjectID)
		require.True(t, body.NoPOC)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":200,"data":{"taskid":"managed-task","total_targets":1,"total_pages":1,"page_size":100}}`))}, nil
	}})
	a.projectResolver = projectResolverFunc(func(_ context.Context, _ engineProjectAPI, id uint64) (int, error) {
		require.Equal(t, uint64(5), id)
		resolved++
		return 99, nil
	})
	id, err := a.Dispatch(context.Background(), ScanJob{RunID: 1, ProjectID: 5, ScopeID: 1, JobType: TaskTypeWebProbe, Targets: []Target{{Type: TargetTypeURL, Value: "https://example.com"}}})
	require.NoError(t, err)
	require.Equal(t, "managed-task", id)
	require.Equal(t, 1, resolved)
	_, err = a.Dispatch(context.Background(), ScanJob{RunID: 2, ProjectID: 5, ScopeID: 1, JobType: TaskTypeWebProbe, Targets: []Target{{Type: TargetTypeURL, Value: "invalid"}}})
	require.Error(t, err)
	require.Equal(t, 1, resolved, "invalid targets must not create a project")
	svc := &Service{engine: a}
	require.NoError(t, svc.validateEngineProject(5, TaskTypeWebProbe))
}

func TestManagedProjectLookupRejectsAmbiguousResponses(t *testing.T) {
	for _, body := range []string{`{"code":200,"data":null}`, `{"code":200,"data":{"projects":[],"total":-1}}`, `{"code":200,"data":{"projects":[{"id":1,"name":"x","description":"wrong"}],"total":1}}`, `{"code":200,"data":{"projects":[{"id":1,"name":"x","description":"d"},{"id":2,"name":"x","description":"d"}],"total":2}}`} {
		a := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
			require.Equal(t, activeAPISignature(activeAPITestSecret, req.Method, req.URL.Path, req.Header.Get("X-Timestamp"), req.Header.Get("X-Nonce"), nil), req.Header.Get("X-Signature"))
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		}})
		_, err := a.findManagedProject(context.Background(), "x", "d")
		require.Error(t, err)
	}
}

// Use a dedicated empty MySQL database; no application records are modified.
func TestManagedProjectMySQLConcurrencyAndRecovery(t *testing.T) {
	raw := os.Getenv("ASM_ENGINE_BINDING_TEST_DSN")
	if raw == "" {
		t.Skip("dedicated binding test database not configured")
	}
	cfg, err := mysql.ParseDSN(raw)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(cfg.DBName, "asm_binding_test_"))
	db, err := sql.Open("mysql", raw)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE project (id BIGINT UNSIGNED PRIMARY KEY, name VARCHAR(255), deleted_at DATETIME DEFAULT '1970-01-01 00:00:00') ENGINE=InnoDB`)
	require.NoError(t, err)
	body, err := os.ReadFile("../../migrations/000033_engine_project_binding.up.sql")
	require.NoError(t, err)
	_, err = db.Exec(string(body))
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO project(id,name) VALUES (5,'测试项目'),(6,'响应丢失'),(7,'权限不足'),(8,'未确认')`)
	require.NoError(t, err)
	ctx := context.Background()
	r := &sqlEngineProjectResolver{db: db}
	var mu sync.Mutex
	projects := map[string]managedActiveProject{}
	posts, creations := 0, 0
	mode := "ok"
	a := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		var data any
		if req.Method == http.MethodGet {
			items := []managedActiveProject{}
			if p, ok := projects[req.URL.Query().Get("search")]; ok {
				items = append(items, p)
			}
			data = map[string]any{"projects": items, "total": len(items)}
		} else {
			if req.URL.Path != activeAPIProjectEnsurePath {
				return nil, io.ErrUnexpectedEOF
			}
			posts++
			if mode == "forbidden" {
				return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			var p managedActiveProject
			if err := json.NewDecoder(req.Body).Decode(&p); err != nil {
				return nil, err
			}
			if existing, ok := projects[p.ExternalID]; ok {
				p = existing
			} else if mode != "unknown" {
				creations++
				p.ID = 100 + creations
				projects[p.ExternalID] = p
			}
			if mode == "lost" || mode == "unknown" {
				return nil, io.ErrUnexpectedEOF
			}
			data = p
		}
		b, _ := json.Marshal(map[string]any{"code": 200, "data": data})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b)))}, nil
	}})
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := r.Resolve(ctx, a, 5); errs <- e }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
	require.Equal(t, 1, creations)
	id, err := r.Resolve(ctx, a, 5)
	require.NoError(t, err)
	require.Equal(t, 101, id)
	a.accessKey = "rotated"
	postsBeforeReuse := posts
	id, err = (&sqlEngineProjectResolver{db: db}).Resolve(ctx, a, 5)
	require.NoError(t, err)
	require.Equal(t, 101, id)
	require.Equal(t, postsBeforeReuse, posts)
	mode = "lost"
	_, err = r.Resolve(ctx, a, 6)
	require.ErrorIs(t, err, ErrEngineProjectSetup)
	mode = "ok"
	id, err = r.Resolve(ctx, a, 6)
	require.NoError(t, err)
	require.Equal(t, 102, id)
	require.Equal(t, 2, creations)
	mode = "forbidden"
	_, err = r.Resolve(ctx, a, 7)
	require.Error(t, err)
	mode = "ok"
	_, err = r.Resolve(ctx, a, 7)
	require.NoError(t, err)
	require.Equal(t, 3, creations)
	mode = "unknown"
	_, err = r.Resolve(ctx, a, 8)
	require.ErrorIs(t, err, ErrEngineProjectSetup)
	mode = "ok"
	_, err = r.Resolve(ctx, a, 8)
	require.NoError(t, err)
	require.Equal(t, 4, creations)
	// Historical uncertain POST /projects must only reconcile, never call ensure.
	_, err = db.Exec(`INSERT INTO project(id,name) VALUES (9,'旧创建待确认')`)
	require.NoError(t, err)
	mode = "forbidden"
	_, err = r.Resolve(ctx, a, 9)
	require.Error(t, err)
	_, err = db.Exec(`UPDATE engine_project_binding SET creation_started=TRUE WHERE project_id=9`)
	require.NoError(t, err)
	legacyPosts := posts
	_, err = r.Resolve(ctx, a, 9)
	require.ErrorIs(t, err, ErrEngineProjectPending)
	require.Equal(t, legacyPosts, posts)
	var oldName, oldDescription string
	require.NoError(t, db.QueryRow(`SELECT remote_name, remote_description FROM engine_project_binding WHERE project_id=9`).Scan(&oldName, &oldDescription))
	projects[oldName] = managedActiveProject{ID: 777, Name: oldName, Description: oldDescription}
	id, err = r.Resolve(ctx, a, 9)
	require.NoError(t, err)
	require.Equal(t, 777, id)
	require.Equal(t, legacyPosts, posts)
	mode = "ok"
	a.baseURL = "https://other-engine.example.com/api/v1"
	id, err = r.Resolve(ctx, a, 5)
	require.NoError(t, err)
	require.NotEqual(t, 101, id)
	require.Equal(t, 5, creations)
}

func TestEnsureProjectProtocolAndIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"unsupported", 404, `{}`, ErrEngineProjectProtocol},
		{"unauthorized", 401, `{}`, ErrEngineProjectAccess},
		{"forbidden", 403, `{}`, ErrEngineProjectAccess},
		{"server error", 503, `{}`, ErrEngineProjectSetup},
		{"wrong identity", 200, `{"code":200,"data":{"id":99,"external_id":"other"}}`, ErrEngineProjectSetup},
		{"missing identity", 200, `{"code":200,"data":{"id":99}}`, ErrEngineProjectSetup},
		{"invalid id", 200, `{"code":200,"data":{"id":0,"external_id":"asm:test"}}`, ErrEngineProjectSetup},
		{"created project", 200, `{"code":200,"msg":"ok","data":{"id":99,"external_id":"asm:test","name":"old name","description":"description","created":true}}`, nil},
		{"renamed project", 200, `{"code":200,"msg":"ok","data":{"id":99,"external_id":"asm:test","name":"renamed","description":"engine notes","created":false}}`, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			a := newTestActiveAPIAdapter(t, fakeHTTPClient{do: func(req *http.Request) (*http.Response, error) {
				calls++
				require.Equal(t, activeAPIProjectEnsurePath, req.URL.Path)
				require.Equal(t, http.MethodPost, req.Method)
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body))}, nil
			}})
			_, err := a.ensureManagedProject(context.Background(), "asm:test", "old name", "description")
			if test.want == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.want)
			}
			require.Equal(t, 1, calls, "never fall back to non-idempotent project creation")
		})
	}
}
