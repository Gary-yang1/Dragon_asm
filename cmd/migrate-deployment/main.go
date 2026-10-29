// migrate-deployment adapts an imported database to a new private engine network.
// It does not read or mutate the source database and never starts scans.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Gary-yang1/Dragon_asm/internal/discovery"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
	"github.com/Gary-yang1/Dragon_asm/internal/platform/db"
	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "deployment migration failed:", err)
		os.Exit(1)
	}
}
func run() error {
	if os.Getenv("DEPLOY_WAIT_ONLY") == "1" {
		for attempt := 0; attempt < 45; attempt++ {
			database, err := db.Open(db.LoadConfigFromEnv())
			if err == nil {
				database.Close()
				connection, redisErr := net.DialTimeout("tcp", os.Getenv("REDIS_ADDR"), 2*time.Second)
				if redisErr == nil {
					connection.Close()
					fmt.Println("Service dependencies ready")
					return nil
				}
			}
			time.Sleep(2 * time.Second)
		}
		return fmt.Errorf("database/cache did not become available")
	}

	if os.Getenv("DEPLOY_MIGRATION") != "1" {
		return fmt.Errorf("explicit DEPLOY_MIGRATION=1 is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	database, err := db.Open(db.LoadConfigFromEnv())
	if err != nil {
		return err
	}
	defer database.Close()
	key, err := discovery.LoadEngineSettingsKey(os.Getenv("ENGINE_SETTINGS_KEY_FILE"))
	if err != nil {
		return err
	}
	store, err := discovery.NewEngineSettingsStore(database, key)
	if err != nil {
		return err
	}
	current, err := store.Latest(ctx)
	if err != nil {
		return err
	}
	endpoint := os.Getenv("DISCOVERY_PASSIVE_ENGINE_BASE_URL")
	token := os.Getenv("DISCOVERY_PASSIVE_ENGINE_TOKEN")
	if endpoint == "" || token == "" {
		return fmt.Errorf("destination engine configuration is missing")
	}
	cfg := current.Settings
	if cfg.PassiveURL != endpoint || cfg.PassiveToken != token || cfg.Policy.Enabled {
		cfg.PassiveURL = endpoint
		cfg.PassiveToken = token
		cfg.Policy.Enabled = false
		// The old active engine is on a local VM; keep its credentials encrypted,
		// but require an explicit reachable endpoint before enabling dispatch here.
		cfg.ActiveURL = ""
		if cfg.Providers == nil {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/management/configuration", nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			response, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("engine configuration read failed")
			}
			defer response.Body.Close()
			if response.StatusCode != 200 {
				return fmt.Errorf("engine configuration status %d", response.StatusCode)
			}
			var providers discovery.ProviderSettings
			if json.NewDecoder(response.Body).Decode(&providers) != nil {
				return fmt.Errorf("invalid engine configuration")
			}
			cfg.Providers = &providers
		}
		next, err := store.Save(ctx, current.Version, cfg, audit.Event{TenantID: "platform", OrgID: "platform", ActorID: "deployment-migration", ActorType: audit.ActorSystem, Action: "platform.discovery_engine.configuration.migrate", ResourceType: "engine", ResourceID: "configuration", Metadata: map[string]any{"reason": "imported deployment; private Baiyan endpoint; active route disabled"}})
		if err != nil {
			return err
		}
		fmt.Println("Runtime configuration migrated to version", next.Version)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT id,project_id,tenant_id,org_id,status FROM task_run WHERE status IN ('pending','running') AND deleted_at='1970-01-01 00:00:00' FOR UPDATE")
	if err != nil {
		return err
	}
	type stale struct {
		id, project         uint64
		tenant, org, status string
	}
	var tasks []stale
	for rows.Next() {
		var t stale
		if err = rows.Scan(&t.id, &t.project, &t.tenant, &t.org, &t.status); err != nil {
			rows.Close()
			return err
		}
		tasks = append(tasks, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	recorder := audit.NewService(audit.NewRepository(dbgen.New(tx)))
	for _, t := range tasks {
		_, err = tx.ExecContext(ctx, "UPDATE task_run SET status='cancelled',error_summary='Deployment migration: execution not resumed on new server; restart explicitly if needed',finished_at=UTC_TIMESTAMP(3),updated_by='deployment-migration' WHERE id=? AND project_id=? AND status=?", t.id, t.project, t.status)
		if err != nil {
			return err
		}
		if err = recorder.Record(ctx, audit.Event{TenantID: t.tenant, OrgID: t.org, ProjectID: t.project, ActorID: "deployment-migration", ActorType: audit.ActorSystem, Action: "discovery.run.migration_interrupted", ResourceType: "task_run", ResourceID: fmt.Sprint(t.id), Before: map[string]any{"status": t.status}, After: map[string]any{"status": "cancelled"}, Metadata: map[string]any{"reason": "source execution cannot be safely resumed on destination"}}); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	fmt.Println("Imported unfinished executions preserved as migration-interrupted:", len(tasks))
	return nil
}
