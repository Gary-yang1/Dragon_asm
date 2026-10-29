package discovery

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

// StageProgress contains absolute counters for a source and target pair.
type StageProgress struct {
	Stage      string `json:"stage"`
	Provider   string `json:"provider"`
	Target     string `json:"target"`
	Status     string `json:"status"`
	Discovered int    `json:"discovered"`
	Completed  int    `json:"completed"`
	Total      int    `json:"total"`
	Failed     int    `json:"failed"`
	NoRecords  int    `json:"no_records"`
	Message    string `json:"message,omitempty"`
}

func validStageProgress(p StageProgress) bool {
	if p.Stage != "collect" && p.Stage != "dns" {
		return false
	}
	if len(p.Provider) == 0 || len(p.Provider) > 64 || len(p.Target) > 253 || len(p.Message) > 512 {
		return false
	}
	switch p.Status {
	case "queued", "running", "success", "partial", "failed", "skipped":
	default:
		return false
	}
	for _, n := range []int{p.Discovered, p.Completed, p.Total, p.Failed, p.NoRecords} {
		if n < 0 || n > 1000000 {
			return false
		}
	}
	return p.Completed <= p.Total
}

type RunActivity struct {
	Status           string             `json:"status"`
	Stages           []StageProgress    `json:"stages"`
	Recent           []RunDiscoveryItem `json:"recent"`
	AssetCount       int                `json:"asset_count"`
	SubdomainCount   int                `json:"subdomain_count"`
	IPCount          int                `json:"ip_count"`
	ReceivedBatches  int                `json:"received_batches"`
	ProcessedBatches int                `json:"processed_batches"`
	FailedBatches    int                `json:"failed_batches"`
	Truncated        bool               `json:"truncated"`
}
type RunDiscoveryItem struct {
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	Provider   string    `json:"provider"`
	ObservedAt time.Time `json:"observed_at"`
	DNSStatus  string    `json:"dns_status,omitempty"`
	DNSError   string    `json:"dns_error,omitempty"`
}

func (s *Service) RunActivity(ctx context.Context, projectID, runID uint64) (RunActivity, error) {
	result := RunActivity{Stages: []StageProgress{}, Recent: []RunDiscoveryItem{}}
	run, err := s.GetTaskRun(ctx, projectID, runID)
	if err != nil {
		return result, err
	}
	result.Status = run.Status
	if s.db == nil {
		return result, nil
	}
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(ingest_status='processed'),0),COALESCE(SUM(ingest_status='failed'),0) FROM discovery_callback WHERE project_id=? AND run_id=? AND deleted_at='1970-01-01 00:00:00'`, projectID, runID).Scan(&result.ReceivedBatches, &result.ProcessedBatches, &result.FailedBatches)
	if err != nil {
		return result, err
	}
	// Read only the small progress/diagnostic projection, never sort full payloads.
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(CAST(JSON_EXTRACT(payload_json,'$.stage_progress') AS CHAR),'null'), COALESCE(CAST(JSON_EXTRACT(payload_json,'$.provider_errors') AS CHAR),'[]') FROM discovery_callback WHERE project_id=? AND run_id=? AND deleted_at='1970-01-01 00:00:00' AND (JSON_CONTAINS_PATH(payload_json,'one','$.stage_progress') OR JSON_LENGTH(JSON_EXTRACT(payload_json,'$.provider_errors'))>0) ORDER BY seq DESC LIMIT 1001`, projectID, runID)
	if err != nil {
		return result, err
	}
	stages := map[string]StageProgress{}
	warnings := map[string]StageProgress{}
	n := 0
	for rows.Next() {
		var raw, diagnostics string
		if err = rows.Scan(&raw, &diagnostics); err != nil {
			rows.Close()
			return result, err
		}
		n++
		if n > 1000 {
			result.Truncated = true
			break
		}
		var p *StageProgress
		if json.Unmarshal([]byte(raw), &p) == nil && p != nil {
			key := p.Stage + "|" + p.Provider + "|" + p.Target
			if _, ok := stages[key]; !ok {
				stages[key] = *p
			}
		}
		var errs []callbackProviderError
		if json.Unmarshal([]byte(diagnostics), &errs) == nil {
			for _, e := range errs {
				if _, ok := warnings[e.Provider]; !ok {
					stage := "collect"
					if e.Provider == "dns" {
						stage = "dns"
					}
					warnings[e.Provider] = StageProgress{Stage: stage, Provider: e.Provider, Status: "partial", Message: e.Code + ": " + e.Message}
				}
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	providers := map[string]bool{}
	for _, p := range stages {
		result.Stages = append(result.Stages, p)
		providers[p.Provider] = true
	}
	for provider, p := range warnings {
		if !providers[provider] {
			result.Stages = append(result.Stages, p)
		}
	}
	sort.Slice(result.Stages, func(i, j int) bool {
		a, b := result.Stages[i], result.Stages[j]
		return a.Stage+a.Provider+a.Target < b.Stage+b.Provider+b.Target
	})
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT CONCAT(JSON_UNQUOTE(JSON_EXTRACT(normalized_json,'$.asset_type')),':',JSON_UNQUOTE(JSON_EXTRACT(normalized_json,'$.value')))), COUNT(DISTINCT CASE WHEN JSON_UNQUOTE(JSON_EXTRACT(normalized_json,'$.asset_type'))='subdomain' THEN JSON_UNQUOTE(JSON_EXTRACT(normalized_json,'$.value')) END),COUNT(DISTINCT CASE WHEN JSON_UNQUOTE(JSON_EXTRACT(normalized_json,'$.asset_type'))='ip' THEN JSON_UNQUOTE(JSON_EXTRACT(normalized_json,'$.value')) END) FROM discovery_observation WHERE project_id=? AND run_id=? AND kind='asset' AND ingest_status='materialized' AND deleted_at='1970-01-01 00:00:00'`, projectID, runID).Scan(&result.AssetCount, &result.SubdomainCount, &result.IPCount)
	if err != nil {
		return result, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT provider,normalized_json,observed_at FROM discovery_observation WHERE project_id=? AND run_id=? AND kind='asset' AND ingest_status='materialized' AND deleted_at='1970-01-01 00:00:00' ORDER BY seq DESC, id DESC LIMIT 60`, projectID, runID)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var provider string
		var raw []byte
		var at time.Time
		if err = rows.Scan(&provider, &raw, &at); err != nil {
			return result, err
		}
		var fact callbackAssetV1
		if json.Unmarshal(raw, &fact) != nil {
			continue
		}
		key := fact.AssetType + ":" + fact.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		result.Recent = append(result.Recent, RunDiscoveryItem{Type: fact.AssetType, Value: fact.Value, Provider: provider, ObservedAt: at, DNSStatus: fact.Attributes["dns_status"], DNSError: fact.Attributes["dns_error"]})
		if len(result.Recent) == 20 {
			break
		}
	}
	return result, rows.Err()
}
