package discovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/hibiken/asynq"
)

const TaskTypeEnrichWebNetwork = "enrich_web_network"
const enrichmentMaxAttempts = 5

// No task status is changed by this worker. Its own durable rows are the queue.
type NetworkEnrichmentHandler struct {
	service *Service
	logger  *slog.Logger
}

func NewNetworkEnrichmentHandler(s *Service, l *slog.Logger) *NetworkEnrichmentHandler {
	return &NetworkEnrichmentHandler{s, l}
}
func (h *NetworkEnrichmentHandler) Register(m *asynq.ServeMux) {
	m.HandleFunc(TaskTypeEnrichWebNetwork, h.Handle)
}
func (h *NetworkEnrichmentHandler) Handle(ctx context.Context, _ *asynq.Task) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	n, err := h.service.EnrichWebNetwork(ctx)
	if h.logger != nil {
		h.logger.Info("website network enrichment finished", "processed", n, "failed", err != nil)
	}
	return err
}

type enrichmentWork struct {
	ID, ProjectID, RunID, Version uint64
	Attempts                      int
	Token                         string
	Raw                           []byte
}

func (s *Service) seedNetworkEnrichment(ctx context.Context) error {
	version := 0
	if s.engineSettings != nil {
		version = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO web_network_enrichment (observation_id,project_id,run_id,config_version,source_hash)
 SELECT o.id,o.project_id,o.run_id,COALESCE(b.version,?),SHA2(CAST(o.normalized_json AS CHAR),256)
 FROM discovery_observation o JOIN task_run r ON r.id=o.run_id AND r.project_id=o.project_id
 JOIN project p ON p.id=o.project_id
 LEFT JOIN engine_run_settings b ON b.run_id=r.id AND b.project_id=r.project_id
 LEFT JOIN web_network_enrichment e ON e.observation_id=o.id
 WHERE e.observation_id IS NULL AND o.kind='exposure' AND o.ingest_status='materialized'
 AND o.deleted_at='1970-01-01 00:00:00' AND r.deleted_at='1970-01-01 00:00:00' AND p.deleted_at='1970-01-01 00:00:00'
 AND p.status='active' AND r.status IN ('success','partial_success') AND r.task_type IN ('web_probe','fingerprint')
 AND JSON_UNQUOTE(JSON_EXTRACT(o.normalized_json,'$.exposure_type'))='web'
 ORDER BY o.id LIMIT 100 ON DUPLICATE KEY UPDATE observation_id=web_network_enrichment.observation_id`, version)
	return err
}

func (s *Service) claimNetworkEnrichment(ctx context.Context) ([]enrichmentWork, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `UPDATE web_network_enrichment e
 JOIN discovery_observation o ON o.id=e.observation_id AND o.project_id=e.project_id AND o.run_id=e.run_id
 JOIN task_run r ON r.id=e.run_id AND r.project_id=e.project_id JOIN project p ON p.id=e.project_id
 SET e.state='failed',e.lease_token='',e.error_summary='来源记录或项目状态已变化，已停止补充信息'
 WHERE e.state IN ('pending','running') AND (p.status<>'active' OR r.status NOT IN ('success','partial_success')
 OR o.deleted_at<>'1970-01-01 00:00:00' OR r.deleted_at<>'1970-01-01 00:00:00' OR p.deleted_at<>'1970-01-01 00:00:00'
 OR e.source_hash<>SHA2(CAST(o.normalized_json AS CHAR),256))`); err != nil {
		return nil, err
	}
	// Exhausted leases become visible failures even when a worker died five times.
	if _, err = tx.ExecContext(ctx, `UPDATE web_network_enrichment SET state='failed',error_summary='补充信息多次中断，可手动重试'
 WHERE state='running' AND lease_until<? AND attempts>=5`, now); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT e.observation_id,e.project_id,e.run_id,e.config_version,e.attempts,o.normalized_json
 FROM web_network_enrichment e JOIN discovery_observation o ON o.id=e.observation_id AND o.project_id=e.project_id AND o.run_id=e.run_id
 JOIN task_run r ON r.id=e.run_id AND r.project_id=e.project_id JOIN project p ON p.id=e.project_id
 WHERE ((e.state='pending' AND e.next_attempt_at<=?) OR (e.state='running' AND e.lease_until<?)) AND e.attempts<5
 AND o.deleted_at='1970-01-01 00:00:00' AND r.deleted_at='1970-01-01 00:00:00' AND p.deleted_at='1970-01-01 00:00:00'
 AND p.status='active' AND r.status IN ('success','partial_success') AND o.ingest_status='materialized'
 ORDER BY e.next_attempt_at,e.observation_id LIMIT 20 FOR UPDATE SKIP LOCKED`, now, now)
	if err != nil {
		return nil, err
	}
	all := []enrichmentWork{}
	for rows.Next() {
		var w enrichmentWork
		if err = rows.Scan(&w.ID, &w.ProjectID, &w.RunID, &w.Version, &w.Attempts, &w.Raw); err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, w)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	claimed := []enrichmentWork{}
	for _, w := range all {
		// A batch uses one configuration version; untouched versions remain queued.
		if len(claimed) > 0 && w.Version != claimed[0].Version {
			continue
		}
		token := make([]byte, 16)
		if _, err = rand.Read(token); err != nil {
			return nil, err
		}
		w.Token = hex.EncodeToString(token)
		w.Attempts++
		_, err = tx.ExecContext(ctx, `UPDATE web_network_enrichment SET state='running',attempts=attempts+1,lease_token=?,lease_until=? WHERE observation_id=?`, w.Token, now.Add(90*time.Second), w.ID)
		if err != nil {
			return nil, err
		}
		claimed = append(claimed, w)
	}
	return claimed, tx.Commit()
}

func networkInput(w enrichmentWork) (networkEnrichmentInput, error) {
	var fact struct {
		URL         string `json:"url"`
		Fingerprint string `json:"fingerprint"`
	}
	if json.Unmarshal(w.Raw, &fact) != nil {
		return networkEnrichmentInput{}, errNetworkEnrichment
	}
	u, err := url.Parse(fact.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return networkEnrichmentInput{}, errNetworkEnrichment
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return networkEnrichmentInput{}, errNetworkEnrichment
		}
		host = ip.String()
	} else {
		if len(host) > 253 || !strings.Contains(host, ".") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost") {
			return networkEnrichmentInput{}, errNetworkEnrichment
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return networkEnrichmentInput{}, errNetworkEnrichment
			}
			for _, ch := range label {
				if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
					return networkEnrichmentInput{}, errNetworkEnrichment
				}
			}
		}
		if strings.Trim(host[strings.LastIndex(host, ".")+1:], "0123456789") == "" {
			return networkEnrichmentInput{}, errNetworkEnrichment
		}
	}
	in := networkEnrichmentInput{Key: strconv.FormatUint(w.ID, 10), Host: host}
	for _, name := range strings.Split(fact.Fingerprint, ",") {
		if name = strings.TrimSpace(name); name != "" && len(name) <= 128 && strings.IndexFunc(name, unicode.IsControl) < 0 && len(in.Fingerprints) < 32 {
			in.Fingerprints = append(in.Fingerprints, name)
		}
	}
	return in, nil
}

func (s *Service) enrichmentAdapter(ctx context.Context, version uint64) (*HTTPEngineAdapter, error) {
	current := s
	if s.engineSettings != nil {
		if version == 0 {
			version = 1
		}
		snap, err := s.engineSettings.Version(ctx, version)
		if err != nil {
			return nil, err
		}
		current = s.serviceWithSettings(snap)
	}
	engine, err := current.engineForTaskType(TaskTypePassiveIntel)
	if err != nil {
		return nil, err
	}
	a, ok := engine.(*HTTPEngineAdapter)
	if !ok {
		return nil, ErrEngineNotConfigured
	}
	return a, nil
}

// EnrichWebNetwork processes one bounded batch, recovered by the periodic scheduler.
func (s *Service) EnrichWebNetwork(ctx context.Context) (int, error) {
	if s.db == nil {
		return 0, errNetworkEnrichment
	}
	if err := s.seedNetworkEnrichment(ctx); err != nil {
		return 0, err
	}
	work, err := s.claimNetworkEnrichment(ctx)
	if err != nil || len(work) == 0 {
		return 0, err
	}
	inputs := []networkEnrichmentInput{}
	valid := []enrichmentWork{}
	done := 0
	for _, w := range work {
		in, err := networkInput(w)
		if err != nil {
			if err = s.finishNetworkEnrichment(ctx, w, nil, "来源网站信息无效", true); err != nil {
				return done, err
			}
			done++
			continue
		}
		inputs = append(inputs, in)
		valid = append(valid, w)
	}
	if len(valid) == 0 {
		return done, nil
	}
	a, err := s.enrichmentAdapter(ctx, valid[0].Version)
	var results map[string]networkEnrichmentResult
	if err == nil {
		requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		results, err = a.enrichNetwork(requestCtx, inputs)
		cancel()
	}
	for _, w := range valid {
		var result *networkEnrichmentResult
		message := ""
		permanent := false
		if err != nil {
			message = "Baiyan 暂时不可用，将自动重试"
			var httpErr *engineStatusError
			if errors.As(err, &httpErr) && httpErr.permanent() {
				permanent = true
				message = "Baiyan 未开放网络补充接口，请检查版本与连接权限"
			}
		} else {
			value := results[strconv.FormatUint(w.ID, 10)]
			result = &value
			if value.Status == "failed" {
				message = "DNS 信息未能获取，将自动重试"
			}
		}
		if finishErr := s.finishNetworkEnrichment(ctx, w, result, message, permanent); finishErr != nil {
			return done, finishErr
		}
		done++
	}
	return done, nil
}

func (s *Service) finishNetworkEnrichment(ctx context.Context, w enrichmentWork, result *networkEnrichmentResult, message string, permanent bool) error {
	state := "complete"
	var raw any
	var enriched any
	if result != nil {
		body, err := json.Marshal(result)
		if err != nil {
			return err
		}
		raw = string(body)
		enriched = result.ObservedAt.UTC()
	}
	if message != "" {
		state = "pending"
		if permanent || w.Attempts >= enrichmentMaxAttempts {
			state = "failed"
			message = strings.ReplaceAll(message, "将自动重试", "可手动重试")
		}
	}
	now := time.Now().UTC()
	changed, err := s.db.ExecContext(ctx, `UPDATE web_network_enrichment e
 JOIN discovery_observation o ON o.id=e.observation_id AND o.project_id=e.project_id AND o.run_id=e.run_id
 JOIN task_run r ON r.id=e.run_id AND r.project_id=e.project_id JOIN project p ON p.id=e.project_id
 SET e.state=?,e.result_json=?,e.enriched_at=?,e.error_summary=?,e.next_attempt_at=?,e.lease_token='',e.lease_until='1970-01-01 00:00:00'
 WHERE e.observation_id=? AND e.state='running' AND e.lease_token=? AND e.lease_until>?
 AND e.source_hash=SHA2(CAST(o.normalized_json AS CHAR),256)
 AND o.deleted_at='1970-01-01 00:00:00' AND r.deleted_at='1970-01-01 00:00:00' AND p.deleted_at='1970-01-01 00:00:00'
 AND p.status='active' AND r.status IN ('success','partial_success')`, state, raw, enriched, message, now.Add(time.Duration(20*w.Attempts)*time.Second), w.ID, w.Token, now)
	if err != nil {
		return err
	}
	n, err := changed.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		_, err = s.db.ExecContext(ctx, `UPDATE web_network_enrichment SET state='failed',error_summary='来源记录或项目状态已变化，未写入补充信息',lease_token='' WHERE observation_id=? AND state='running' AND lease_token=? AND lease_until>?`, w.ID, w.Token, now)
	}
	return err
}

func RegisterNetworkEnrichmentTask(registrar PeriodicTaskRegistrar, queue string) (string, error) {
	if queue == "" {
		queue = "low"
	}
	return registrar.Register("@every 30s", asynq.NewTask(TaskTypeEnrichWebNetwork, nil), asynq.Queue(queue), asynq.MaxRetry(0), asynq.Timeout(time.Minute), asynq.Unique(25*time.Second))
}
