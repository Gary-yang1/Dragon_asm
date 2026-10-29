package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	workerEngineRuntimeKey = "asm:discovery:engine-worker:v1"

	// WorkerEngineHeartbeatTTL leaves room for two missed 15-second refreshes
	// before the UI reports the worker as stale/unknown.
	WorkerEngineHeartbeatTTL      = 45 * time.Second
	WorkerEngineHeartbeatInterval = 15 * time.Second
)

var ErrWorkerEngineStatusUnavailable = errors.New("discovery: worker engine status unavailable")

// WorkerEngineRuntimeStatus contains only a non-secret routing fingerprint and
// timestamp. It is safe to share through Redis and cannot be used to recover a
// Token, AK, SK, or Provider credential.
type WorkerEngineRuntimeStatus struct {
	ConfigurationVersion uint64    `json:"configuration_version,omitempty"`
	ConfigFingerprint    string    `json:"config_fingerprint"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type RedisEngineRuntimeStore struct {
	client *redis.Client
	key    string
}

func NewRedisEngineRuntimeStore(client *redis.Client) *RedisEngineRuntimeStore {
	return &RedisEngineRuntimeStore{client: client, key: workerEngineRuntimeKey}
}

func (s *RedisEngineRuntimeStore) WriteWorkerEngineStatus(
	ctx context.Context,
	status WorkerEngineRuntimeStatus,
) error {
	if s == nil || s.client == nil || !validEngineConfigFingerprint(status.ConfigFingerprint) || status.UpdatedAt.IsZero() {
		return ErrWorkerEngineStatusUnavailable
	}
	payload, err := json.Marshal(status)
	if err != nil {
		return ErrWorkerEngineStatusUnavailable
	}
	if err := s.client.Set(ctx, s.key, payload, WorkerEngineHeartbeatTTL).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrWorkerEngineStatusUnavailable, err)
	}
	return nil
}

func (s *RedisEngineRuntimeStore) ReadWorkerEngineStatus(ctx context.Context) (WorkerEngineRuntimeStatus, error) {
	if s == nil || s.client == nil {
		return WorkerEngineRuntimeStatus{}, ErrWorkerEngineStatusUnavailable
	}
	raw, err := s.client.Get(ctx, s.key).Bytes()
	if errors.Is(err, redis.Nil) {
		return WorkerEngineRuntimeStatus{}, ErrWorkerEngineStatusUnavailable
	}
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return WorkerEngineRuntimeStatus{}, ErrWorkerEngineStatusUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var status WorkerEngineRuntimeStatus
	if err := decoder.Decode(&status); err != nil {
		return WorkerEngineRuntimeStatus{}, ErrWorkerEngineStatusUnavailable
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return WorkerEngineRuntimeStatus{}, ErrWorkerEngineStatusUnavailable
	}
	if !validEngineConfigFingerprint(status.ConfigFingerprint) || status.UpdatedAt.IsZero() {
		return WorkerEngineRuntimeStatus{}, ErrWorkerEngineStatusUnavailable
	}
	return status, nil
}

// EngineRuntimeConfigFingerprint compares API and Worker routing without hashing
// raw credentials. It includes endpoint, project mapping, policy, and whether
// each credential is present, but never the credential value itself.
func EngineRuntimeConfigFingerprint(config EngineRouterConfig, policy ActiveDispatchPolicy) string {
	type fingerprintMaterial struct {
		Version               int      `json:"version"`
		PassiveBaseURL        string   `json:"passive_base_url"`
		PassiveTokenSet       bool     `json:"passive_token_set"`
		ActiveBaseURL         string   `json:"active_base_url"`
		ActiveAccessKeySet    bool     `json:"active_access_key_set"`
		ActiveSecretKeySet    bool     `json:"active_secret_key_set"`
		ActiveProjectMappings []string `json:"active_project_mappings"`
		ActivePolicy          []bool   `json:"active_policy"`
	}

	mappings := make([]string, 0)
	if projectMap, err := parseActiveEngineProjectMap(config.ActiveProjectMap); err == nil {
		for asmProjectID, engineProjectID := range projectMap {
			mappings = append(mappings, fmt.Sprintf("%d=%d", asmProjectID, engineProjectID))
		}
		sort.Strings(mappings)
	} else if strings.TrimSpace(config.ActiveProjectMap) != "" {
		mappings = append(mappings, "invalid")
	}
	payload, _ := json.Marshal(fingerprintMaterial{
		Version:               1,
		PassiveBaseURL:        safeManagedBaseURL(config.PassiveBaseURL),
		PassiveTokenSet:       strings.TrimSpace(config.PassiveToken) != "",
		ActiveBaseURL:         safeManagedBaseURL(config.ActiveBaseURL),
		ActiveAccessKeySet:    strings.TrimSpace(config.ActiveAccessKey) != "",
		ActiveSecretKeySet:    strings.TrimSpace(config.ActiveSecretKey) != "",
		ActiveProjectMappings: mappings,
		ActivePolicy:          []bool{policy.Enabled, policy.RequireApproval, policy.RequireOwnership},
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func validEngineConfigFingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
