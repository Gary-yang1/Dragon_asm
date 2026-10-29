//revive:disable:exported

package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// EngineRoute identifies one independently configured discovery engine.
type EngineRoute string

const (
	EngineRoutePassive EngineRoute = "passive"
	EngineRouteActive  EngineRoute = "active"

	maxActiveProjectMapBytes = 16 << 10
)

var ErrEngineRouteUnsupported = errors.New("discovery: task type has no engine route")

// EngineSelector chooses the adapter that owns one task type. Selection must
// never fall back to another route: a missing or unhealthy active engine must
// not cause an active task to reach the passive engine, or vice versa.
type EngineSelector interface {
	EngineForTaskType(taskType string) (EngineAdapter, error)
}

// TaskTypeEngineRouter keeps passive and active engine configuration isolated.
type TaskTypeEngineRouter struct {
	passive EngineAdapter
	active  EngineAdapter
}

// NewTaskTypeEngineRouter creates a deterministic task-type router. Either
// adapter may be nil so one engine can remain available while the other is
// unconfigured.
func NewTaskTypeEngineRouter(passive, active EngineAdapter) *TaskTypeEngineRouter {
	return &TaskTypeEngineRouter{passive: passive, active: active}
}

// EngineRouteForTaskType returns the engine contract for a known routed type.
// dirscan deliberately has no route until its legal and lifecycle controls are
// designed; it must not be enabled just because it is classified as active.
func EngineRouteForTaskType(taskType string) (EngineRoute, error) {
	switch strings.TrimSpace(taskType) {
	case TaskTypePassiveIntel, TaskTypeDNS, TaskTypeOrgIntel:
		return EngineRoutePassive, nil
	case TaskTypePortProbe, TaskTypeWebProbe, TaskTypeFingerprint:
		return EngineRouteActive, nil
	default:
		return "", errors.Join(ErrEngineJobRejected, ErrEngineRouteUnsupported)
	}
}

// EngineForTaskType returns exactly the configured adapter for taskType.
func (r *TaskTypeEngineRouter) EngineForTaskType(taskType string) (EngineAdapter, error) {
	route, err := EngineRouteForTaskType(taskType)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, ErrEngineNotConfigured
	}

	var adapter EngineAdapter
	switch route {
	case EngineRoutePassive:
		adapter = r.passive
	case EngineRouteActive:
		adapter = r.active
	}
	if adapter == nil {
		return nil, fmt.Errorf("%w: %s route", ErrEngineNotConfigured, route)
	}
	return adapter, nil
}

// EngineRouterConfig contains trusted process configuration for both engines.
// Secret values are accepted here but are never included in status or errors.
type EngineRouterConfig struct {
	PassiveBaseURL string `json:"-"`
	PassiveToken   string `json:"-"`

	ActiveBaseURL    string `json:"-"`
	ActiveAccessKey  string `json:"-"`
	ActiveSecretKey  string `json:"-"`
	ActiveProjectMap string `json:"-"`
}

// EngineRouteConfigStatus reports configuration readiness without exposing
// credentials.
type EngineRouteConfigStatus struct {
	Configured bool
	Ready      bool
	Err        error
}

// EngineRouterConfigStatus keeps passive and active setup failures independent.
type EngineRouterConfigStatus struct {
	Passive EngineRouteConfigStatus
	Active  EngineRouteConfigStatus
}

// NewConfiguredEngineRouter builds both adapters independently. An invalid
// active configuration therefore does not disable a valid passive engine.
func NewConfiguredEngineRouter(
	config EngineRouterConfig,
	passiveClient HTTPClient,
	activeClient HTTPClient,
) (*TaskTypeEngineRouter, EngineRouterConfigStatus) {
	var passive EngineAdapter
	var active EngineAdapter
	var status EngineRouterConfigStatus

	status.Passive.Configured = anyConfigured(config.PassiveBaseURL, config.PassiveToken)
	if status.Passive.Configured {
		adapter, err := NewHTTPEngineAdapter(config.PassiveBaseURL, config.PassiveToken, passiveClient)
		if err != nil {
			status.Passive.Err = fmt.Errorf("passive engine configuration: %w", err)
		} else {
			passive = adapter
			status.Passive.Ready = true
		}
	}

	status.Active.Configured = anyConfigured(
		config.ActiveBaseURL,
		config.ActiveAccessKey,
		config.ActiveSecretKey,
		config.ActiveProjectMap,
	)
	if status.Active.Configured {
		projectMap, err := parseActiveEngineProjectMap(config.ActiveProjectMap)
		if err != nil {
			status.Active.Err = err
		} else {
			adapter, adapterErr := NewActiveAPIEngineAdapter(
				config.ActiveBaseURL,
				config.ActiveAccessKey,
				config.ActiveSecretKey,
				projectMap,
				activeClient,
			)
			if adapterErr != nil {
				status.Active.Err = fmt.Errorf("active engine configuration: %w", adapterErr)
			} else {
				active = adapter
				status.Active.Ready = true
			}
		}
	}

	return NewTaskTypeEngineRouter(passive, active), status
}

func anyConfigured(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func parseActiveEngineProjectMap(raw string) (map[uint64]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		return map[uint64]int{}, nil
	}
	if len(raw) > maxActiveProjectMapBytes {
		return nil, fmt.Errorf("active engine project map: %w", ErrEngineNotConfigured)
	}

	var encoded map[string]int
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	if err := decoder.Decode(&encoded); err != nil {
		return nil, fmt.Errorf("active engine project map: %w", ErrEngineNotConfigured)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("active engine project map: %w", ErrEngineNotConfigured)
	}
	if encoded == nil {
		return nil, fmt.Errorf("active engine project map: %w", ErrEngineNotConfigured)
	}

	projectMap := make(map[uint64]int, len(encoded))
	for rawASMProjectID, engineProjectID := range encoded {
		asmProjectID, err := strconv.ParseUint(rawASMProjectID, 10, 64)
		if err != nil || asmProjectID == 0 || engineProjectID <= 0 {
			return nil, fmt.Errorf("active engine project map: %w", ErrEngineNotConfigured)
		}
		projectMap[asmProjectID] = engineProjectID
	}
	return projectMap, nil
}
