package discovery

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/audit"
)

// Configuration exposes public values and masks, retaining offline connection editing.
func (s *EngineManagementService) Configuration(ctx context.Context, actorID string) (EngineSettingsView, error) {
	if _, err := s.authorize(ctx, actorID); err != nil {
		return EngineSettingsView{}, err
	}
	if s.settings == nil {
		return EngineSettingsView{}, ErrEngineSettingsUnavailable
	}
	snapshot, err := s.settings.Latest(ctx)
	if err != nil {
		return EngineSettingsView{}, err
	}
	legacy := snapshot.Settings.Providers == nil
	if legacy {
		providers, err := readLegacyProviders(ctx, snapshot)
		if err != nil {
			view := settingsView(snapshot)
			view.ProviderError = ErrProviderSettingsUnavailable.Error()
			return view, nil //nolint:nilerr // ProviderError is an explicit partial failure; connection fields remain editable.
		}
		snapshot.Settings.Providers = &providers
	}
	view := settingsView(snapshot)
	view.ProvidersManaged = !legacy
	return view, nil
}
func readLegacyProviders(ctx context.Context, snapshot EngineSettingsSnapshot) (ProviderSettings, error) {
	router, _ := snapshot.Router()
	adapter, err := router.EngineForTaskType(TaskTypePassiveIntel)
	if err != nil {
		return ProviderSettings{}, ErrProviderSettingsUnavailable
	}
	httpAdapter, ok := adapter.(*HTTPEngineAdapter)
	if !ok {
		return ProviderSettings{}, ErrProviderSettingsUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return httpAdapter.readProviderConfiguration(ctx)
}

// UpdateConfiguration validates and audits a system administrator configuration edit.
func (s *EngineManagementService) UpdateConfiguration(ctx context.Context, actorID string, in UpdateEngineSettingsInput, meta AuditMeta) (EngineSettingsView, error) {
	actor, err := s.authorize(ctx, actorID)
	if err != nil {
		return EngineSettingsView{}, err
	}
	if s.settings == nil {
		return EngineSettingsView{}, ErrEngineSettingsUnavailable
	}
	if in.Version == 0 || len(in.Values) > 32 || len(in.ClearSecrets) > 9 || len(strings.TrimSpace(in.Reason)) == 0 || len(in.Reason) > 512 {
		return EngineSettingsView{}, ErrEngineSettingsInvalid
	}
	snapshot, err := s.settings.Latest(ctx)
	if err != nil {
		return EngineSettingsView{}, err
	}
	if snapshot.Version != in.Version {
		return EngineSettingsView{}, ErrEngineSettingsConflict
	}
	providerPatch := false
	for key := range in.Values {
		if strings.HasPrefix(key, "subfinder_") || strings.HasPrefix(key, "quake_") || strings.HasPrefix(key, "hunter_") || strings.HasPrefix(key, "fofa_") || strings.HasPrefix(key, "provider_") || strings.HasPrefix(key, "dns_") {
			providerPatch = true
		}
	}
	for _, key := range in.ClearSecrets {
		if strings.HasPrefix(key, "subfinder_") || strings.HasPrefix(key, "quake_") || strings.HasPrefix(key, "hunter_") || strings.HasPrefix(key, "fofa_") || strings.HasPrefix(key, "provider_") || strings.HasPrefix(key, "dns_") {
			providerPatch = true
		}
	}
	if providerPatch && snapshot.Settings.Providers == nil {
		p, err := readLegacyProviders(ctx, snapshot)
		if err != nil {
			return EngineSettingsView{}, err
		}
		snapshot.Settings.Providers = &p
	}
	updated, err := applySettingsPatch(snapshot.Settings, in)
	if err != nil {
		return EngineSettingsView{}, err
	}
	fields := make([]string, 0, len(in.Values)+len(in.ClearSecrets))
	for key := range in.Values {
		fields = append(fields, key)
	}
	fields = append(fields, in.ClearSecrets...)
	sort.Strings(fields)
	next, err := s.settings.Save(ctx, in.Version, updated, audit.Event{TenantID: actor.TenantID, OrgID: actor.OrgID, ActorID: actorID, ActorType: audit.ActorUser, Action: "platform.discovery_engine.configuration.update", ResourceType: ResourceTypeEngine, ResourceID: "configuration", IP: meta.IP, UserAgent: meta.UserAgent, RequestID: meta.RequestID, Metadata: map[string]any{"changed_fields": fields, "reason": strings.TrimSpace(in.Reason)}})
	if err != nil {
		return EngineSettingsView{}, err
	}
	return settingsView(next), nil
}
