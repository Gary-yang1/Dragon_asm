package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

func (a *HTTPEngineAdapter) readProviderConfiguration(ctx context.Context) (ProviderSettings, error) {
	var settings ProviderSettings
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/management/configuration", nil)
	if err != nil {
		return settings, ErrProviderSettingsUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := a.client.Do(req)
	if err != nil {
		return settings, ErrProviderSettingsUnavailable
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK || decodeEngineJSON(resp.Body, &settings) != nil {
		return settings, ErrProviderSettingsUnavailable
	}
	return settings, nil
}
func (a *HTTPEngineAdapter) ensureProviderConfiguration(ctx context.Context) error {
	if a == nil || a.configurationVersion == 0 || a.providerSettings == nil {
		return nil
	}
	body, err := json.Marshal(a.providerSettings)
	if err != nil {
		return ErrEngineSettingsInvalid
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, a.baseURL+"/management/configurations/"+strconv.FormatUint(a.configurationVersion, 10), bytes.NewReader(body))
	if err != nil {
		return ErrProviderSettingsUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return ErrProviderSettingsUnavailable
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return ErrProviderSettingsUnavailable
	}
	return nil
}
