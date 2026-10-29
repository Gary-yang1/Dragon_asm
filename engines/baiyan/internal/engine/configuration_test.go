package engine

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func providerFixture() ProviderConfiguration {
	return ProviderConfiguration{FOFAEnabled: true, FOFAEmail: "test@example.invalid", FOFAKey: "secret-before", FOFAMaxResults: 1000, PassiveName: "certificate_transparency", PassiveMaxResults: 500, DNSMaxResults: 500}
}
func TestConfigurationVersionsEncryptedImmutableAndSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	baseline := providerFixture()
	m, err := NewConfigurationManager(dir, baseline, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Save(7, baseline); err != nil {
		t.Fatal(err)
	}
	next := baseline
	next.FOFAKey = "secret-after"
	if err = m.Save(8, next); err != nil {
		t.Fatal(err)
	}
	if err = m.Save(7, next); err == nil {
		t.Fatal("version overwritten")
	}
	raw, err := os.ReadFile(m.filename(7))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(baseline.FOFAKey)) {
		t.Fatal("plaintext persisted")
	}
	restored, err := NewConfigurationManager(dir, next, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	old, err := restored.Load(7)
	if err != nil || old.FOFAKey != baseline.FOFAKey {
		t.Fatal("old configuration lost")
	}
	original, err := restored.Load(0)
	if err != nil || original.FOFAKey != baseline.FOFAKey {
		t.Fatal("legacy baseline overwritten")
	}
	latest, err := restored.Current()
	if err != nil || latest.FOFAKey != next.FOFAKey {
		t.Fatal("latest configuration lost")
	}
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(m.filename(7), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Load(7); err == nil {
		t.Fatal("corruption accepted")
	}
}
func TestConfigurationServiceAuthenticationAndPublicMasking(t *testing.T) {
	m, err := NewConfigurationManager(t.TempDir(), providerFixture(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := managementTestHandler(t).WithConfigurations(m)
	body, _ := json.Marshal(providerFixture())
	req := httptest.NewRequest(http.MethodPut, "/management/configurations/1", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	req = httptest.NewRequest(http.MethodPut, "/management/configurations/1", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer engine-token")
	w = httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/management/status", nil)
	req.Header.Set("Authorization", "Bearer engine-token")
	w = httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)
	if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte(providerFixture().FOFAKey)) {
		t.Fatal("status exposed plaintext")
	}
	req = httptest.NewRequest(http.MethodGet, "/management/configuration", nil)
	w = httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("unauthenticated export")
	}
}
func TestManagedProvidersRejectMetadata(t *testing.T) {
	for _, raw := range []string{"http://169.254.169.254", "http://100.100.100.200", "http://[fd00:ec2::254]", "http://127.0.0.1", "https://user:secret@example.test"} {
		if validProviderURL(raw) {
			t.Fatal("accepted dangerous endpoint", raw)
		}
	}
}

func TestScanRequiresProvisionedConfigurationVersion(t *testing.T) {
	m, err := NewConfigurationManager(t.TempDir(), providerFixture(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	jobs := &fakeJobs{}
	h, err := NewHandler(jobs, "engine-token", "https://asm.example.com")
	if err != nil {
		t.Fatal(err)
	}
	h.WithConfigurations(m)
	payload := validHTTPScanRequest()
	payload["configuration_version"] = uint64(12)
	body, _ := json.Marshal(payload)
	call := func() int {
		r := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer engine-token")
		r.Header.Set("Idempotency-Key", "7")
		w := httptest.NewRecorder()
		h.Routes().ServeHTTP(w, r)
		return w.Code
	}
	if call() != 422 {
		t.Fatal("unprovisioned version accepted")
	}
	if err = m.Save(12, providerFixture()); err != nil {
		t.Fatal(err)
	}
	if call() != 202 || jobs.request.ConfigurationVersion != 12 {
		t.Fatal("job did not retain its configuration version")
	}
}

func TestManagementIncludesConfiguredDiscoverySourcesWithoutSecrets(t *testing.T) {
	c := providerFixture()
	c.QuakeEnabled = true
	c.QuakeKey = "quake-private-credential"
	c.HunterEnabled = true
	c.HunterKey = "hunter-private-credential"
	m, err := NewConfigurationManager(t.TempDir(), c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := managementTestHandler(t).WithConfigurations(m)
	req := httptest.NewRequest(http.MethodGet, "/management/status", nil)
	req.Header.Set("Authorization", "Bearer engine-token")
	w := httptest.NewRecorder()
	h.Routes().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, key := range []string{c.QuakeKey, c.HunterKey, c.FOFAKey} {
		if bytes.Contains(w.Body.Bytes(), []byte(key)) {
			t.Fatal("credential leaked")
		}
	}
	var status managementStatus
	if err = json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, p := range status.Providers {
		found[p.Key] = p.Configured
	}
	if !found["quake"] || !found["hunter"] || !found["fofa"] || found["subfinder"] {
		t.Fatalf("wrong configured flags: %+v", found)
	}
}
