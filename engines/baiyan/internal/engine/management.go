package engine

import (
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	managementStatusReady = "ready"
	fixedEmailMask        = "********"
	fixedSecretMask       = "••••••••"

	maxManagementCapabilities = 64
	maxManagementProviders    = 32
	maxProviderCredentials    = 16
)

// CredentialKind selects the masking policy used before a credential can be
// retained by the management status snapshot.
type CredentialKind string

const (
	CredentialKindEmail  CredentialKind = "email"
	CredentialKindSecret CredentialKind = "secret"
)

// ManagementCredentialConfig is write-only input for building the status
// snapshot. Value is deliberately excluded from JSON so the raw credential
// cannot be serialized accidentally.
type ManagementCredentialConfig struct {
	Key   string         `json:"-"`
	Kind  CredentialKind `json:"-"`
	Value string         `json:"-"`
}

// ManagementProviderConfig describes a provider without performing a health
// check. Configured reflects local startup configuration only.
type ManagementProviderConfig struct {
	Key         string                       `json:"-"`
	Name        string                       `json:"-"`
	Configured  bool                         `json:"-"`
	Credentials []ManagementCredentialConfig `json:"-"`
}

// ManagementConfig is converted to an immutable, already-masked response when
// the HTTP handler starts. No raw credential is retained in the Handler.
type ManagementConfig struct {
	EngineID     string                     `json:"-"`
	Capabilities []string                   `json:"-"`
	Providers    []ManagementProviderConfig `json:"-"`
}

type managementCredential struct {
	Key         string `json:"key"`
	Configured  bool   `json:"configured"`
	MaskedValue string `json:"masked_value"`
}

type managementProvider struct {
	Key         string                 `json:"key"`
	Name        string                 `json:"name"`
	Configured  bool                   `json:"configured"`
	Credentials []managementCredential `json:"credentials"`
}

type managementStatus struct {
	Status       string               `json:"status"`
	EngineID     string               `json:"engine_id"`
	Capabilities []string             `json:"capabilities"`
	Providers    []managementProvider `json:"providers"`
}

func buildManagementStatus(config ManagementConfig) (managementStatus, error) {
	engineID := strings.TrimSpace(config.EngineID)
	if !validEngineIdentity(engineID) {
		return managementStatus{}, errors.New("baiyan management: engine identity is invalid")
	}
	if len(config.Capabilities) > maxManagementCapabilities || len(config.Providers) > maxManagementProviders {
		return managementStatus{}, errors.New("baiyan management: status configuration exceeds limits")
	}

	capabilities := make([]string, 0, len(config.Capabilities))
	seenCapabilities := make(map[string]struct{}, len(config.Capabilities))
	for _, capability := range config.Capabilities {
		capability = strings.ToLower(strings.TrimSpace(capability))
		if !validManagementLabel(capability) {
			return managementStatus{}, errors.New("baiyan management: capability is invalid")
		}
		if _, duplicate := seenCapabilities[capability]; duplicate {
			continue
		}
		seenCapabilities[capability] = struct{}{}
		capabilities = append(capabilities, capability)
	}
	sort.Strings(capabilities)

	providers := make([]managementProvider, 0, len(config.Providers))
	seenProviders := make(map[string]struct{}, len(config.Providers))
	for _, providerConfig := range config.Providers {
		providerKey := strings.ToLower(strings.TrimSpace(providerConfig.Key))
		providerName := strings.TrimSpace(providerConfig.Name)
		if !validManagementLabel(providerKey) || providerName == "" || utf8.RuneCountInString(providerName) > 64 || containsControl(providerName) {
			return managementStatus{}, errors.New("baiyan management: provider is invalid")
		}
		if _, duplicate := seenProviders[providerKey]; duplicate {
			return managementStatus{}, errors.New("baiyan management: provider is configured twice")
		}
		seenProviders[providerKey] = struct{}{}
		if len(providerConfig.Credentials) > maxProviderCredentials {
			return managementStatus{}, errors.New("baiyan management: provider credentials exceed limits")
		}

		credentials := make([]managementCredential, 0, len(providerConfig.Credentials))
		seenCredentials := make(map[string]struct{}, len(providerConfig.Credentials))
		for _, credentialConfig := range providerConfig.Credentials {
			credentialKey := strings.ToLower(strings.TrimSpace(credentialConfig.Key))
			if !validManagementLabel(credentialKey) {
				return managementStatus{}, errors.New("baiyan management: credential key is invalid")
			}
			if _, duplicate := seenCredentials[credentialKey]; duplicate {
				return managementStatus{}, errors.New("baiyan management: credential is configured twice")
			}
			seenCredentials[credentialKey] = struct{}{}
			credentials = append(credentials, maskManagementCredential(credentialKey, credentialConfig.Kind, credentialConfig.Value))
		}
		sort.Slice(credentials, func(i, j int) bool { return credentials[i].Key < credentials[j].Key })
		providers = append(providers, managementProvider{
			Key: providerKey, Name: providerName, Configured: providerConfig.Configured, Credentials: credentials,
		})
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Key < providers[j].Key })

	return managementStatus{
		Status: managementStatusReady, EngineID: engineID, Capabilities: capabilities, Providers: providers,
	}, nil
}

func maskManagementCredential(key string, kind CredentialKind, raw string) managementCredential {
	value := strings.TrimSpace(raw)
	credential := managementCredential{Key: key, Configured: value != ""}
	if !credential.Configured {
		return credential
	}
	switch kind {
	case CredentialKindEmail:
		credential.MaskedValue = maskEmail(value)
	default:
		credential.MaskedValue = maskSecret(value)
	}
	return credential
}

func maskSecret(value string) string {
	runes := []rune(value)
	if len(runes) < 8 {
		return fixedSecretMask
	}
	suffix := runes[len(runes)-4:]
	for _, char := range suffix {
		if unicode.IsControl(char) || unicode.IsSpace(char) || !unicode.IsPrint(char) {
			return fixedSecretMask
		}
	}
	return fixedSecretMask + string(suffix)
}

func maskEmail(value string) string {
	if len(value) > 320 || containsControl(value) {
		return fixedEmailMask
	}
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return fixedEmailMask
	}
	local := []rune(value[:at])
	domain := strings.ToLower(value[at+1:])
	if len(local) < 2 || len(local) > 64 || !validEmailDomain(domain) {
		return fixedEmailMask
	}
	return string(local[0]) + fixedEmailMask + string(local[len(local)-1]) + "@" + domain
}

func validEmailDomain(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func validManagementLabel(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.' || char == ':' {
			continue
		}
		return false
	}
	return true
}

func containsControl(value string) bool {
	for _, char := range value {
		if unicode.IsControl(char) {
			return true
		}
	}
	return false
}
