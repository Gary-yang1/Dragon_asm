package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	maxCallbackCredentialEntries = 32
	maxCallbackSecretLength      = 4096
	maxCallbackSecretsJSON       = 64 << 10
)

// CallbackCredentialSet keeps callback HMAC secrets in memory and exposes only
// the active reference used when snapshotting new TaskRuns.
type CallbackCredentialSet struct {
	activeRef    string
	secrets      map[string]string
	legacySecret string
}

// NewCallbackCredentialSet parses an optional identity-to-secret JSON object.
// When encodedSecrets is empty, legacySecret is also used for the active ref to
// preserve the original single-secret configuration.
func NewCallbackCredentialSet(activeRef, legacySecret, encodedSecrets string) (*CallbackCredentialSet, error) {
	activeRef = strings.TrimSpace(activeRef)
	legacySecret = strings.TrimSpace(legacySecret)
	if !validCallbackIdentity(activeRef) {
		return nil, ErrInvalidCallbackIdentity
	}

	secrets := make(map[string]string)
	if strings.TrimSpace(encodedSecrets) == "" {
		if !validCallbackSecret(legacySecret) {
			return nil, ErrInvalidCallbackIdentity
		}
		secrets[activeRef] = legacySecret
	} else {
		var err error
		secrets, err = parseCallbackSecretsJSON(encodedSecrets)
		if err != nil {
			return nil, err
		}
		if _, ok := secrets[activeRef]; !ok {
			return nil, ErrInvalidCallbackIdentity
		}
	}
	if legacySecret != "" && !validCallbackSecret(legacySecret) {
		return nil, ErrInvalidCallbackIdentity
	}
	return &CallbackCredentialSet{activeRef: activeRef, secrets: secrets, legacySecret: legacySecret}, nil
}

// ActiveRef returns the credential identity snapshotted onto newly dispatched runs.
func (c *CallbackCredentialSet) ActiveRef() string {
	if c == nil {
		return ""
	}
	return c.activeRef
}

func (c *CallbackCredentialSet) secretFor(ref string) string {
	if c == nil {
		return ""
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return c.legacySecret
	}
	return c.secrets[ref]
}

func parseCallbackSecretsJSON(raw string) (map[string]string, error) {
	if len(raw) > maxCallbackSecretsJSON {
		return nil, ErrInvalidCallbackIdentity
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, ErrInvalidCallbackIdentity
	}
	secrets := make(map[string]string)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, ErrInvalidCallbackIdentity
		}
		key, ok := keyToken.(string)
		if !ok || !validCallbackIdentity(key) {
			return nil, ErrInvalidCallbackIdentity
		}
		if _, duplicate := secrets[key]; duplicate {
			return nil, ErrInvalidCallbackIdentity
		}
		var secret string
		if err := decoder.Decode(&secret); err != nil {
			return nil, ErrInvalidCallbackIdentity
		}
		secret = strings.TrimSpace(secret)
		if !validCallbackSecret(secret) {
			return nil, ErrInvalidCallbackIdentity
		}
		secrets[key] = secret
		if len(secrets) > maxCallbackCredentialEntries {
			return nil, ErrInvalidCallbackIdentity
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(secrets) == 0 {
		return nil, ErrInvalidCallbackIdentity
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidCallbackIdentity
	}
	return secrets, nil
}

func validCallbackSecret(value string) bool {
	return value != "" && len(value) <= maxCallbackSecretLength
}
