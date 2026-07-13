package discovery

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCallbackCredentialSetSingleSecretCompatibility(t *testing.T) {
	credentials, err := NewCallbackCredentialSet("baiyan-primary", "single-secret", "")
	require.NoError(t, err)
	assert.Equal(t, "baiyan-primary", credentials.ActiveRef())
	assert.Equal(t, "single-secret", credentials.secretFor("baiyan-primary"))
	assert.Equal(t, "single-secret", credentials.secretFor(""))
	assert.Empty(t, credentials.secretFor("unknown"))
}

func TestCallbackCredentialSetSupportsRotation(t *testing.T) {
	credentials, err := NewCallbackCredentialSet(
		"baiyan-new", "legacy-secret",
		`{"baiyan-old":"old-secret","baiyan-new":"new-secret"}`,
	)
	require.NoError(t, err)
	assert.Equal(t, "baiyan-new", credentials.ActiveRef())
	assert.Equal(t, "old-secret", credentials.secretFor("baiyan-old"))
	assert.Equal(t, "new-secret", credentials.secretFor("baiyan-new"))
	assert.Equal(t, "legacy-secret", credentials.secretFor(""))
}

func TestCallbackCredentialSetRejectsUnsafeConfiguration(t *testing.T) {
	tooMany := make(map[string]string)
	for i := 0; i <= maxCallbackCredentialEntries; i++ {
		tooMany[fmt.Sprintf("engine-%d", i)] = "secret"
	}
	tooManyJSON, err := json.Marshal(tooMany)
	require.NoError(t, err)

	tests := []struct {
		name    string
		active  string
		legacy  string
		encoded string
	}{
		{name: "missing active ref", legacy: "secret"},
		{name: "active missing from map", active: "new", encoded: `{"old":"secret"}`},
		{name: "duplicate identity", active: "same", encoded: `{"same":"one","same":"two"}`},
		{name: "invalid identity", active: "bad identity", legacy: "secret"},
		{name: "non string secret", active: "engine", encoded: `{"engine":1}`},
		{name: "empty secret", active: "engine", encoded: `{"engine":""}`},
		{name: "too many identities", active: "engine-0", encoded: string(tooManyJSON)},
		{name: "trailing JSON", active: "engine", encoded: `{"engine":"secret"}{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCallbackCredentialSet(tt.active, tt.legacy, tt.encoded)
			assert.ErrorIs(t, err, ErrInvalidCallbackIdentity)
		})
	}
}
