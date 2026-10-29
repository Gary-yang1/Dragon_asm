package discovery

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fixture is a real Baiyan site snapshot batch, written by the engine's
// TestSiteSnapshotCallbackMatchesASMContractFixture. Run 20 on the test
// environment failed because this validator rejected the engine's "web" assets
// with 400, which no test on either side exercised.
func TestCallbackAcceptsBaiyanSiteSnapshotBatch(t *testing.T) {
	raw, err := os.ReadFile("testdata/baiyan_site_snapshot_callback.json")
	require.NoError(t, err)

	payload, err := parseCallbackPayload(raw)
	require.NoError(t, err)
	require.Len(t, payload.Assets, 1)
	require.Equal(t, "web", payload.Assets[0].AssetType)
	require.Len(t, payload.Exposures, 1)
	require.Equal(t, "Example Home", payload.Exposures[0].Name)
	require.Equal(t, "web:https://www.example.com:443", payload.Exposures[0].Parent.NaturalKey)
}
