package safehttp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/safehttp"
)

// The guard runs at dial time, so a loopback destination is refused even though
// the server is genuinely listening and would answer.
func TestClientRefusesLoopbackDestination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := safehttp.NewClient(safehttp.Config{})
	resp, err := client.Get(server.URL) //nolint:bodyclose // the request must not succeed.
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a request to a loopback address must be refused")
	}
	assert.ErrorIs(t, err, safehttp.ErrBlockedAddress)
}

// A hostname that resolves to loopback must be refused too: the check applies to
// the resolved address, which is what closes the DNS-rebinding window.
func TestClientRefusesHostnameResolvingToLoopback(t *testing.T) {
	client := safehttp.NewClient(safehttp.Config{})
	// localhost resolves to 127.0.0.1 / ::1 on every supported platform.
	resp, err := client.Get("http://localhost:1/") //nolint:bodyclose // must not succeed.
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a hostname resolving to loopback must be refused")
	}
	assert.ErrorIs(t, err, safehttp.ErrBlockedAddress)
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	client := safehttp.NewClient(safehttp.Config{})
	// CheckRedirect returns ErrUseLastResponse, so a 3xx surfaces as the response
	// itself rather than being chased to the Location target.
	require.NotNil(t, client.CheckRedirect)
	err := client.CheckRedirect(nil, nil)
	assert.ErrorIs(t, err, http.ErrUseLastResponse)
}

func TestValidateURL(t *testing.T) {
	blocked := []string{
		"http://127.0.0.1/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.1.2.3/hook",
		"http://[::1]/hook",
		"http://localhost/hook",
		"http://runner.internal/hook",
		"http://printer.local/hook",
		"https://user:pass@example.com/hook", // credentials would be stored and echoed back
		"ftp://example.com/hook",
		"file:///etc/passwd",
		"//example.com/hook", // no scheme
	}
	for _, raw := range blocked {
		t.Run("blocked/"+raw, func(t *testing.T) {
			assert.Error(t, safehttp.ValidateURL(raw), "%q must be rejected", raw)
		})
	}

	allowed := []string{
		"https://hooks.example.com/services/abc",
		"http://example.com:8080/notify",
		"https://8.8.8.8/hook",
	}
	for _, raw := range allowed {
		t.Run("allowed/"+raw, func(t *testing.T) {
			assert.NoError(t, safehttp.ValidateURL(raw), "%q must be accepted", raw)
		})
	}
}

func TestReadBoundedCapsBody(t *testing.T) {
	data, err := safehttp.ReadBounded(strings.NewReader(strings.Repeat("a", 100)), 10)
	assert.ErrorIs(t, err, safehttp.ErrResponseTooLarge)
	assert.Len(t, data, 10)

	data, err = safehttp.ReadBounded(strings.NewReader("short"), 10)
	require.NoError(t, err)
	assert.Equal(t, "short", string(data))
}

// The blocked-address error must not be mistaken for a generic transport error
// by callers that branch on it.
func TestBlockedAddressErrorIsDistinguishable(t *testing.T) {
	assert.False(t, errors.Is(safehttp.ErrBlockedAddress, safehttp.ErrBlockedScheme))
}
