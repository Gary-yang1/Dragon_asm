package notification

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixedNow() time.Time { return time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC) }

// The default sender uses the SSRF-guarded client, which refuses loopback, so
// tests that need a real endpoint inject a plain client. That is exactly the
// behaviour asserted separately in TestWebhookSenderRefusesInternalRecipient.
func testSender() *WebhookSender {
	return NewWebhookSender(
		WithWebhookClient(&http.Client{Timeout: 5 * time.Second}),
		WithWebhookNow(fixedNow),
		// httptest servers listen on loopback, which the real policy refuses; the
		// production behaviour is asserted in TestWebhookSenderRefusesInternalRecipient.
		WithWebhookURLValidator(func(string) error { return nil }),
	)
}

func TestWebhookSenderPostsToEveryRecipient(t *testing.T) {
	var mu sync.Mutex
	var bodies []webhookPayload
	var contentTypes []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload webhookPayload
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		mu.Lock()
		bodies = append(bodies, payload)
		contentTypes = append(contentTypes, r.Header.Get("Content-Type"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := testSender().Send(context.Background(), Message{
		RuleID: 7, ProjectID: 1, Trigger: TriggerNewHighRisk, Channel: ChannelWebhook,
		Recipients: []string{server.URL + "/a", server.URL + "/b"},
		Subject:    "新增高危风险",
		Payload:    json.RawMessage(`{"risk_id":42}`),
	})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, bodies, 2, "every recipient must receive the notification")
	assert.Equal(t, uint64(7), bodies[0].RuleID)
	assert.Equal(t, uint64(1), bodies[0].ProjectID)
	assert.Equal(t, TriggerNewHighRisk, bodies[0].Trigger)
	assert.Equal(t, "新增高危风险", bodies[0].Subject)
	assert.JSONEq(t, `{"risk_id":42}`, string(bodies[0].Payload))
	assert.Equal(t, "application/json", contentTypes[0])
}

// One dead endpoint must not silence the others, and the failure must surface.
func TestWebhookSenderReportsFailureButKeepsDelivering(t *testing.T) {
	var mu sync.Mutex
	delivered := 0
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		delivered++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	err := testSender().Send(context.Background(), Message{
		ProjectID: 1, Trigger: TriggerNewHighRisk, Channel: ChannelWebhook,
		Recipients: []string{bad.URL, good.URL},
	})
	assert.ErrorIs(t, err, ErrDeliveryFailed)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, delivered, "the healthy endpoint must still receive it")
}

// The endpoint can carry a token in its path, so it must not appear in an error
// that gets persisted and shown back to users.
func TestWebhookSenderErrorOmitsTheEndpoint(t *testing.T) {
	sender := NewWebhookSender(
		WithWebhookClient(&http.Client{Timeout: 200 * time.Millisecond}),
		WithWebhookNow(fixedNow),
	)
	// A routable address that will not answer, so the transport errors out.
	err := sender.Send(context.Background(), Message{
		ProjectID: 1, Trigger: TriggerNewHighRisk, Channel: ChannelWebhook,
		Recipients: []string{"https://192.0.2.1/hooks/s3cr3t-token"},
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "s3cr3t-token")
}

// The production sender must refuse an internal recipient even if such a rule
// somehow exists in the database.
func TestWebhookSenderRefusesInternalRecipient(t *testing.T) {
	err := NewWebhookSender(WithWebhookNow(fixedNow)).Send(context.Background(), Message{
		ProjectID: 1, Trigger: TriggerNewHighRisk, Channel: ChannelWebhook,
		Recipients: []string{"http://169.254.169.254/latest/meta-data/"},
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "meta-data", "the blocked target must not be echoed verbatim")
}

// A channel with no transport must fail loudly; reporting success would record a
// delivery that never happened.
func TestChannelRouterFailsForUnconfiguredChannel(t *testing.T) {
	router := NewChannelRouter(map[string]Sender{ChannelWebhook: testSender()})

	err := router.Send(context.Background(), Message{Channel: ChannelEmail, ProjectID: 1})
	assert.ErrorIs(t, err, ErrChannelUnavailable)
}

func TestChannelRouterRoutesToTheRegisteredSender(t *testing.T) {
	var called bool
	router := NewChannelRouter(map[string]Sender{
		ChannelWebhook: senderFunc(func(context.Context, Message) error {
			called = true
			return nil
		}),
	})
	require.NoError(t, router.Send(context.Background(), Message{Channel: ChannelWebhook}))
	assert.True(t, called)
}

type senderFunc func(ctx context.Context, msg Message) error

func (f senderFunc) Send(ctx context.Context, msg Message) error { return f(ctx, msg) }
