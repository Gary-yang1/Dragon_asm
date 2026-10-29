package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/safehttp"
)

var (
	// ErrChannelUnavailable marks a channel that has no configured transport, so
	// an unsent notification is visible instead of silently succeeding.
	ErrChannelUnavailable = errors.New("notification: channel has no configured sender")
	// ErrDeliveryFailed wraps a non-2xx or transport-level webhook failure.
	ErrDeliveryFailed = errors.New("notification: delivery failed")
)

// webhookPayload is the JSON posted to a webhook endpoint. It carries
// identifiers and the triggering payload — never recipients or platform config.
type webhookPayload struct {
	RuleID    uint64          `json:"rule_id"`
	ProjectID uint64          `json:"project_id"`
	Trigger   string          `json:"trigger"`
	Subject   string          `json:"subject"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	SentAt    string          `json:"sent_at"`
}

// WebhookSender delivers notifications by POSTing to each recipient URL.
//
// The recipients are operator-supplied URLs, so every request goes through the
// SSRF-guarded client in platform/safehttp: internal addresses are refused at
// dial time, redirects are not followed, and both time and response size are
// bounded.
type WebhookSender struct {
	client *http.Client
	now    func() time.Time
	// maxResponse bounds how much of a reply is read before it is discarded.
	maxResponse int64
	// validateURL is defence in depth on top of the dial-time guard, and the seam
	// tests use to reach a local endpoint deliberately.
	validateURL func(string) error
}

// WebhookOption configures a WebhookSender.
type WebhookOption func(*WebhookSender)

// WithWebhookClient injects a client, for tests that must reach a local server.
func WithWebhookClient(client *http.Client) WebhookOption {
	return func(s *WebhookSender) {
		if client != nil {
			s.client = client
		}
	}
}

// WithWebhookURLValidator overrides the pre-send URL policy.
//
// Only tests should relax this, and only together with an unguarded client: the
// dial-time check in platform/safehttp is what actually stops an internal
// request, and it stays in force regardless of what is passed here.
func WithWebhookURLValidator(validate func(string) error) WebhookOption {
	return func(s *WebhookSender) {
		if validate != nil {
			s.validateURL = validate
		}
	}
}

// WithWebhookNow overrides the clock for deterministic tests.
func WithWebhookNow(now func() time.Time) WebhookOption {
	return func(s *WebhookSender) {
		if now != nil {
			s.now = now
		}
	}
}

// NewWebhookSender builds a sender with the guarded client.
func NewWebhookSender(opts ...WebhookOption) *WebhookSender {
	s := &WebhookSender{
		client:      safehttp.NewClient(safehttp.Config{}),
		now:         func() time.Time { return time.Now().UTC() },
		maxResponse: safehttp.DefaultMaxResponse,
		validateURL: safehttp.ValidateURL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Send posts the message to every recipient. It reports the first failure but
// still attempts the remaining recipients, so one dead endpoint does not silence
// the others.
func (s *WebhookSender) Send(ctx context.Context, msg Message) error {
	if msg.Channel != ChannelWebhook {
		return fmt.Errorf("%w: %s", ErrChannelUnavailable, msg.Channel)
	}
	body, err := json.Marshal(webhookPayload{
		RuleID:    msg.RuleID,
		ProjectID: msg.ProjectID,
		Trigger:   msg.Trigger,
		Subject:   msg.Subject,
		Payload:   msg.Payload,
		SentAt:    s.now().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}

	var failures []error
	for _, recipient := range msg.Recipients {
		if err := s.post(ctx, recipient, body); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (s *WebhookSender) post(ctx context.Context, endpoint string, body []byte) error {
	// Re-validate at send time: a rule stored before the guard existed, or edited
	// directly in the database, must not become an outbound request.
	if err := s.validateURL(endpoint); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ASM-Notification/1")

	resp, err := s.client.Do(req)
	if err != nil {
		// The URL is deliberately omitted: it can embed a token in its path, and
		// this error is persisted and surfaced.
		return fmt.Errorf("%w: transport error", ErrDeliveryFailed)
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain a bounded amount so the connection can be reused, and discard it —
	// the receiver's body is untrusted content with no use here.
	_, _ = safehttp.ReadBounded(resp.Body, s.maxResponse)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: status=%s", ErrDeliveryFailed, strconv.Itoa(resp.StatusCode))
	}
	return nil
}

// ChannelRouter dispatches to the sender registered for a message's channel.
// A channel with no sender fails loudly rather than reporting a delivery that
// never happened.
type ChannelRouter struct {
	senders map[string]Sender
}

// NewChannelRouter builds a router from channel to sender.
func NewChannelRouter(senders map[string]Sender) *ChannelRouter {
	copied := make(map[string]Sender, len(senders))
	for channel, sender := range senders {
		if sender != nil {
			copied[channel] = sender
		}
	}
	return &ChannelRouter{senders: copied}
}

// Send routes by channel.
func (r *ChannelRouter) Send(ctx context.Context, msg Message) error {
	sender, ok := r.senders[msg.Channel]
	if !ok {
		return fmt.Errorf("%w: %s", ErrChannelUnavailable, msg.Channel)
	}
	return sender.Send(ctx, msg)
}
