package engine

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"baiyan/internal/contract"
)

func TestCallbackSenderRetriesImmutableBodyAndSigns(t *testing.T) {
	var (
		mu         sync.Mutex
		bodies     []string
		signatures []string
		sequences  []string
		engineIDs  []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		signatures = append(signatures, r.Header.Get("X-Signature"))
		sequences = append(sequences, r.URL.Query().Get("seq"))
		engineIDs = append(engineIDs, r.Header.Get("X-Engine-ID"))
		attempt := len(bodies)
		mu.Unlock()
		timestamp := r.Header.Get("X-Timestamp")
		mac := hmac.New(sha256.New, []byte("callback-secret"))
		_, _ = mac.Write([]byte(timestamp))
		_, _ = mac.Write(raw)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(want), []byte(r.Header.Get("X-Signature"))) {
			t.Errorf("invalid callback HMAC")
		}
		if attempt == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	sender, err := NewIdentityBoundCallbackSender("callback-secret", "baiyan-primary", server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	sender.now = func() time.Time { return time.Unix(1783900000, 0).UTC() }
	batch := contract.CallbackBatch{
		SchemaVersion: contract.SchemaVersion, RunID: 1, Seq: 3, Phase: "progress", Status: "running",
		ObservedAt: time.Now().UTC(), Assets: []contract.AssetFact{}, Relations: []contract.RelationFact{},
		Exposures: []contract.ExposureFact{}, ProviderErrors: []contract.ProviderError{}, ErrorSummary: "",
	}
	if err := sender.Send(context.Background(), server.URL+"/api/v1/discovery/callback?project_id=1&run_id=1", batch, 1); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || bodies[0] != bodies[1] || sequences[0] != "3" || sequences[1] != "3" ||
		engineIDs[0] != "baiyan-primary" || engineIDs[1] != "baiyan-primary" {
		t.Fatalf("retry mutated body/seq: bodies=%v seq=%v", bodies, sequences)
	}
	for _, signature := range signatures {
		if !strings.HasPrefix(signature, "sha256=") {
			t.Fatalf("unexpected signature format: %s", signature)
		}
	}
}

func TestIdentityBoundCallbackSenderRejectsInvalidIdentity(t *testing.T) {
	for _, identity := range []string{"bad identity", ".hidden"} {
		_, err := NewIdentityBoundCallbackSender("secret", identity, "https://asm.example.com", nil)
		if err == nil {
			t.Fatalf("expected invalid engine identity rejection: %q", identity)
		}
	}
}

func TestCallbackSenderRejectsUntrustedOrigin(t *testing.T) {
	sender, err := NewCallbackSender("secret", "https://asm.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = sender.Send(context.Background(), "https://evil.invalid/api/v1/discovery/callback", contract.CallbackBatch{Seq: 1}, 0)
	if err == nil {
		t.Fatal("expected untrusted callback origin rejection")
	}
}

func TestCallbackSenderDoesNotFollowRedirects(t *testing.T) {
	var redirected bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		if r.Header.Get("X-Signature") != "" || r.Header.Get("X-Timestamp") != "" {
			t.Error("callback credentials reached redirect destination")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	sender, err := NewCallbackSender("callback-secret", source.URL, source.Client())
	if err != nil {
		t.Fatal(err)
	}
	err = sender.Send(context.Background(), source.URL+"/api/v1/discovery/callback?project_id=1&run_id=1", contract.CallbackBatch{
		SchemaVersion: contract.SchemaVersion, RunID: 1, Seq: 1, Phase: "started", Status: "running",
		ObservedAt: time.Now().UTC(), Assets: []contract.AssetFact{}, Relations: []contract.RelationFact{},
		Exposures: []contract.ExposureFact{}, ProviderErrors: []contract.ProviderError{}, ErrorSummary: "",
	}, 0)
	if err == nil {
		t.Fatal("expected redirect response to fail callback delivery")
	}
	if redirected {
		t.Fatal("callback sender followed redirect")
	}
}
