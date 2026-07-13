package capability

import (
	"context"
	"errors"
	"testing"
	"time"

	"baiyan/internal/contract"
	"baiyan/internal/job"
)

type checkpointSenderStub struct {
	err     error
	batches []contract.CallbackBatch
}

func (s *checkpointSenderStub) Send(_ context.Context, _ string, batch contract.CallbackBatch, _ int) error {
	s.batches = append(s.batches, batch)
	return s.err
}

func TestCheckpointedBatchSenderReplaysPendingAndSkipsAcknowledged(t *testing.T) {
	store, err := job.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(job.Record{
		JobID: "job-7", Request: contract.ScanRequest{RunID: 7}, Status: job.StatusRunning,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	staleRecord, err := store.Get("job-7")
	if err != nil {
		t.Fatal(err)
	}
	original := contract.CallbackBatch{
		SchemaVersion: contract.SchemaVersion, RunID: 7, Seq: 1, Phase: "started", Status: "running",
		ObservedAt: time.Unix(100, 0).UTC(), Assets: []contract.AssetFact{}, Relations: []contract.RelationFact{},
		Exposures: []contract.ExposureFact{}, ProviderErrors: []contract.ProviderError{}, ErrorSummary: "",
	}
	failed := &checkpointSenderStub{err: errors.New("response lost")}
	first, err := NewCheckpointedBatchSender(store, failed)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Send(context.Background(), "https://asm.invalid/callback", original, 0); err == nil {
		t.Fatal("expected injected delivery failure")
	}
	if err := store.Save(staleRecord); err != nil {
		t.Fatal(err)
	}

	regenerated := original
	regenerated.ObservedAt = time.Unix(200, 0).UTC()
	replayed := &checkpointSenderStub{}
	second, err := NewCheckpointedBatchSender(store, replayed)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Send(context.Background(), "https://asm.invalid/callback", regenerated, 0); err != nil {
		t.Fatal(err)
	}
	if len(replayed.batches) != 1 || !replayed.batches[0].ObservedAt.Equal(original.ObservedAt) {
		t.Fatalf("pending callback was not replayed immutably: %+v", replayed.batches)
	}
	if err := second.Send(context.Background(), "https://asm.invalid/callback", regenerated, 0); err != nil {
		t.Fatal(err)
	}
	if len(replayed.batches) != 1 {
		t.Fatalf("acknowledged callback was sent again: %d sends", len(replayed.batches))
	}
	if err := store.Save(staleRecord); err != nil {
		t.Fatal(err)
	}
	record, err := store.Get("job-7")
	if err != nil {
		t.Fatal(err)
	}
	if record.LastCallbackSeq != 1 || record.PendingCallback != nil {
		t.Fatalf("unexpected checkpoint state: %+v", record)
	}
}
