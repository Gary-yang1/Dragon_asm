package discovery

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/asset"
	"github.com/Gary-yang1/Dragon_asm/internal/exposure"
)

type fakeAssetImporter struct {
	imports []asset.ImportInput
	err     error
	nextID  uint64
}

func (f *fakeAssetImporter) Import(ctx context.Context, in asset.ImportInput) (*asset.Asset, error) {
	_ = ctx
	if f.err != nil {
		return nil, f.err
	}
	if f.nextID == 0 {
		f.nextID = 1
	}
	id := f.nextID
	f.nextID++
	f.imports = append(f.imports, in)
	return &asset.Asset{ID: id, ProjectID: in.ProjectID, AssetType: in.AssetType, Value: in.Value}, nil
}

type fakeExposureIngester struct {
	inputs []exposure.IngestInput
	err    error
}

type fakeCallbackInbox struct {
	callback *DiscoveryCallback
	err      error
	claimed  bool
	failed   bool
	complete bool
}

type fakeCallbackFactIngester struct {
	callbacks []DiscoveryCallback
	err       error
}

func (f *fakeCallbackFactIngester) IngestCallbackFacts(_ context.Context, callback DiscoveryCallback) error {
	f.callbacks = append(f.callbacks, callback)
	return f.err
}

func (f *fakeCallbackInbox) ClaimDiscoveryCallbackIngest(_ context.Context, projectID, runID, seq uint64) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if f.callback == nil || f.callback.ProjectID != projectID || f.callback.RunID != runID || f.callback.Seq != seq {
		return false, ErrNotFound
	}
	f.claimed = true
	f.callback.IngestStatus = CallbackIngestProcessing
	return true, nil
}

func (f *fakeCallbackInbox) FailDiscoveryCallbackIngest(_ context.Context, _, _, _ uint64) error {
	f.failed = true
	f.callback.IngestStatus = CallbackIngestFailed
	return nil
}

func (f *fakeCallbackInbox) CompleteDiscoveryCallbackIngest(_ context.Context, _, _, _ uint64) (CompleteCallbackIngestResult, error) {
	f.complete = true
	f.callback.IngestStatus = CallbackIngestProcessed
	return CompleteCallbackIngestResult{Processed: true}, nil
}

func (f *fakeCallbackInbox) GetDiscoveryCallback(_ context.Context, projectID, runID, seq uint64) (*DiscoveryCallback, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.callback == nil || f.callback.ProjectID != projectID || f.callback.RunID != runID || f.callback.Seq != seq {
		return nil, ErrNotFound
	}
	cp := *f.callback
	cp.Payload = append([]byte(nil), f.callback.Payload...)
	return &cp, nil
}

func callbackIngestTask(t *testing.T, raw string) (*asynq.Task, *fakeCallbackInbox) {
	t.Helper()
	callback := &DiscoveryCallback{
		TenantID: "t1", OrgID: "o1", ProjectID: 1, RunID: 2, Seq: 3,
		Phase: CallbackPhaseProgress, Payload: []byte(raw), IngestStatus: CallbackIngestPending,
	}
	payload, err := json.Marshal(CallbackTaskPayload{ProjectID: 1, RunID: 2, Seq: 3})
	require.NoError(t, err)
	return asynq.NewTask(TaskTypeIngestScanResult, payload), &fakeCallbackInbox{callback: callback}
}

func (f *fakeExposureIngester) Ingest(ctx context.Context, in exposure.IngestInput) (*exposure.IngestResult, error) {
	_ = ctx
	if f.err != nil {
		return nil, f.err
	}
	f.inputs = append(f.inputs, in)
	return &exposure.IngestResult{Exposure: &exposure.Exposure{ProjectID: in.ProjectID, AssetID: in.AssetID}}, nil
}

func TestIngestHandlerDecodesCallbackPayload(t *testing.T) {
	importer := &fakeAssetImporter{}
	task, inbox := callbackIngestTask(t, `{"run_id":2,"seq":3,"assets":[{"asset_type":"domain","value":"example.com","confidence":90}]}`)

	require.NoError(t, NewIngestHandler(importer, nil).WithCallbackInbox(inbox).Handle(context.Background(), task))
	require.Len(t, importer.imports, 1)
	assert.Equal(t, "t1", importer.imports[0].TenantID)
	assert.Equal(t, "o1", importer.imports[0].OrgID)
	assert.Equal(t, uint64(1), importer.imports[0].ProjectID)
	assert.Equal(t, asset.TypeDomain, importer.imports[0].AssetType)
	assert.Equal(t, "example.com", importer.imports[0].Value)
	assert.Equal(t, "discovery", importer.imports[0].Source)
	assert.Equal(t, uint8(90), importer.imports[0].Confidence)
	assert.Equal(t, "engine", importer.imports[0].ActorID)
}

func TestIngestHandlerUsesTransactionalV1FactIngester(t *testing.T) {
	task, inbox := callbackIngestTask(t, `{"schema_version":"1.0"}`)
	facts := &fakeCallbackFactIngester{}
	handler := NewIngestHandler(nil, nil).WithCallbackInbox(inbox).WithCallbackFactIngester(facts)
	require.NoError(t, handler.Handle(context.Background(), task))
	require.Len(t, facts.callbacks, 1)
	assert.Equal(t, uint64(1), facts.callbacks[0].ProjectID)
	assert.True(t, inbox.claimed)
	assert.True(t, inbox.complete)
	assert.False(t, inbox.failed)
}

func TestIngestHandlerMarksInboxFailedWhenV1TransactionFails(t *testing.T) {
	task, inbox := callbackIngestTask(t, `{"schema_version":"1.0"}`)
	facts := &fakeCallbackFactIngester{err: ErrCallbackFactReference}
	handler := NewIngestHandler(nil, nil).WithCallbackInbox(inbox).WithCallbackFactIngester(facts)
	err := handler.Handle(context.Background(), task)
	assert.ErrorIs(t, err, ErrCallbackFactReference)
	assert.True(t, inbox.failed)
	assert.False(t, inbox.complete)
}

func TestIngestHandlerDecodesExposurePayload(t *testing.T) {
	importer := &fakeAssetImporter{}
	exposures := &fakeExposureIngester{}
	task, inbox := callbackIngestTask(t, `{"run_id":2,"seq":3,"exposures":[{"asset_type":"ip","value":"1.2.3.4","exposure_type":"port","protocol":"tcp","port":443,"confidence":95}]}`)

	require.NoError(t, NewIngestHandler(importer, nil).WithCallbackInbox(inbox).WithExposureIngester(exposures).Handle(context.Background(), task))
	require.Len(t, importer.imports, 1)
	require.Len(t, exposures.inputs, 1)
	assert.Equal(t, asset.TypeIP, importer.imports[0].AssetType)
	assert.Equal(t, exposure.TypePort, exposures.inputs[0].ExposureType)
	assert.Equal(t, uint32(443), exposures.inputs[0].Port)
	assert.Equal(t, uint8(95), exposures.inputs[0].Confidence)
	assert.NotZero(t, exposures.inputs[0].AssetID)
}

func TestIngestHandlerImportsCertificateAsset(t *testing.T) {
	importer := &fakeAssetImporter{}
	exposures := &fakeExposureIngester{}
	task, inbox := callbackIngestTask(t, `{"exposures":[{"asset_type":"domain","value":"www.example.com","exposure_type":"certificate","fingerprint":"abc123","cert_subject":"www.example.com","cert_issuer":"Example CA","cert_serial":"01","cert_not_after":"2026-07-20T00:00:00Z","cert_sans":["www.example.com"]}]}`)

	require.NoError(t, NewIngestHandler(importer, nil).WithCallbackInbox(inbox).WithExposureIngester(exposures).Handle(context.Background(), task))
	require.Len(t, importer.imports, 2)
	assert.Equal(t, asset.TypeDomain, importer.imports[0].AssetType)
	assert.Equal(t, asset.TypeCertificate, importer.imports[1].AssetType)
	assert.Equal(t, "abc123", importer.imports[1].Value)
	require.Len(t, exposures.inputs, 1)
	assert.Equal(t, exposure.TypeCertificate, exposures.inputs[0].ExposureType)
	assert.Equal(t, "www.example.com", exposures.inputs[0].CertSubject)
	assert.Equal(t, "Example CA", exposures.inputs[0].CertIssuer)
	assert.Equal(t, "01", exposures.inputs[0].CertSerial)
	require.Len(t, exposures.inputs[0].CertSANs, 1)
}

func TestIngestHandlerRejectsInvalidPayload(t *testing.T) {
	task := asynq.NewTask(TaskTypeIngestScanResult, []byte(`{bad json}`))
	require.Error(t, NewIngestHandler(nil, nil).Handle(context.Background(), task))
}

func TestIngestHandlerRejectsInvalidAssetPayload(t *testing.T) {
	task, inbox := callbackIngestTask(t, `{"assets":[{"asset_type":"domain"}]}`)
	require.ErrorIs(t, NewIngestHandler(&fakeAssetImporter{}, nil).WithCallbackInbox(inbox).Handle(context.Background(), task), ErrInvalidCallbackPayload)
}

func TestIngestHandlerRejectsInvalidExposurePayload(t *testing.T) {
	task, inbox := callbackIngestTask(t, `{"exposures":[{"asset_type":"ip","value":"1.2.3.4"}]}`)
	require.ErrorIs(t, NewIngestHandler(&fakeAssetImporter{}, nil).WithCallbackInbox(inbox).WithExposureIngester(&fakeExposureIngester{}).Handle(context.Background(), task), ErrInvalidCallbackPayload)
}
