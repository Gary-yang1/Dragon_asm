# Baiyan Passive Engine

`cmd/baiyan-engine` is the isolated HTTP facade used by ASM. It is deliberately independent from the legacy `cmd/baiyan` CLI and does not import or execute masscan, dirscan, observer_ward, alterx, ESD, AXFR, Subfinder binaries, or any other active scanner.

## Supported Engine Contract v1

- `POST /scan`: `passive_intel` + `options.profile=subdomain_passive`, or `dns` + `options.profile=resolve`.
- `GET /scan/{engine_job_id}`: bounded job status.
- `POST /scan/{engine_job_id}/cancel`: idempotent queued/running cancellation.
- IDs are JSON uint64. `Idempotency-Key` must be the decimal `run_id`.
- Callback batches use monotonic `seq`, at most 500 facts, HMAC-SHA256 over `timestamp + raw_body`, and wait for 2xx before sending the next batch/final callback.
- `rate_limit` is one shared per-job budget for outbound provider and DNS operations started per second; `concurrency` independently caps simultaneous DNS work.
- Scan request bodies are capped at the contract-defined 2 MiB. Requested passive sources that are not configured produce explicit partial-success evidence; DNS output honors the requested A/AAAA/CNAME record types.

All callback URLs must use `BAIYAN_CALLBACK_ALLOWED_ORIGIN`, the fixed `/api/v1/discovery/callback` path, and matching project/run query IDs. Every callback includes `X-Engine-ID` from the required `BAIYAN_ENGINE_ID`; ASM binds that identity to `task_run.callback_secret_ref`. Provider credentials are read only from environment variables; request options accept only contract allowlists.

ASM supports callback key rotation with `DISCOVERY_CALLBACK_SECRETS`, a bounded JSON object mapping engine identities to HMAC secrets. `DISCOVERY_CALLBACK_SECRET_REF` selects the identity snapshotted by new TaskRuns; older non-empty refs remain valid while retained in the map. `DISCOVERY_CALLBACK_LEGACY_SECRET` is optional and applies only to historical rows whose ref is empty. Secrets are never persisted or returned by an API.

## Configuration

```text
BAIYAN_LISTEN_ADDR=:9090
BAIYAN_ENGINE_TOKEN=replace-with-engine-token
BAIYAN_ENGINE_ID=baiyan-primary
BAIYAN_CALLBACK_SECRET=replace-with-shared-hmac-secret
BAIYAN_CALLBACK_ALLOWED_ORIGIN=http://asm-api:8080
BAIYAN_JOB_STORE_DIR=/var/lib/baiyan/jobs
BAIYAN_QUEUE_SIZE=100
BAIYAN_WORKERS=2
BAIYAN_PASSIVE_PROVIDER_NAME=certificate_transparency
BAIYAN_PASSIVE_PROVIDER_URL=http://mock-provider:9191/subdomains
BAIYAN_PASSIVE_PROVIDER_TOKEN=
BAIYAN_PASSIVE_MAX_RESULTS=500
BAIYAN_DNS_PROVIDER_URL=http://mock-provider:9191/dns
BAIYAN_DNS_PROVIDER_TOKEN=
BAIYAN_DNS_MAX_RESULTS=500
```

The provider endpoint returns strict JSON: `{"subdomains":["api.example.com"]}`. It is bounded to 1 MiB and the configured result cap. DNS enrichment uses Go's resolver with per-host timeout and bounded concurrency.

## Crash recovery

Each job is atomically persisted as a mode-0600 JSON record (`fsync` + rename) before queueing. On restart, `queued` and `running` records are reset to `queued` and replayed with the same deterministic `job-{run_id}` identity and request hash. Completed terminal records are never replayed.

Callback delivery is checkpointed in the same record. Before network delivery the immutable batch is stored as `pending_callback`; only a successful 2xx advances `last_callback_seq`. Recovery skips acknowledged sequences and replays an uncertain pending batch from its stored representation, so regenerated timestamps cannot turn a crash retry into an ASM payload conflict. Stale Job Service writes merge the newest callback checkpoint instead of rolling it back.

## Verification

```bash
go test ./internal/contract ./internal/job ./internal/capability ./internal/engine ./cmd/baiyan-engine -race
go vet ./internal/contract ./internal/job ./internal/capability ./internal/engine ./cmd/baiyan-engine
go build ./cmd/baiyan-engine
```

The legacy CLI embeds `lib/` through its historical build script and is outside the passive engine runtime.

## Container security

`Dockerfile.engine` copies only `cmd/baiyan-engine` and the new `internal/{capability,contract,engine,job}` packages into the builder. The runtime image contains one application file (`/app/baiyan-engine`) and does not contain the legacy CLI or bundled active scanners.

The Compose service is opt-in through profile `baiyan` and runs as `10001:10001` with a read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, and a dedicated writable `/var/lib/baiyan/jobs` volume. Missing tokens or callback secrets make the Engine fail closed.

```bash
make test-baiyan-image
docker compose --profile baiyan up baiyan-engine
```
