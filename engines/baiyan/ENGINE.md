# Baiyan Engine

`cmd/baiyan-engine` is the isolated HTTP facade used by ASM. It is deliberately independent from the legacy `cmd/baiyan` CLI.

## Capabilities

Job types are dispatched by an explicit router. A job type with no registered executor is refused with a distinct error, so "this engine cannot do that" is never reported as "this scan found nothing". Today the router serves `passive_intel`, `dns` and `org_intel`; all are passive collection.

The engine does not execute masscan, dirscan, observer_ward, alterx, ESD, or AXFR, and performs no active scanning. It is no longer categorically tool-free: the image ships pinned external binaries, and `internal/toolrunner` is the only path by which any of them can be executed. That path enforces a start-up binary allowlist, a per-tool flag allowlist, an explicitly constructed environment (the engine's own environment — including the callback HMAC secret — is never inherited), capped output, a timeout, and process-group cleanup on cancellation. See `TOOLS.md` for what is shipped and where it comes from.

## Supported Engine Contract v1

- `POST /scan`: `passive_intel` + `options.profile=subdomain_passive`, or `dns` + `options.profile=resolve`.
- `GET /scan/{engine_job_id}`: bounded job status.
- `POST /scan/{engine_job_id}/cancel`: idempotent queued/running cancellation.
- `GET /management/status`: authenticated, read-only engine capability and provider configuration summary.
- IDs are JSON uint64. `Idempotency-Key` must be the decimal `run_id`.
- Callback batches use monotonic `seq`, at most 500 facts, HMAC-SHA256 over `timestamp + raw_body`, and wait for 2xx before sending the next batch/final callback.
- `rate_limit` is one shared per-job budget for outbound provider and DNS operations started per second; `concurrency` independently caps simultaneous DNS work.
- Scan request bodies are capped at the contract-defined 2 MiB. Requested passive sources that are not configured produce explicit partial-success evidence; DNS output honors the requested A/AAAA/CNAME record types.

All callback URLs must use `BAIYAN_CALLBACK_ALLOWED_ORIGIN`, the fixed `/api/v1/discovery/callback` path, and matching project/run query IDs. Every callback includes `X-Engine-ID` from the required `BAIYAN_ENGINE_ID`; ASM binds that identity to `task_run.callback_secret_ref`. Provider credentials are read only from environment variables; request options accept only contract allowlists.

ASM supports callback key rotation with `DISCOVERY_CALLBACK_SECRETS`, a bounded JSON object mapping engine identities to HMAC secrets. `DISCOVERY_CALLBACK_SECRET_REF` selects the identity snapshotted by new TaskRuns; older non-empty refs remain valid while retained in the map. `DISCOVERY_CALLBACK_LEGACY_SECRET` is optional and applies only to historical rows whose ref is empty. Secrets are never persisted or returned by an API.

### Management status

`GET /management/status` uses the same `Authorization: Bearer <BAIYAN_ENGINE_TOKEN>` authentication as scan routes. It returns a startup-time snapshot and never starts a scan, reads a job, or calls a Provider. The response shape is:

```json
{
  "status": "ready",
  "engine_id": "baiyan-primary",
  "capabilities": ["dns", "network_enrichment", "org_intel", "passive_intel"],
  "providers": [
    {
      "key": "fofa",
      "name": "FOFA",
      "configured": true,
      "credentials": [
        {"key": "email", "configured": true, "masked_value": "u********r@example.com"},
        {"key": "key", "configured": true, "masked_value": "••••••••1234"}
      ]
    }
  ]
}
```

Email values retain only the first and last local-part characters plus the domain. Secrets of sufficient length retain only the last four characters after a fixed eight-character mask; short secrets are fully masked. Unconfigured credentials use `configured: false` and an empty `masked_value`. The engine never returns the raw engine token, Provider token, key, cookie, callback secret, or any environment-variable value.

## Network enrichment

`POST /enrich/network` uses the same engine Bearer token. It is a stateless,
read-only capability, independent of `/scan`, job storage, ASM and callbacks.
It performs DNS lookups only, without connecting to the supplied websites or IPs.

```json
{
  "schema_version": "1.0",
  "items": [
    {"key": "web-123", "host": "www.example.com", "observed_ips": ["203.0.113.10"], "fingerprints": ["nginx"]}
  ]
}
```

The body is limited to 128 KiB and 1–20 items. Keys are unique, at most 128 bytes;
hostnames are at most 253 bytes. Each item accepts up to 32 existing IPs and 32
fingerprints (128 bytes each). The whole batch is validated before DNS work.
URL syntax, wildcard and single-label names, localhost/local names, unspecified,
loopback, multicast and link-local IPs are rejected. Private unicast IPs remain
valid asset identities. DNS names are queried as absolute names so resolver
search domains are not appended.

The response uses schema `1.0` and retains input order and keys:

```json
{
  "schema_version": "1.0",
  "items": [{
    "key": "web-123",
    "host": "www.example.com",
    "status": "success",
    "resolved_ips": ["203.0.113.20"],
    "cname_chain": ["edge.cloudfront.net"],
    "cdn": {"status": "identified", "provider": "Amazon CloudFront", "evidence": ["DNS canonical name: edge.cloudfront.net"]},
    "cloud": {"status": "identified", "provider": "AWS", "evidence": ["DNS canonical name: edge.cloudfront.net"]},
    "observed_at": "2026-09-16T00:00:00Z",
    "rule_version": "dns-cname-v1"
  }]
}
```

`resolved_ips` contains fresh system-DNS answers only. Existing `observed_ips`
and IP-literal hosts are never relabeled as fresh DNS observations. `cname_chain`
currently contains Go's final canonical name, not all intermediate CNAME hops.
DNS work is globally limited to four targets, three seconds per target and
15 seconds per batch, and respects client cancellation.

`status` is `success` when both lookups succeed (including valid empty answers),
`partial` when one fails and `failed` when both fail. Failures include a bounded
`error_kind`: `dns_timeout`, `dns_not_found`, `dns_error` or `cancelled`.
CDN/cloud no-match remains `unknown`; absence of evidence is not a negative result.
Rules match DNS suffix boundaries. Exact, recognized scanner CDN fingerprints
are accepted as weaker evidence with explicit provenance. Cloud edge attribution
does not identify origin hosting. This version has no ASN or IP range database.
The network-enrichment resolver is independent of the optional HTTP provider
configured for `/scan` DNS jobs; it uses the engine host's system DNS.

Clients can safely retry this read-only endpoint; later retries may observe
changed DNS and carry a new observation timestamp. Enrichment failures should
not undo a completed website scan.

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
FOFA_EMAIL=
FOFA_KEY=
```

The provider endpoint returns strict JSON: `{"subdomains":["api.example.com"]}`. It is bounded to 1 MiB and the configured result cap. DNS enrichment uses Go's resolver with per-host timeout and bounded concurrency.

## Crash recovery

Each job is atomically persisted as a mode-0600 JSON record (`fsync` + rename) before queueing. On restart, `queued` and `running` records are reset to `queued` and replayed with the same deterministic `job-{run_id}` identity and request hash. Completed terminal records are never replayed.

Callback delivery is checkpointed in the same record. Before network delivery the immutable batch is stored as `pending_callback`; only a successful 2xx advances `last_callback_seq`. Recovery skips acknowledged sequences and replays an uncertain pending batch from its stored representation, so regenerated timestamps cannot turn a crash retry into an ASM payload conflict. Stale Job Service writes merge the newest callback checkpoint instead of rolling it back.

## Verification

```bash
go test ./internal/contract ./internal/job ./internal/capability ./internal/networkenrich ./internal/engine ./cmd/baiyan-engine -race
go vet ./internal/contract ./internal/job ./internal/capability ./internal/networkenrich ./internal/engine ./cmd/baiyan-engine
go build ./cmd/baiyan-engine
```

The legacy CLI embeds `lib/` through its historical build script and is outside the passive engine runtime.

## Container security

`Dockerfile.engine` copies only `cmd/baiyan-engine` and the `internal/{capability,contract,engine,job,networkenrich,toolrunner}` packages into the builder. The runtime image contains the engine (`/app/baiyan-engine`) plus the pinned passive tools built from source into `/app/tools/` (root-owned, mode 0555; see `TOOLS.md`). It does not contain the legacy CLI or bundled active scanners.

The Compose service is opt-in through profile `baiyan` and runs as `10001:10001` with a read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, and a dedicated writable `/var/lib/baiyan/jobs` volume. Missing tokens or callback secrets make the Engine fail closed.

```bash
make test-baiyan-image
docker compose --profile baiyan up baiyan-engine
```

### Incremental multi-source discovery

The service entry point now runs Subfinder, FOFA, Quake and Hunter as independent
providers. `sources: ["auto"]` selects the providers available in the immutable
configuration snapshot; an explicit source list remains explicit. Existing
FOFA-only templates do not silently expand. Quake/Hunter credentials and the
Subfinder disable switch are managed through ASM's encrypted configuration API.
The image's `/app/tools/subfinder` is registered by default; subprocesses receive
an isolated temporary HOME and no engine or callback secrets.

Collection has up to four concurrent providers. Subfinder flushes output in
bounded batches (50 lines or 500 ms); paged providers flush each page. All events
pass through one callback sequence writer. DNS runs in bounded batches of at
most 25 hosts after collection, and processes the full accepted host set instead
of silently dropping hosts after 500. NXDOMAIN/no records and transient DNS
errors are distinguished. Completed batches are immediately ingested into ASM.

Callbacks optionally contain `stage_progress` snapshots. The authenticated
`GET /projects/{project_id}/discovery/runs/{run_id}/activity` API returns the
latest source/DNS stages, callback processing counts, distinct materialized
asset counts and up to 20 recent results. It requires discovery-read and
asset-read permission. The task-detail UI polls every four seconds while running.
Older runs expose stored provider errors without inventing missing counters.

Acknowledged callback sequences remain durable. On restart an uncertain callback
is replayed verbatim, then discovery starts a fresh sequence range. Providers may
be queried again; asset observation natural keys deduplicate assets, while the
run's fact-record count can include repeated observations. This is delivery
recovery, not a promise to resume a third-party pagination cursor. ASM waits for
callback ingestion before accepting a successful terminal engine status.

### Wildcard DNS

Before resolving a job's hosts, the engine resolves two random labels under the
immediate parent zone of each host (at most 200 zones per job; probes share the
job's rate budget). A zone is wildcarded only when every probe answers. A host
whose addresses — or, without addresses, aliases — all fall inside its zone's
wildcard answer keeps its asset fact with `attributes.dns_wildcard=suspected`
but gets no `resolves_to`/`cname_to` relations, so names a source merely
remembered do not attach to a shared wildcard IP. A host with any answer of its
own is kept as a normal record. Probe failures leave resolution unfiltered.

### CDN attribution

One rule set, `networkenrich.ClassifyNetwork` (rule version `cdn-rules-v2`),
serves both `/enrich/network` and the passive DNS stage. Evidence is checked
strongest first: curated CNAME suffixes (CDN and cloud), CNAME keywords, edge
address ranges, then an exact scanner fingerprint. No match stays `unknown`.

The keyword and IPv4 range lists are the OneForAll data the Baiyan CLI already
used (`lib/OneForAll/data/cdn_*.json`), embedded from
`internal/networkenrich/rules/`. They are applied more strictly than the CLI's
substring match: dotted keywords need a label boundary, provider words must
begin the registrable label, and generic words (`cdn`, `cache`), DNS-hosting
names (`awsdns`, `dnsv1`), bare short labels and cloud-hosting suffixes
(`amazonaws.com`, `aliyuncs.com`) are not CDN evidence. Cloudflare's published
IPv4/IPv6 ranges are added with a provider name. Upstream OneForAll is GPL-3.0;
confirm the data may be distributed in the engine image before release.

The passive DNS stage records evidence, not decisions. A host keeps aliases that
leave every scope root in `attributes.dns_cname` (in-scope aliases still become
`cname_to` relations). An identified host carries `cdn_status`, `cdn_provider`,
`cdn_evidence` and `attribution_rule_version`; an address carries the same plus
`ip_role=cdn_edge` when its range is listed or the host that resolved to it is
served through an edge by alias. Resolution relations are kept. ASM stores the
identified judgements in `asset_network_attribution` and decides what an edge
means for its inventory, derived targets and active scanning.

### Search-engine website snapshots

FOFA results are requested with `host,domain,ip,port,protocol,title,server`.
Rows crawled over HTTP(S) on a host the job accepted (the scope root or an
in-scope subdomain within the result cap) also produce a `web` asset keyed
`web:<scheme>://<host>:<port>` — the form active probing uses — a `contains`
relation from the host, and a passive `web` exposure carrying the crawled title
as `name`, the server banner as `fingerprint` and `value: "unknown"` because
FOFA reports no status code. Confidence is 70. Nothing is fetched from the site.
ASM shows a live probe of the same URL in preference to a crawl. Quake and
Hunter still contribute hostnames only.

This service integration does not invoke the CLI's combined discovery-and-port-
scan workflow. ESD/zone-transfer, SRV and other active expansion strategies still
need separate capability/authorization wiring before they can be selected here.
