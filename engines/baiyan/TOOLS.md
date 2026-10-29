# External tool supply chain

The engine executes third-party binaries for capabilities Go cannot provide on
its own. Those binaries run against customer infrastructure, so where they come
from is a security property, not a packaging detail.

Rules:

1. Every tool is built from a pinned upstream source during the image build.
   Nothing is committed to this repository as a prebuilt binary.
2. Go tools are installed with `go install <module>@<version>`, which verifies
   the module against `sum.golang.org` before compiling. That is the provenance
   check — no separate checksum is needed or useful.
3. Non-Go tools are fetched from a pinned release URL and verified against a
   SHA-256 recorded in this file before they are unpacked or executed.
4. A tool with no reproducible upstream is not shipped. "It works" is not
   provenance.
5. Adding a tool means adding it here, to `Dockerfile.engine`, and to the
   `toolrunner` registration in `cmd/baiyan-engine`, with an explicit flag
   allowlist. A tool the runner does not know about cannot be executed.

## Shipped tools

| Tool | Upstream | Version | How it is obtained | License |
|---|---|---|---|---|
| subfinder | `github.com/projectdiscovery/subfinder/v2` | v2.14.0 | `go install` (sum.golang.org verified) | MIT |
| enscan | `github.com/wgpsec/ENScan_GO` | v2.0.5 (`9969d5156c2fec80d5f4724b8d6d6bbb45471933`) | git clone pinned to that commit, built in the image | MIT |

**Why enscan is pinned by commit rather than `go install`.** Its `go.mod` declares
the module as `github.com/wgpsec/ENScan` while the repository lives at
`github.com/wgpsec/ENScan_GO`. The paths do not match, so the module is not
resolvable through the proxy and `go install ...@v2.0.5` fails with "unknown
revision". A commit SHA is a git object hash and is as strong a pin as a module
checksum; the build additionally asserts that the pinned commit is still what
`v2.0.5` points at, so a moved tag fails the build instead of silently changing
what ships.

**enscan needs operator-supplied credentials.** Every source it queries (爱企查,
天眼查, 快查, 风鸟) is a commercial registry requiring a session cookie or API
token from an account the operator owns, configured in enscan's own config file
under its `HOME`. Without one, `org_intel` runs return `PROVIDER_UNAVAILABLE`
evidence rather than results. Those credentials are never passed through the
engine environment and never appear in callbacks: the runner builds the child
environment explicitly, and tool output is not forwarded into provider errors
because enscan echoes its configuration on failure.

### Operational notes

**subfinder needs a writable `HOME`.** It creates a config directory on first
run, and the engine image has a read-only root filesystem with no home directory
for uid 10001. Registering it without `HOME` pointing somewhere writable makes
every invocation fail with `open /home/baiyan/.config/subfinder/config.yaml: no
such file or directory`. `/tmp` works — the tmpfs is `noexec`, which does not
prevent writing a config file.

Verified on 2026-07-27 against the built image under the full hardening set
(`--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, uid 10001):
`subfinder -version` reports v2.14.0 and a passive lookup returns results.

## Audit of the previously committed binaries (2026-07-27)

`engines/baiyan/lib/` contained four prebuilt executables checked into git. They
were inspected before removal; none of them can be reproduced from source.

| File | SHA-256 (as committed) | What inspection showed |
|---|---|---|
| `lib/subfinder/subfinder` | `70fdbc26982cc20d7b41796cc9fcecf44ae2c43ffba138581b2154816764e348` | Go 1.19 (EOL), built from `(devel)` — no release tag, so no version to pin or audit. |
| `lib/dirscan/dirscan` | `1cea25ea425d4ab462444af29374efbba0f8771425805f34b9de3d5a45c0b702` | Go 1.19, module path `Dirscan` `(devel)`. A local module with no import path and no source anywhere in this repository. **Unattributable.** |
| `lib/ob/observer_ward` | `d9c3899f1ffc01ec77a7755e301a6c780a644a2c60568508c4037723fee8ad54` | Rust, stripped, no recoverable version string. |
| `lib/masscan/masscan` | `4e190c5845bcad9af2eb843d856c8e854853efbce53fea508301a5a467da2f42` | C, stripped, no recoverable version string. Dynamically linked against glibc, so it would not run in the Alpine engine image anyway. |

These are recorded so the removal is auditable, **not** so they can be restored.
A hash of an unattributable binary proves only that it has not changed since
someone unknown built it.

`lib/masscan/masscan-darwin-amd64` was a developer-machine build and never had a
place in a Linux image.

Data files under `lib/` (`dicc.txt`, `subs.esd`, the OneForAll CDN JSON) stay in
git: they are reviewable text. `GeoLite2-ASN.mmdb` also remains for now, but it
is MaxMind-licensed and redistribution is restricted — see the follow-up below.

## Not shipped, and why

**dirscan** — ASM has `dirscan` as a task type and it is gated as an active
capability, but no directory-scanning binary is shipped. The binary that used to
be in `lib/` has no upstream: it is a local Go module called `Dirscan` whose
source is not in this repository. Wiring an unattributable binary into a pipeline
that sends unsolicited requests to customer infrastructure is not something the
platform can stand behind, so the capability stops here pending a decision on
which real, pinned scanner to adopt (ffuf and feroxbuster are both maintained,
released, and installable from a pinned source).

**observer_ward**, **masscan** — deferred to their own phases. masscan
additionally requires `CAP_NET_RAW` and root, which the hardened engine image
deliberately does not have; it needs a separate, isolated image rather than a
relaxation of this one.

## Follow-ups

- `GeoLite2-ASN.mmdb` (6.5 MB) is committed to git under the MaxMind EULA, which
  restricts redistribution. It should be fetched at build time from an account
  the operator controls, not vendored.
- `internal/baiyan/embed.go` declares `//go:embed lib`, but no `lib` directory
  exists beside it, so the legacy `cmd/baiyan` CLI package does not compile. This
  predates the supply-chain work and is why removing `lib/` breaks nothing that
  currently builds.
