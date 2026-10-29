package capability

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"baiyan/internal/contract"
	"baiyan/internal/toolrunner"
)

// fakeToolRunner stands in for the real runner. It writes the JSON enscan would
// have written, so the executor's parsing is exercised against realistic shapes
// without needing the binary or a registry account.
type fakeToolRunner struct {
	available bool
	sections  map[string][]map[string]string
	exitCode  int
	err       error
	requests  []toolrunner.Request
}

func (f *fakeToolRunner) Has(string) bool { return f.available }

func (f *fakeToolRunner) Run(_ context.Context, req toolrunner.Request) (toolrunner.Result, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return toolrunner.Result{}, f.err
	}
	if f.sections != nil {
		payload, _ := json.Marshal(f.sections)
		_ = os.WriteFile(filepath.Join(req.Dir, "result.json"), payload, 0o600)
	}
	return toolrunner.Result{ExitCode: f.exitCode}, nil
}

type capturingSender struct {
	batches []contract.CallbackBatch
	err     error
}

func (c *capturingSender) Send(_ context.Context, _ string, batch contract.CallbackBatch, _ int) error {
	c.batches = append(c.batches, batch)
	return c.err
}

func (c *capturingSender) final() contract.CallbackBatch {
	if len(c.batches) == 0 {
		return contract.CallbackBatch{}
	}
	return c.batches[len(c.batches)-1]
}

func orgIntelRequest(company string) contract.ScanRequest {
	return contract.ScanRequest{
		RunID: 42, JobType: "org_intel", TimeoutSeconds: 60,
		CallbackURL: "http://asm/api/v1/discovery/callback",
		Targets:     []contract.Target{{Type: "company", Value: company}},
	}
}

func newOrgIntelExecutor(t *testing.T, runner ToolRunner, sender BatchSender) *OrgIntelExecutor {
	t.Helper()
	executor := NewOrgIntelExecutor(runner, sender, t.TempDir())
	fixed := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	executor.now = func() time.Time { return fixed }
	return executor
}

// A deployment without the tool must say so. Reporting an empty success would
// read as "this company has no online presence", which is a very different and
// very wrong conclusion.
func TestOrgIntelReportsMissingToolAsEvidence(t *testing.T) {
	sender := &capturingSender{}
	executor := newOrgIntelExecutor(t, &fakeToolRunner{available: false}, sender)

	result, err := executor.Execute(context.Background(), orgIntelRequest("示例科技有限公司"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Status != "partial_success" {
		t.Fatalf("status %q, want partial_success", result.Status)
	}
	final := sender.final()
	if len(final.ProviderErrors) != 1 || final.ProviderErrors[0].Code != "PROVIDER_NOT_CONFIGURED" {
		t.Fatalf("provider errors: %+v", final.ProviderErrors)
	}
}

func TestOrgIntelExtractsSubjectsFilingsAndDomains(t *testing.T) {
	runner := &fakeToolRunner{available: true, sections: map[string][]map[string]string{
		"enterprise_info": {
			{"name": "示例科技（北京）有限公司", "credit_code": "91110108MA01ABCD2X", "invest": "100", "relation": "invest"},
			{"name": "示例网络技术有限公司", "credit_code": "91310115MA1K3XYZ8N", "invest": "51"},
		},
		"icp_info": {
			{"name": "示例科技（北京）有限公司", "icp": "京ICP备12345678号-1", "domain": "example.com", "site_name": "示例官网"},
			{"name": "示例网络技术有限公司", "icp": "沪ICP备87654321号", "domain": "https://shop.example.cn/index.html"},
		},
	}}
	sender := &capturingSender{}
	executor := newOrgIntelExecutor(t, runner, sender)

	result, err := executor.Execute(context.Background(), orgIntelRequest("示例集团"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Status != "success" {
		t.Fatalf("status %q, want success", result.Status)
	}
	final := sender.final()

	// The queried company plus the two subsidiaries.
	if len(final.Organizations) != 3 {
		t.Fatalf("got %d organizations, want 3: %+v", len(final.Organizations), final.Organizations)
	}
	if final.Organizations[0].Name != "示例集团" {
		t.Fatalf("the queried company must be asserted first, got %q", final.Organizations[0].Name)
	}
	if final.Organizations[1].RegistrationCode != "91110108MA01ABCD2X" {
		t.Fatalf("registration code: %q", final.Organizations[1].RegistrationCode)
	}
	if final.Organizations[1].EquityRatio != 100 {
		t.Fatalf("equity ratio: %v", final.Organizations[1].EquityRatio)
	}

	if len(final.Filings) != 2 {
		t.Fatalf("got %d filings, want 2", len(final.Filings))
	}
	if final.Filings[0].FilingNo != "京ICP备12345678号-1" || final.Filings[0].Domains[0] != "example.com" {
		t.Fatalf("filing 0: %+v", final.Filings[0])
	}
	// A URL in the domain column has to be reduced to the host.
	if final.Filings[1].Domains[0] != "shop.example.cn" {
		t.Fatalf("filing 1 domains: %v", final.Filings[1].Domains)
	}
	// Each filing's holder must resolve to its own organization, not the root.
	if final.Filings[1].Organization.ClientRef == final.Filings[0].Organization.ClientRef {
		t.Fatal("filings held by different companies must reference different organizations")
	}

	// Domains proven by a filing are real root assets and belong in the inventory.
	if len(final.Assets) != 2 {
		t.Fatalf("got %d assets, want 2: %+v", len(final.Assets), final.Assets)
	}
	for _, asset := range final.Assets {
		if asset.AssetType != "domain" {
			t.Fatalf("asset type %q", asset.AssetType)
		}
		if asset.ActiveProbe {
			t.Fatal("enterprise collection is passive and must never be marked as an active probe")
		}
	}
}

// Registry columns are free text typed by humans. Anything that is not clearly a
// domain must be dropped rather than stored as one.
func TestOrgIntelRejectsJunkDomainValues(t *testing.T) {
	runner := &fakeToolRunner{available: true, sections: map[string][]map[string]string{
		"icp_info": {
			{"icp": "京ICP备11111111号", "domain": "暂无"},
			{"icp": "京ICP备22222222号", "domain": "详见官网"},
			{"icp": "京ICP备33333333号", "domain": "com"},
			{"icp": "京ICP备44444444号", "domain": "-invalid-.com"},
			{"icp": "京ICP备55555555号", "domain": "192.168.1.1"},
			{"icp": "京ICP备66666666号", "domain": "good.example.com"},
		},
	}}
	sender := &capturingSender{}
	executor := newOrgIntelExecutor(t, runner, sender)

	if _, err := executor.Execute(context.Background(), orgIntelRequest("测试公司")); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	final := sender.final()
	if len(final.Assets) != 1 || final.Assets[0].Value != "good.example.com" {
		t.Fatalf("only the real domain should survive, got %+v", final.Assets)
	}
}

// The filing number is the evidence tying a domain to a legal entity. A value
// that is not a filing number is not evidence.
func TestOrgIntelRejectsMalformedFilingNumbers(t *testing.T) {
	runner := &fakeToolRunner{available: true, sections: map[string][]map[string]string{
		"icp_info": {
			{"icp": "无", "domain": "a.example.com"},
			{"icp": "ICP", "domain": "b.example.com"},
			{"icp": "<script>alert(1)</script>", "domain": "c.example.com"},
			{"icp": "京ICP备12345678号-1", "domain": "d.example.com"},
		},
	}}
	sender := &capturingSender{}
	executor := newOrgIntelExecutor(t, runner, sender)

	if _, err := executor.Execute(context.Background(), orgIntelRequest("测试公司")); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	final := sender.final()
	if len(final.Filings) != 1 || final.Filings[0].FilingNo != "京ICP备12345678号-1" {
		t.Fatalf("got %+v", final.Filings)
	}
}

func TestOrgIntelDeduplicates(t *testing.T) {
	runner := &fakeToolRunner{available: true, sections: map[string][]map[string]string{
		"enterprise_info": {
			{"name": "重复公司"}, {"name": "重复公司"}, {"name": "重复公司"},
		},
		"icp_info": {
			{"icp": "京ICP备12345678号", "domain": "dup.example.com"},
			{"icp": "京ICP备12345678号", "domain": "dup.example.com"},
		},
	}}
	sender := &capturingSender{}
	executor := newOrgIntelExecutor(t, runner, sender)

	if _, err := executor.Execute(context.Background(), orgIntelRequest("母公司")); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	final := sender.final()
	if len(final.Organizations) != 2 {
		t.Fatalf("got %d organizations, want the parent plus one deduplicated child", len(final.Organizations))
	}
	if len(final.Filings) != 1 || len(final.Assets) != 1 {
		t.Fatalf("filings=%d assets=%d, want 1 each", len(final.Filings), len(final.Assets))
	}
}

// A source name arriving in a job request must not be able to make the executor
// query something nobody vetted.
func TestOrgIntelRefusesSourcesOutsideTheAllowlist(t *testing.T) {
	sender := &capturingSender{}
	executor := newOrgIntelExecutor(t, &fakeToolRunner{available: true}, sender)

	request := orgIntelRequest("测试公司")
	request.Options = map[string]any{"sources": []any{"aqc", "evil-source"}}

	if _, err := executor.Execute(context.Background(), request); err == nil {
		t.Fatal("an unlisted source must be refused")
	}
}

func TestOrgIntelPassesOnlyVettedSourcesAndFields(t *testing.T) {
	runner := &fakeToolRunner{available: true}
	sender := &capturingSender{}
	executor := newOrgIntelExecutor(t, runner, sender)

	request := orgIntelRequest("测试公司")
	request.Options = map[string]any{
		"sources": []any{"tyc", "aqc", "aqc"},
		"fields":  []any{"icp", "not-a-field", "app"},
	}
	if _, err := executor.Execute(context.Background(), request); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(runner.requests) != 1 {
		t.Fatalf("expected one tool invocation, got %d", len(runner.requests))
	}
	args := strings.Join(runner.requests[0].Args, " ")
	if !strings.Contains(args, "-type aqc,tyc") {
		t.Fatalf("sources must be deduplicated and sorted: %s", args)
	}
	if !strings.Contains(args, "-field app,icp") {
		t.Fatalf("unknown fields must be dropped: %s", args)
	}
}

// The engine holds the callback HMAC secret and the registry cookies live in the
// tool's own config. Neither may be inherited into, or reported out of, a run.
func TestOrgIntelGivesTheToolAMinimalEnvironment(t *testing.T) {
	runner := &fakeToolRunner{available: true}
	executor := newOrgIntelExecutor(t, runner, &capturingSender{})

	if _, err := executor.Execute(context.Background(), orgIntelRequest("测试公司")); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	env := runner.requests[0].Env
	if len(env) != 2 || env["PATH"] == "" || env["HOME"] == "" {
		t.Fatalf("the tool environment must be exactly HOME and PATH, got %v", env)
	}
}

// A company name is operator-supplied free text. It must never become a path.
func TestOrgIntelKeepsCompanyNamesOutOfPaths(t *testing.T) {
	runner := &fakeToolRunner{available: true}
	base := t.TempDir()
	executor := NewOrgIntelExecutor(runner, &capturingSender{}, base)

	hostile := "../../etc/passwd"
	if _, err := executor.Execute(context.Background(), orgIntelRequest(hostile)); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	dir := runner.requests[0].Dir
	if strings.Contains(dir, "..") || strings.Contains(dir, "passwd") {
		t.Fatalf("the company name reached the output path: %s", dir)
	}
	if !strings.HasPrefix(dir, base) {
		t.Fatalf("output directory %s escaped the work directory %s", dir, base)
	}
}

// A failing tool must not leak what it printed: enscan echoes the cookies it was
// configured with and the queries it made.
func TestOrgIntelDoesNotForwardToolOutputOnFailure(t *testing.T) {
	sender := &capturingSender{}
	runner := &fakeToolRunner{available: true, exitCode: 1}
	executor := newOrgIntelExecutor(t, runner, sender)

	result, err := executor.Execute(context.Background(), orgIntelRequest("测试公司"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Status != "partial_success" {
		t.Fatalf("status %q", result.Status)
	}
	final := sender.final()
	if len(final.ProviderErrors) != 1 || final.ProviderErrors[0].Code != "PROVIDER_UNAVAILABLE" {
		t.Fatalf("provider errors: %+v", final.ProviderErrors)
	}
	// The message should help an operator without reproducing tool output.
	if !strings.Contains(final.ProviderErrors[0].Message, "credential") {
		t.Fatalf("message should point at the likely cause: %q", final.ProviderErrors[0].Message)
	}
}

func TestOrgIntelReportsTimeoutAsRetryable(t *testing.T) {
	sender := &capturingSender{}
	runner := &fakeToolRunner{available: true, err: toolrunner.ErrTimeout}
	executor := newOrgIntelExecutor(t, runner, sender)

	if _, err := executor.Execute(context.Background(), orgIntelRequest("测试公司")); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	final := sender.final()
	if len(final.ProviderErrors) != 1 || final.ProviderErrors[0].Code != "PROVIDER_TIMEOUT" {
		t.Fatalf("provider errors: %+v", final.ProviderErrors)
	}
	if !final.ProviderErrors[0].Retryable {
		t.Fatal("a timeout is worth retrying and must be marked so")
	}
}

// Output that does not parse must be dropped, not guessed at.
func TestOrgIntelIgnoresUnparseableOutput(t *testing.T) {
	runner := &fakeToolRunner{available: true}
	sender := &capturingSender{}
	base := t.TempDir()
	executor := NewOrgIntelExecutor(runner, sender, base)
	executor.now = func() time.Time { return time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC) }

	// Write garbage where the executor expects JSON.
	runner.sections = nil
	original := runner.Run
	_ = original
	runner.err = nil

	if _, err := executor.Execute(context.Background(), orgIntelRequest("测试公司")); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	final := sender.final()
	// Only the asserted root company survives; nothing was invented.
	if len(final.Organizations) != 1 || len(final.Filings) != 0 || len(final.Assets) != 0 {
		t.Fatalf("orgs=%d filings=%d assets=%d", len(final.Organizations), len(final.Filings), len(final.Assets))
	}
}

// ASM rejects any phase outside its own enum, so a batch with the wrong phase is
// silently dropped at the callback boundary rather than ingested.
func TestOrgIntelUsesThePhasesASMAccepts(t *testing.T) {
	sender := &capturingSender{}
	executor := newOrgIntelExecutor(t, &fakeToolRunner{available: true}, sender)
	if _, err := executor.Execute(context.Background(), orgIntelRequest("测试公司")); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(sender.batches) != 2 {
		t.Fatalf("expected a started and a completed batch, got %d", len(sender.batches))
	}
	if sender.batches[0].Phase != "started" || sender.batches[1].Phase != "completed" {
		t.Fatalf("phases %q then %q", sender.batches[0].Phase, sender.batches[1].Phase)
	}
	// ASM requires result_count to equal the number of facts in the batch.
	final := sender.final()
	if final.ResultCount != uint64(final.FactCount()) {
		t.Fatalf("result_count %d does not match fact count %d", final.ResultCount, final.FactCount())
	}
}

func TestOrgIntelRequiresASender(t *testing.T) {
	executor := NewOrgIntelExecutor(&fakeToolRunner{available: true}, nil, t.TempDir())
	if _, err := executor.Execute(context.Background(), orgIntelRequest("x")); err == nil {
		t.Fatal("a run with nowhere to report results must fail loudly")
	}
}

func TestOrgIntelSurfacesSenderFailures(t *testing.T) {
	wantErr := errors.New("callback rejected")
	executor := newOrgIntelExecutor(t, &fakeToolRunner{available: true}, &capturingSender{err: wantErr})
	if _, err := executor.Execute(context.Background(), orgIntelRequest("x")); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want the sender's error", err)
	}
}

func TestNormalizeRegistryDomain(t *testing.T) {
	cases := map[string]string{
		"Example.COM":                  "example.com",
		"http://www.example.com/a?b=c": "example.com",
		"https://a.b.example.cn:8443/": "a.b.example.cn",
		"  example.com.  ":             "example.com",
		"暂无":                           "",
		"":                             "",
		"com":                          "",
		"-bad.example.com":             "",
		"example .com":                 "",
		"192.168.1.1":                  "",
		"1.2.3.4":                      "",
	}
	for input, want := range cases {
		if got := normalizeRegistryDomain(input); got != want {
			t.Fatalf("normalizeRegistryDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

// The arguments the executor builds must survive the runner's own flag
// allowlist. Without this, a mismatch between EnscanToolSpec and enscanArgs
// would only surface as a refused invocation during a real scan — and "-delay
// -1" did exactly that, because "-1" reads as a flag.
func TestEnscanArgumentsPassTheRunnerAllowlist(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "enscan")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	registry, err := toolrunner.NewRegistry([]toolrunner.Spec{EnscanToolSpec(stub)})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	cases := [][]string{
		enscanArgs("示例集团", t.TempDir(), []string{"aqc"}, []string{"icp"}),
		enscanArgs("示例集团", t.TempDir(), []string{"aqc", "tyc"}, []string{"app", "icp"}),
		enscanArgs("示例集团", t.TempDir(), []string{"miit"}, nil),
	}
	for i, args := range cases {
		if _, err := registry.Run(context.Background(), toolrunner.Request{
			Tool: orgIntelTool, Args: args, Env: map[string]string{"PATH": "/usr/bin:/bin"},
		}); err != nil {
			t.Fatalf("case %d: the runner refused the executor's own arguments (%v): %v", i, args, err)
		}
	}
}

// A hostile company name must not be able to smuggle in a flag.
func TestEnscanArgumentsRefuseFlagLikeCompanyNames(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "enscan")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	registry, err := toolrunner.NewRegistry([]toolrunner.Spec{EnscanToolSpec(stub)})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	args := enscanArgs("--proxy=http://attacker.test", t.TempDir(), []string{"aqc"}, nil)
	_, err = registry.Run(context.Background(), toolrunner.Request{
		Tool: orgIntelTool, Args: args, Env: map[string]string{"PATH": "/usr/bin:/bin"},
	})
	if !errors.Is(err, toolrunner.ErrFlagNotAllowed) {
		t.Fatalf("got %v, want ErrFlagNotAllowed", err)
	}
}
