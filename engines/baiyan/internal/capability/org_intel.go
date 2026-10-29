package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"baiyan/internal/contract"
	"baiyan/internal/job"
	"baiyan/internal/toolrunner"
)

// Enterprise intelligence collection.
//
// In China the discovery chain starts at a company name, not a domain: the
// registry gives subsidiaries and branches, those give ICP filings, and filings
// give the root domains everything else hangs off. Nothing about this is active
// — every request goes to a third-party dataset, never to the customer.
//
// The collection itself is done by enscan, which is executed through toolrunner
// under the constraints described there. This file is the boundary: it decides
// what enscan may be asked, and it refuses to trust anything it gets back.

const (
	// orgIntelTool is the toolrunner name the enscan binary is registered under.
	orgIntelTool = "enscan"
	// maxOrgResults bounds one run regardless of how large a corporate group is.
	// A conglomerate can have thousands of entities and the callback protocol
	// caps a batch at 500 facts.
	maxOrgResults = 300
	// maxFilingsPerOrg bounds filings attributed to a single entity.
	maxFilingsPerOrg = 200
	// maxDomainsPerFiling bounds domains under one filing number.
	maxDomainsPerFiling = 50
	// orgIntelOutputDirMode keeps the per-run output directory private to the
	// engine user; enscan writes result files there.
	orgIntelOutputDirMode = 0o700
)

// enscanSources are the data sources this executor is willing to ask for.
//
// Each needs a credential the operator supplies, and each is a commercial
// registry with its own terms of use. The allowlist exists so a job request
// cannot name an arbitrary source string, and so adding one is a deliberate act.
var enscanSources = map[string]bool{
	"aqc":    true, // 爱企查
	"tyc":    true, // 天眼查
	"kc":     true, // 快查
	"rb":     true, // 风鸟
	"tycapi": true, // 天眼查 official API
	"miit":   true, // ICP filing lookup plugin
}

// filingNoPattern matches an ICP filing number. Anything that does not look like
// one is dropped rather than stored: the filing number is the evidence, and a
// malformed one is worse than none.
var filingNoPattern = regexp.MustCompile(`^[\p{Han}A-Za-z]{1,10}ICP(备|证)?[0-9]{5,12}号(-[0-9]{1,4})?$`)

// domainPattern is deliberately conservative. Registry data is free text typed
// by humans, so a "domain" field routinely contains a URL, a sentence, or a
// company name.
var domainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// EnscanToolSpec is how enscan must be registered with the runner.
//
// It lives here rather than in the engine's wiring so the flag allowlist and the
// code that builds the arguments cannot drift apart — a mismatch would only show
// up as a refused invocation at scan time.
func EnscanToolSpec(path string) toolrunner.Spec {
	return toolrunner.Spec{
		Name: orgIntelTool,
		Path: path,
		AllowedFlags: []string{
			"-n",       // keyword (company name)
			"-type",    // data sources
			"-field",   // field groups
			"-json",    // JSON output
			"-out-dir", // output directory
			"-delay",   // per-request delay
			"-is-show", // suppress interactive output
		},
	}
}

// enscanArgs builds one invocation. Values that can begin with a dash use the
// "-flag=value" form: passed as two arguments, "-1" would itself look like a
// flag and be refused by the runner's allowlist.
func enscanArgs(company, outDir string, sources, fields []string) []string {
	args := []string{
		"-n", company,
		"-type", strings.Join(sources, ","),
		"-json",
		"-out-dir", outDir,
		// Registries throttle aggressively and flag accounts that do not pause.
		// -1 asks enscan for a random 1-5s gap between requests.
		"-delay=-1",
		"-is-show=false",
	}
	if len(fields) > 0 {
		args = append(args, "-field", strings.Join(fields, ","))
	}
	return args
}

// ToolRunner is the subset of toolrunner the executor needs, so tests do not
// have to produce a real binary.
type ToolRunner interface {
	Run(ctx context.Context, req toolrunner.Request) (toolrunner.Result, error)
	Has(name string) bool
}

// OrgIntelExecutor collects enterprise information for a company name.
type OrgIntelExecutor struct {
	runner  ToolRunner
	sender  BatchSender
	workDir string
	now     func() time.Time
}

// NewOrgIntelExecutor builds the executor. A nil runner is allowed: the engine
// then reports the capability as unconfigured rather than failing to start.
func NewOrgIntelExecutor(runner ToolRunner, sender BatchSender, workDir string) *OrgIntelExecutor {
	return &OrgIntelExecutor{
		runner: runner, sender: sender, workDir: workDir,
		now: func() time.Time { return time.Now().UTC() },
	}
}

// Execute runs one enterprise-information job.
func (e *OrgIntelExecutor) Execute(ctx context.Context, request contract.ScanRequest) (job.ExecutionResult, error) {
	if e.sender == nil {
		return job.ExecutionResult{}, errors.New("baiyan org_intel: callback sender is required")
	}
	if err := e.send(ctx, request, contract.CallbackBatch{
		SchemaVersion: contract.SchemaVersion, RunID: request.RunID, Seq: 1,
		Phase: "started", Status: "running", ObservedAt: e.now(),
		Assets: []contract.AssetFact{}, Relations: []contract.RelationFact{},
		Exposures: []contract.ExposureFact{}, ProviderErrors: []contract.ProviderError{},
	}); err != nil {
		return job.ExecutionResult{}, err
	}

	providerErrors := make([]contract.ProviderError, 0)
	organizations := make([]contract.OrganizationFact, 0)
	filings := make([]contract.FilingFact, 0)
	assets := make([]contract.AssetFact, 0)

	if e.runner == nil || !e.runner.Has(orgIntelTool) {
		// The engine was built without the tool, or the operator did not enable
		// it. That is a deployment fact, not a scan result, and it has to reach
		// ASM as explicit evidence rather than as an empty success.
		providerErrors = append(providerErrors, contract.ProviderError{
			Provider: orgIntelTool, Code: "PROVIDER_NOT_CONFIGURED",
			Message: "enterprise intelligence tool is not available in this engine", Retryable: false,
		})
		return e.finish(ctx, request, assets, organizations, filings, providerErrors)
	}

	sources, err := requestedEnscanSources(request.Options)
	if err != nil {
		return job.ExecutionResult{}, err
	}
	fields := requestedEnscanFields(request.Options)

	for _, target := range request.Targets {
		company := strings.TrimSpace(target.Value)
		if company == "" {
			continue
		}
		collected, runErr := e.collectForCompany(ctx, request, company, sources, fields)
		if runErr != nil {
			providerErrors = append(providerErrors, contract.ProviderError{
				Provider: orgIntelTool, Code: runErr.code, Message: runErr.message, Retryable: runErr.retryable,
			})
			continue
		}
		organizations = append(organizations, collected.organizations...)
		filings = append(filings, collected.filings...)
		assets = append(assets, collected.assets...)
		if len(organizations) >= maxOrgResults {
			organizations = organizations[:maxOrgResults]
			break
		}
	}
	return e.finish(ctx, request, assets, organizations, filings, providerErrors)
}

type collectedOrgIntel struct {
	organizations []contract.OrganizationFact
	filings       []contract.FilingFact
	assets        []contract.AssetFact
}

// toolFailure carries a tool problem as evidence rather than as a Go error, so
// one failing company does not abandon the whole run.
type toolFailure struct {
	code      string
	message   string
	retryable bool
}

func (e *OrgIntelExecutor) collectForCompany(
	ctx context.Context, request contract.ScanRequest, company string, sources, fields []string,
) (collectedOrgIntel, *toolFailure) {
	outDir, err := e.prepareOutputDir(request.RunID, company)
	if err != nil {
		return collectedOrgIntel{}, &toolFailure{
			code: "ENGINE_WORKDIR_UNAVAILABLE", message: "could not prepare an output directory", retryable: false,
		}
	}
	defer func() { _ = os.RemoveAll(outDir) }()

	args := enscanArgs(company, outDir, sources, fields)

	result, runErr := e.runner.Run(ctx, toolrunner.Request{
		Tool: orgIntelTool, Args: args, Dir: outDir,
		Timeout: orgIntelTimeout(request.TimeoutSeconds),
		// enscan needs a writable HOME for its own config, and nothing else. The
		// engine's environment — including the callback secret — is not inherited.
		Env: map[string]string{"HOME": outDir, "PATH": "/usr/bin:/bin"},
	})
	if runErr != nil {
		if errors.Is(runErr, toolrunner.ErrTimeout) {
			return collectedOrgIntel{}, &toolFailure{
				code: "PROVIDER_TIMEOUT", message: "enterprise lookup exceeded its timeout", retryable: true,
			}
		}
		// The tool's own output is not forwarded: it echoes the cookies it was
		// configured with and the queries it made.
		return collectedOrgIntel{}, &toolFailure{
			code: "PROVIDER_UNAVAILABLE", message: "enterprise lookup failed to run", retryable: true,
		}
	}
	if result.ExitCode != 0 {
		return collectedOrgIntel{}, &toolFailure{
			code: "PROVIDER_UNAVAILABLE",
			message: fmt.Sprintf("enterprise lookup exited with status %d; check that a credential is configured for %s",
				result.ExitCode, strings.Join(sources, ",")),
			retryable: true,
		}
	}
	return e.parseOutputDir(outDir, company, e.now())
}

func (e *OrgIntelExecutor) prepareOutputDir(runID uint64, company string) (string, error) {
	base := e.workDir
	if base == "" {
		base = os.TempDir()
	}
	// The company name is attacker-influenced free text and must never reach a
	// path. A hash of it keeps runs separate without letting it escape.
	dir := filepath.Join(base, fmt.Sprintf("org-%d-%s", runID, stableRef("org", company)))
	if err := os.MkdirAll(dir, orgIntelOutputDirMode); err != nil {
		return "", err
	}
	return dir, nil
}

// enscanRecord is one row of enscan's JSON output. Every value is a string
// because the tool flattens heterogeneous registry data into string maps.
type enscanRecord map[string]string

func (e *OrgIntelExecutor) parseOutputDir(dir, company string, observedAt time.Time) (collectedOrgIntel, *toolFailure) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return collectedOrgIntel{}, &toolFailure{
			code: "ENGINE_OUTPUT_UNREADABLE", message: "could not read enterprise lookup output", retryable: false,
		}
	}
	out := collectedOrgIntel{
		organizations: make([]contract.OrganizationFact, 0),
		filings:       make([]contract.FilingFact, 0),
		assets:        make([]contract.AssetFact, 0),
	}
	seenOrg := make(map[string]bool)
	seenFiling := make(map[string]bool)
	seenDomain := make(map[string]bool)
	rootRef := stableRef("org", company)

	// The root company is asserted from the request, not from tool output, so a
	// filing always has an organization to hang off even when the registry
	// returned nothing about the company itself.
	out.organizations = append(out.organizations, contract.OrganizationFact{
		FactMeta:    orgFactMeta(rootRef, "org:"+strings.ToLower(company), observedAt, 90),
		Name:        company,
		SubjectType: "company",
	})
	seenOrg[strings.ToLower(company)] = true

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			names = append(names, entry.Name())
		}
	}
	// Sorted so a run over the same data produces the same fact order.
	sort.Strings(names)

	for _, name := range names {
		payload, readErr := readBoundedFile(filepath.Join(dir, name), maxOrgIntelFileSize)
		if readErr != nil {
			continue
		}
		var sections map[string][]enscanRecord
		if json.Unmarshal(payload, &sections) != nil {
			// Output that does not parse is dropped rather than guessed at.
			continue
		}
		e.collectSections(sections, rootRef, observedAt, seenOrg, seenFiling, seenDomain, &out)
	}
	return out, nil
}

func (e *OrgIntelExecutor) collectSections(
	sections map[string][]enscanRecord, rootRef string, observedAt time.Time,
	seenOrg, seenFiling, seenDomain map[string]bool, out *collectedOrgIntel,
) {
	sectionNames := make([]string, 0, len(sections))
	for name := range sections {
		sectionNames = append(sectionNames, name)
	}
	sort.Strings(sectionNames)

	for _, section := range sectionNames {
		for _, record := range sections[section] {
			switch {
			case isEnterpriseSection(section):
				e.collectOrganization(record, rootRef, observedAt, seenOrg, out)
			case isFilingSection(section):
				e.collectFiling(record, rootRef, observedAt, seenFiling, seenDomain, out)
			}
		}
	}
}

func (e *OrgIntelExecutor) collectOrganization(
	record enscanRecord, rootRef string, observedAt time.Time, seenOrg map[string]bool, out *collectedOrgIntel,
) {
	name := cleanRegistryText(firstNonEmpty(record, "name", "企业名称", "公司名称"))
	if name == "" || len(out.organizations) >= maxOrgResults {
		return
	}
	key := strings.ToLower(name)
	if seenOrg[key] {
		return
	}
	seenOrg[key] = true

	ref := stableRef("org", name)
	fact := contract.OrganizationFact{
		FactMeta:         orgFactMeta(ref, "org:"+key, observedAt, 75),
		Name:             name,
		SubjectType:      "company",
		RegistrationCode: cleanRegistryCode(firstNonEmpty(record, "credit_code", "统一社会信用代码", "creditCode")),
		Parent:           contract.FactReference{ClientRef: rootRef},
		Relation:         normalizeOrgRelation(firstNonEmpty(record, "relation", "type", "关系")),
		EquityRatio:      parseEquityRatio(firstNonEmpty(record, "invest", "percent", "持股比例", "投资比例")),
	}
	out.organizations = append(out.organizations, fact)
}

func (e *OrgIntelExecutor) collectFiling(
	record enscanRecord, rootRef string, observedAt time.Time,
	seenFiling, seenDomain map[string]bool, out *collectedOrgIntel,
) {
	filingNo := cleanRegistryText(firstNonEmpty(record, "icp", "license", "备案号", "网站备案/许可证号"))
	if filingNo == "" || !filingNoPattern.MatchString(filingNo) {
		return
	}
	if seenFiling[filingNo] || len(out.filings) >= maxFilingsPerOrg {
		return
	}
	seenFiling[filingNo] = true

	holder := cleanRegistryText(firstNonEmpty(record, "name", "企业名称", "主办单位名称"))
	orgRef := rootRef
	if holder != "" {
		orgRef = stableRef("org", holder)
	}

	domains := extractDomains(record, seenDomain)
	out.filings = append(out.filings, contract.FilingFact{
		FactMeta:     orgFactMeta(stableRef("filing", filingNo), "filing:"+filingNo, observedAt, 85),
		Organization: contract.FactReference{ClientRef: orgRef},
		FilingNo:     filingNo,
		FilingType:   normalizeFilingType(filingNo),
		WebsiteName:  cleanRegistryText(firstNonEmpty(record, "site_name", "网站名称", "title")),
		Domains:      domains,
	})

	// A domain proven by an ICP filing is a genuine root asset and belongs in the
	// asset inventory, not only in the filing evidence.
	for _, domain := range domains {
		out.assets = append(out.assets, assetFact(
			stableRef("root", domain), "domain:"+domain, "domain", domain, "icp_filing", observedAt,
		))
	}
}

func extractDomains(record enscanRecord, seenDomain map[string]bool) []string {
	raw := firstNonEmpty(record, "domain", "website", "网站首页网址", "域名", "homeSite")
	if raw == "" {
		return nil
	}
	domains := make([]string, 0, 1)
	// Registry fields routinely pack several values into one cell.
	for _, candidate := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' || r == '，' || r == '；'
	}) {
		domain := normalizeRegistryDomain(candidate)
		if domain == "" || seenDomain[domain] {
			continue
		}
		seenDomain[domain] = true
		domains = append(domains, domain)
		if len(domains) >= maxDomainsPerFiling {
			break
		}
	}
	return domains
}

// normalizeRegistryDomain reduces a free-text registry value to a domain, or to
// "" when it is not one.
func normalizeRegistryDomain(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://")
	if idx := strings.IndexAny(value, "/?#:"); idx >= 0 {
		value = value[:idx]
	}
	value = strings.TrimSuffix(strings.TrimPrefix(value, "www."), ".")
	if value == "" || len(value) > 253 || !domainPattern.MatchString(value) {
		return ""
	}
	// A bare TLD is not an asset.
	if strings.Count(value, ".") < 1 {
		return ""
	}
	// An IP literal is not a domain. No TLD is numeric, so checking the last
	// label rejects dotted quads without a separate IP parser.
	last := value[strings.LastIndex(value, ".")+1:]
	if strings.IndexFunc(last, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
		return ""
	}
	return value
}

func normalizeFilingType(filingNo string) string {
	if strings.Contains(filingNo, "证") {
		return "license"
	}
	return "filing"
}

func normalizeOrgRelation(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "branch", "分公司", "分支机构":
		return "branch"
	case "hold", "holds", "控股":
		return "hold"
	case "supplier", "供应商":
		return "supplier"
	default:
		return "invest"
	}
}

func parseEquityRatio(raw string) float64 {
	value := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), "%"))
	if value == "" {
		return 0
	}
	ratio, err := strconv.ParseFloat(value, 64)
	if err != nil || ratio < 0 || ratio > 100 {
		return 0
	}
	return ratio
}

// cleanRegistryText strips the control characters and full-width padding that
// scraped registry data is full of, and bounds the length.
func cleanRegistryText(raw string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, raw)
	cleaned = strings.TrimSpace(strings.ReplaceAll(cleaned, "　", " "))
	if len(cleaned) > 255 {
		cleaned = strings.TrimSpace(cleaned[:255])
	}
	return cleaned
}

// cleanRegistryCode keeps only the characters a unified social credit code can
// contain, so a junk value cannot ride into the database.
func cleanRegistryCode(raw string) string {
	code := strings.ToUpper(cleanRegistryText(raw))
	for _, r := range code {
		if (r < '0' || r > '9') && (r < 'A' || r > 'Z') {
			return ""
		}
	}
	if len(code) > 64 {
		return ""
	}
	return code
}

func firstNonEmpty(record enscanRecord, keys ...string) string {
	for _, key := range keys {
		if value, ok := record[key]; ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func isEnterpriseSection(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "enterprise") || strings.Contains(lower, "invest") ||
		strings.Contains(lower, "branch") || strings.Contains(lower, "holds")
}

func isFilingSection(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "icp") || strings.Contains(lower, "filing")
}

func orgFactMeta(clientRef, naturalKey string, observedAt time.Time, confidence uint8) contract.FactMeta {
	return contract.FactMeta{
		ClientRef: clientRef, NaturalKey: naturalKey,
		Source: "org_intel", Provider: orgIntelTool,
		ObservedAt: observedAt, Confidence: confidence,
		// Enterprise registries are third-party datasets. Nothing here touches
		// the customer's own infrastructure.
		ActiveProbe: false,
	}
}

func requestedEnscanSources(options map[string]any) ([]string, error) {
	raw, ok := options["sources"]
	if !ok {
		return []string{"aqc"}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, errors.New("baiyan org_intel: sources option must be a list")
	}
	sources := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		name, ok := value.(string)
		if !ok {
			return nil, errors.New("baiyan org_intel: sources entries must be strings")
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if !enscanSources[name] {
			return nil, fmt.Errorf("baiyan org_intel: source %q is not allowed", name)
		}
		if !seen[name] {
			seen[name] = true
			sources = append(sources, name)
		}
	}
	if len(sources) == 0 {
		return []string{"aqc"}, nil
	}
	sort.Strings(sources)
	return sources, nil
}

// enscanFields are the field groups worth collecting. Anything not listed is not
// requested, which keeps the number of registry queries — and the account risk —
// proportional to what ASM can actually store.
var enscanFields = map[string]bool{"icp": true, "app": true, "wechat": true, "weibo": true, "copyright": true}

func requestedEnscanFields(options map[string]any) []string {
	raw, ok := options["fields"]
	if !ok {
		return []string{"icp"}
	}
	values, ok := raw.([]any)
	if !ok {
		return []string{"icp"}
	}
	fields := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		name, ok := value.(string)
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if enscanFields[name] && !seen[name] {
			seen[name] = true
			fields = append(fields, name)
		}
	}
	if len(fields) == 0 {
		return []string{"icp"}
	}
	sort.Strings(fields)
	return fields
}

func orgIntelTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return 10 * time.Minute
	}
	timeout := time.Duration(seconds) * time.Second
	if timeout > toolrunner.MaxTimeout {
		return toolrunner.MaxTimeout
	}
	return timeout
}

// maxOrgIntelFileSize bounds one result file. enscan writes what a registry
// returned, and the engine must not be at the mercy of that size.
const maxOrgIntelFileSize = 32 << 20

func readBoundedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("baiyan org_intel: %s exceeds the size limit", filepath.Base(path))
	}
	return os.ReadFile(path) // #nosec G304 -- path is built from the engine's own work directory
}

func (e *OrgIntelExecutor) finish(
	ctx context.Context, request contract.ScanRequest,
	assets []contract.AssetFact, organizations []contract.OrganizationFact,
	filings []contract.FilingFact, providerErrors []contract.ProviderError,
) (job.ExecutionResult, error) {
	status := "success"
	summary := ""
	if len(providerErrors) > 0 {
		status = "partial_success"
		summary = "some enterprise sources did not return data"
	}
	batch := contract.CallbackBatch{
		SchemaVersion: contract.SchemaVersion, RunID: request.RunID, Seq: 2,
		Phase: "completed", Status: status, ObservedAt: e.now(),
		Assets: assets, Relations: []contract.RelationFact{}, Exposures: []contract.ExposureFact{},
		Organizations: organizations, Filings: filings,
		ProviderErrors: providerErrors, ErrorSummary: summary,
	}
	batch.ResultCount = uint64(batch.FactCount())
	if err := e.send(ctx, request, batch); err != nil {
		return job.ExecutionResult{}, err
	}
	return job.ExecutionResult{Status: status, ResultCount: batch.ResultCount, ErrorSummary: summary}, nil
}

func (e *OrgIntelExecutor) send(ctx context.Context, request contract.ScanRequest, batch contract.CallbackBatch) error {
	return e.sender.Send(ctx, request.CallbackURL, batch, 3)
}
