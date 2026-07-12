package baiyan

import (
	"bufio"
	"encoding/base64"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Options struct {
	RootDir            string
	TargetsFile        string
	ICP                string
	Company            string
	Deep               int
	Ratio              int
	CertScan           bool
	DirScan            bool
	FastScan           bool
	NoFinger           bool
	Threads            int
	MasscanConcurrency int
}

type App struct {
	opts            Options
	rootDir         string
	workspace       Workspace
	progress        *Progress
	httpClient      *http.Client
	spaceConfig     SpaceConfig
	subfinderConfig SubfinderConfig
	cdnMatcher      *CDNMatcher
	esdDict         []string
	esdDictOnce     sync.Once
	esdDictErr      error
	targets         []string // cached for checkpoint saves
	fileMu          sync.Mutex
	skipSources     map[string]bool // 预检查失效的来源，本轮跳过
}

type Workspace struct {
	ExternalDir     string
	RuntimeDir      string
	URLsFile        string
	SubdomainsFile  string
	DirscanFile     string
	CIDRFile        string
	FingerFile      string
	ResultXLSX      string
	DirscanWordlist string
	SubfinderConfig string
}

type Progress struct {
	mu    sync.Mutex
	start time.Time
}

type OrderedSet struct {
	mu    sync.Mutex
	items []string
	seen  map[string]struct{}
}

type State struct {
	Subdomains *OrderedSet
	URLs       *OrderedSet
	CIDRs      *OrderedSet
}

type CDNMatcher struct {
	cidrs         []*net.IPNet
	cnameKeywords []string
}

type MasscanRecord struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port int `json:"port"`
	} `json:"ports"`
}

type FingerRecord struct {
	URL        string
	Name       string
	Length     string
	StatusCode string
	Title      string
	Priority   string
}

type scanTask struct {
	Host    string
	IP      string
	Ports   []int
	Profile string
}

// ——— checkpoint types ———

const checkpointVersion = 1

type TargetPhase string

const (
	phaseStarting          TargetPhase = "starting"
	phaseSubdomainsDone   TargetPhase = "subdomains_done"
	phaseCIDRScanning     TargetPhase = "cidr_scanning"
	phaseTargetDone       TargetPhase = "target_done"
)

type Checkpoint struct {
	Version      int              `json:"version"`
	TargetsFile  string           `json:"targets_file"`
	Targets      []string         `json:"targets"`
	Options      checkpointOpts   `json:"options"`
	LastTargetIdx int             `json:"last_target_idx"`
	LastTarget   string           `json:"last_target"`
	Phase        TargetPhase      `json:"phase"`
	DomainCtx    *domainContext   `json:"domain_ctx,omitempty"`
	CIDRCtx      *cidrContext     `json:"cidr_ctx,omitempty"`
}

type checkpointOpts struct {
	CertScan           bool `json:"certscan"`
	DirScan            bool `json:"dirscan"`
	FastScan           bool `json:"fast_scan"`
	NoFinger           bool `json:"nofinger"`
	Threads            int  `json:"threads"`
	MasscanConcurrency int  `json:"masscan_concurrency"`
}

type domainContext struct {
	ScanSubs []string `json:"scan_subs"`
	AllSubs  []string `json:"all_subs"`
}

type cidrContext struct {
	CIDR           string `json:"cidr"`
	ScannedIPCount int    `json:"scanned_ip_count"`
	TotalIPCount   int    `json:"total_ip_count"`
}

var cdnPorts = uniqueIntSlice([]int{
	80, 443, 444, 808, 844, 8080, 8081, 8443, 9090, 9091, 9092, 9093, 3000, 3001, 4000, 5000, 5173, 6000,
	7001, 7002, 8000, 8001, 8009, 8010, 8020, 8088, 8090, 8091, 8100, 8123, 8181, 8500, 8848, 8849, 8888,
	8889, 9000, 9001, 9080, 9200, 9300, 9443, 9500, 9600, 10000, 10080, 10443, 10668, 11001, 11111, 11211,
	11443, 12000, 12345, 12443, 14000, 14443, 15672, 16080, 17000, 18080, 19000, 20000, 20880, 21000, 22000,
	23000, 2375, 2376, 2377, 2379, 2380, 27017, 3306, 3307, 33060, 3389, 5006, 5007, 5432, 5433, 5672, 5800,
	5900, 6001, 6379, 6443, 7000, 7001, 7474, 7475, 7687, 7777, 7800, 8023, 8043, 8060, 8069, 8092, 8093,
	8123, 8138, 8140, 8258, 8280, 8281, 8300, 8443, 8444, 8545, 8558, 8563, 8600, 8686, 8765, 8777, 8780,
	8859, 8983, 8984, 9081, 9094, 9095, 9140, 9153, 9191, 9343, 9379, 9390, 9444, 9492, 9500, 9527, 9669,
	9700, 9750, 9790, 9791, 9792, 9793, 9794, 9795, 9796, 9800, 9868, 9876, 9898, 9900, 9901, 9909, 9943,
	9981,
})

var portLiarProbePorts = []int{7137, 3591, 31337, 44444, 54321, 65533}

// isPortLiar probes unusual ports with TCP connect. If 3 or more respond,
// the host likely has a firewall/WAF that accepts connections on all ports.
func isPortLiar(ctx context.Context, ip string) bool {
	hit := 0
	for _, port := range portLiarProbePorts {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 2*time.Second)
		if err == nil {
			conn.Close()
			hit++
		}
		if hit >= 3 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		default:
		}
	}
	return false
}

var defaultWebPorts = uniqueIntSlice([]int{
	80, 81, 82, 88, 90, 443, 444, 591, 593, 800, 801, 808, 880,
	1000, 1080, 1311, 1414, 2301, 3000, 3001, 3128, 3443, 4000, 4443,
	4567, 4848, 5000, 5001, 5080, 5443, 5601, 5800, 6080, 6081, 7001,
	7002, 7080, 7081, 7443, 7777, 7800, 8000, 8001, 8008, 8009, 8010,
	8020, 8023, 8043, 8060, 8069, 8080, 8081, 8082, 8083, 8088, 8090,
	8091, 8092, 8093, 8100, 8123, 8181, 8200, 8280, 8281, 8443, 8444,
	8484, 8500, 8686, 8765, 8780, 8800, 8848, 8880, 8888, 8889, 9000,
	9001, 9043, 9060, 9080, 9081, 9090, 9091, 9092, 9093, 9443, 9444,
	9500, 9800, 9981, 10000, 10443, 12043, 12443, 15672, 16080, 18080,
	20000,
})

var lowValueSubdomainPorts = uniqueIntSlice([]int{
	80, 81, 88, 443, 444, 591, 593, 8000, 8001, 8080, 8081, 8443, 8888, 9443,
})

var lowValueSubdomainPrefixes = []string{
	"autodiscover",
	"imap",
	"mail",
	"mx",
	"pop",
	"pop3",
	"smtp",
	"webmail",
}

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func New(opts Options) (*App, error) {
	if opts.Threads <= 0 {
		opts.Threads = 300
	}
	if opts.MasscanConcurrency <= 0 {
		opts.MasscanConcurrency = 1
	}
	rootDir, err := filepath.Abs(opts.RootDir)
	if err != nil {
		return nil, err
	}

	if err := ensureLib(rootDir); err != nil {
		return nil, fmt.Errorf("解压 lib/ 失败: %w", err)
	}

	if fresh, err := ensureConfig(rootDir); err != nil {
		return nil, fmt.Errorf("生成 config/ 失败: %w", err)
	} else if fresh {
		fmt.Printf("\n[CONFIG] 已在 %s 生成配置模板：\n", filepath.Join(rootDir, "config"))
		fmt.Println("  - spaceConfig.ini     ← 填写 FOFA / Quake 密钥")
		fmt.Println("  - subfinder-config.yaml ← 填写各平台 API 凭据")
		fmt.Println("\n  填写完成后重新运行 ./baiyan -f targets.txt")
		return nil, ErrConfigGenerated
	}

	spaceCfg, err := loadSpaceConfig(rootDir)
	if err != nil {
		return nil, fmt.Errorf("读取 spaceConfig.ini 失败: %w", err)
	}
	subfinderCfg, err := loadSubfinderConfig(rootDir)
	if err != nil {
		return nil, fmt.Errorf("读取 subfinder-config.yaml 失败: %w", err)
	}
	workspace, err := newWorkspace(rootDir)
	if err != nil {
		return nil, err
	}
	cdnMatcher, err := loadCDNMatcher(rootDir)
	if err != nil {
		return nil, err
	}

	return &App{
		opts:            opts,
		rootDir:         rootDir,
		workspace:       workspace,
		progress:        &Progress{start: time.Now()},
		httpClient:      &http.Client{Timeout: 20 * time.Second},
		spaceConfig:     spaceCfg,
		subfinderConfig: subfinderCfg,
		cdnMatcher:      cdnMatcher,
	}, nil
}

func newWorkspace(rootDir string) (Workspace, error) {
	externalDir := filepath.Join(rootDir, "external")
	runtimeDir := filepath.Join(externalDir, "go-runtime")
	if err := os.MkdirAll(externalDir, 0o755); err != nil {
		return Workspace{}, err
	}
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return Workspace{}, err
	}

	ws := Workspace{
		ExternalDir:     externalDir,
		RuntimeDir:      runtimeDir,
		URLsFile:        filepath.Join(externalDir, "result.txt"),
		SubdomainsFile:  filepath.Join(externalDir, "subdomianlist.txt"),
		DirscanFile:     filepath.Join(externalDir, "dir.txt"),
		CIDRFile:        filepath.Join(externalDir, "cidr.txt"),
		FingerFile:      filepath.Join(rootDir, "lib", "ob", "ob_output.txt"),
		ResultXLSX:      filepath.Join(rootDir, "result.xlsx"),
		DirscanWordlist: filepath.Join(rootDir, "lib", "dirscan", "dicc.txt"),
		SubfinderConfig: filepath.Join(rootDir, "config", "subfinder-config.yaml"),
	}

	for _, path := range []string{ws.URLsFile, ws.SubdomainsFile, ws.DirscanFile, ws.CIDRFile, ws.FingerFile} {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return Workspace{}, err
		}
		f.Close()
	}
	return ws, nil
}

func loadCDNMatcher(root string) (*CDNMatcher, error) {
	cidrPath := filepath.Join(root, "lib", "OneForAll", "data", "cdn_ip_cidr.json")
	keywordPath := filepath.Join(root, "lib", "OneForAll", "data", "cdn_cname_keywords.json")

	var cidrValues []string
	cidrData, err := os.ReadFile(cidrPath)
	if err != nil {
		return nil, fmt.Errorf("读取 CDN CIDR 数据失败: %w", err)
	}
	if err := json.Unmarshal(cidrData, &cidrValues); err != nil {
		return nil, fmt.Errorf("解析 CDN CIDR 数据失败: %w", err)
	}

	cidrs := make([]*net.IPNet, 0, len(cidrValues))
	for _, value := range cidrValues {
		_, network, err := net.ParseCIDR(strings.TrimSpace(value))
		if err == nil && network != nil {
			cidrs = append(cidrs, network)
		}
	}

	var keywordMap map[string]string
	keywordData, err := os.ReadFile(keywordPath)
	if err != nil {
		return nil, fmt.Errorf("读取 CDN CNAME 关键字失败: %w", err)
	}
	if err := json.Unmarshal(keywordData, &keywordMap); err != nil {
		return nil, fmt.Errorf("解析 CDN CNAME 关键字失败: %w", err)
	}

	keywords := make([]string, 0, len(keywordMap))
	for key := range keywordMap {
		key = strings.TrimSpace(strings.ToLower(key))
		if key != "" {
			keywords = append(keywords, key)
		}
	}
	sort.Strings(keywords)

	return &CDNMatcher{cidrs: cidrs, cnameKeywords: keywords}, nil
}

func (a *App) Run(ctx context.Context) error {
	if a.opts.ICP != "" {
		return a.runICP(ctx)
	}
	if a.opts.Company != "" {
		return a.runCompany(ctx)
	}

	targets, err := readTargets(a.opts.TargetsFile)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("目标文件为空")
	}
	a.targets = targets

	state := &State{
		Subdomains: NewOrderedSet(),
		URLs:       NewOrderedSet(),
		CIDRs:      NewOrderedSet(),
	}

	// ——— checkpoint load / resume ———
	cp, cpErr := a.loadCheckpoint()
	resumed := false
	startIdx := 0

	if cpErr == nil && a.canResumeFrom(cp, targets) {
		// 从 txt 文件恢复数据，而非 checkpoint
		if subs, err := readLines(a.workspace.SubdomainsFile); err == nil {
			state.Subdomains.AddMany(subs)
		}
		if urls, err := readLines(a.workspace.URLsFile); err == nil {
			state.URLs.AddMany(urls)
		}
		if cidrs, err := readLines(a.workspace.CIDRFile); err == nil {
			state.CIDRs.AddMany(cidrs)
		}
		resumed = true

		if cp.Phase == phaseTargetDone {
			startIdx = cp.LastTargetIdx + 1
		} else {
			startIdx = cp.LastTargetIdx
		}
		a.progress.Log("[RESUME] 从断点恢复，已完成 %d/%d 目标，累计子域 %d / URL %d / CIDR %d",
			startIdx, len(targets), state.Subdomains.Len(), state.URLs.Len(), state.CIDRs.Len())
	} else {
		// 全新启动，清空旧数据文件
		for _, path := range []string{a.workspace.SubdomainsFile, a.workspace.URLsFile, a.workspace.CIDRFile} {
			os.WriteFile(path, nil, 0o644)
		}
		a.progress.Log("[0%%] 启动 Go 版 Baiyan，目标总数: %d", len(targets))
		preflightWarnings := a.preflight(ctx)
		if len(preflightWarnings) == 0 {
			a.progress.Log("[5%%] 预检查完成，已验证常见 API 凭据")
		} else {
			a.progress.Log("[5%%] 预检查完成，发现 %d 条警告", len(preflightWarnings))
			for _, warning := range preflightWarnings {
				a.progress.Log("  [WARN] %s -> %s", warning.Source, warning.Message)
			}
		}
	}

	for index := startIdx; index < len(targets); index++ {
		target := targets[index]

		// Determine mid-target resume context.
		isMidTarget := resumed && index == startIdx && cp != nil && cp.Phase != phaseTargetDone
		var domCtx *domainContext
		var cidrCtx *cidrContext
		if isMidTarget {
			if cp.Phase == phaseSubdomainsDone && cp.DomainCtx != nil {
				domCtx = cp.DomainCtx
			} else if cp.Phase == phaseCIDRScanning && cp.CIDRCtx != nil {
				cidrCtx = cp.CIDRCtx
			}
		}

		switch classifyTarget(target) {
		case targetDomain:
			err = a.processDomainNormal(ctx, target, index, len(targets), state, domCtx)
		case targetCIDR:
			err = a.processCIDR(ctx, target, index, len(targets), state, cidrCtx)
		case targetIP:
			// 批量收集连续 IP 目标，并行扫描
			ipBatch := []string{target}
			batchStart := index
			for index+1 < len(targets) && classifyTarget(targets[index+1]) == targetIP {
				index++
				ipBatch = append(ipBatch, targets[index])
			}
			err = a.processIPBatch(ctx, ipBatch, batchStart, len(targets), state)
		default:
			a.progress.Log("[SKIP] 无法识别目标: %s", target)
		}
		if err != nil {
			a.progress.Log("[WARN] 目标 %s 执行失败: %v", target, err)
		}

		// Save checkpoint: target fully processed.
		if saveErr := a.saveCheckpoint(targets, index, target, phaseTargetDone, nil, nil); saveErr != nil {
			a.progress.Log("[WARN] 保存断点失败: %v", saveErr)
		}
	}

	dirscanLines := []string{}
	fingerLines := []string{}

	if a.opts.DirScan {
		a.progress.Log("[82%%] 进入目录扫描阶段，URL 数量: %d", state.URLs.Len())
		dirscanLines, err = a.runDirscan(ctx, state.URLs.Items())
		if err != nil {
			a.progress.Log("[WARN] 目录扫描失败: %v", err)
		}
	}

	if !a.opts.NoFinger {
		a.progress.Log("[90%%] 进入指纹探测阶段，默认开启")
		fingerLines, err = a.runObserverWard(ctx, a.workspace.URLsFile)
		if err != nil {
			a.progress.Log("[WARN] 指纹探测失败: %v", err)
		}
	} else {
		a.progress.Log("[90%%] 已跳过指纹探测: --nofinger")
	}

	a.workspace.ResultXLSX = filepath.Join(a.rootDir, "result_"+time.Now().Format("20060102_150405")+".xlsx")
	if err := a.writeWorkbook(state, dirscanLines, fingerLines); err != nil {
		return err
	}
	a.clearCheckpoint()
	a.progress.Log("[100%%] 执行完成，结果文件: %s", a.workspace.ResultXLSX)
	return nil
}

func (a *App) processDomainNormal(ctx context.Context, domain string, targetIndex, targetTotal int, state *State, domCtx *domainContext) error {
	targetLabel := fmt.Sprintf("目标 %d/%d %s", targetIndex+1, targetTotal, domain)

	scanSubs := NewOrderedSet()
	allSubs := NewOrderedSet()
	scanSubs.Add(domain)
	allSubs.Add(domain)

	resolvedIPs := NewOrderedSet()
	urlStartIdx := state.URLs.Len() // 本 target 新增 URL 基线,供路径派生切片

	if domCtx != nil {
		// ——— RESUME: restore from checkpoint, skip sub-enum ———
		scanSubs.AddMany(domCtx.ScanSubs)
		allSubs.AddMany(domCtx.AllSubs)
		state.Subdomains.AddMany(allSubs.Items()) // resume 恢复时数据已在文件中，无需重复写入
		a.progress.Log("[RESUME] %s -> 跳过子域收集，扫描子域 %d 个，汇总子域 %d 个", targetLabel, scanSubs.Len()-1, allSubs.Len()-1)
	} else {
		// ——— FRESH: parallel sub-enum ———
		a.progress.Log("[%.0f%%] %s -> 子域收集阶段开始，并行执行 Subfinder-active/Subfinder-all/OneForAll/ESD/SpaceEngines", a.targetPercent(targetIndex, targetTotal, 0.00), targetLabel)

		type sourceJob struct {
			name string
			use  string // "scan+all" or "all"
			fn   func(context.Context) ([]string, error)
		}
		type sourceResult struct {
			name string
			use  string
			vals []string
			err  error
		}

		allJobs := []sourceJob{
			{name: "subfinder-all", use: "scan+all", fn: func(ctx context.Context) ([]string, error) { return a.runSubfinder(ctx, domain, false) }},
			{name: "oneforall-go", use: "scan+all", fn: func(ctx context.Context) ([]string, error) { return a.runOneForAllGo(ctx, domain) }},
			{name: "esd", use: "scan+all", fn: func(ctx context.Context) ([]string, error) { return a.runESD(ctx, domain) }},
			{name: "space-engines", use: "scan+all", fn: func(ctx context.Context) ([]string, error) { return a.collectFromSpaceEngines(ctx, domain) }},
		}
		// 过滤预检查失效的来源
		jobs := make([]sourceJob, 0, len(allJobs))
		for _, j := range allJobs {
			if a.skipSources[j.name] {
				a.progress.Log("[SKIP] %s -> %s 预检查未通过，本轮跳过", targetLabel, j.name)
				continue
			}
			jobs = append(jobs, j)
		}

		var wg sync.WaitGroup
		resultCh := make(chan sourceResult, len(jobs))
		for _, job := range jobs {
			wg.Add(1)
			go func(j sourceJob) {
				defer wg.Done()
				jobCtx, jobCancel := context.WithTimeout(ctx, 2*time.Minute)
				defer jobCancel()
				done := make(chan sourceResult, 1)
				go func() {
					vals, err := j.fn(jobCtx)
					done <- sourceResult{j.name, j.use, vals, err}
				}()
				select {
				case r := <-done:
					resultCh <- r
				case <-jobCtx.Done():
					resultCh <- sourceResult{j.name, j.use, nil, fmt.Errorf("%s 超时（10m0s）", j.name)}
				}
			}(job)
		}
		go func() {
			wg.Wait()
			close(resultCh)
		}()

		// ——— 启动端口扫描 worker 池，等待接收任务 ———
		taskConcurrency := a.opts.MasscanConcurrency
		if taskConcurrency < 1 { taskConcurrency = 1 }
		taskCh := make(chan scanTask, 256)
		var taskWg sync.WaitGroup
		for w := 0; w < taskConcurrency; w++ {
			taskWg.Add(1)
			go func() {
				defer taskWg.Done()
				for task := range taskCh {
					a.progress.Log("[SCAN] %s -> %s(%s) 使用策略 %s", targetLabel, task.Host, task.IP, task.Profile)
					urls, err := a.scanResolvedDomainIP(ctx, task.Host, task.IP, task.Ports)
					if err != nil {
						a.progress.Log("[WARN] %s -> 端口扫描失败 %s(%s): %v", targetLabel, task.Host, task.IP, err)
						continue
					}
					if len(urls) > 0 {
						a.addURLs(state, urls)
					}
				}
			}()
		}

		// ——— 流式处理：来源返回即开始解析+扫描，不等全部完成 ———
		var prepWg sync.WaitGroup
		// 每子域独立 goroutine，限制并发数防止 DNS 风暴
		subSem := make(chan struct{}, 64)

		for r := range resultCh {
			if r.err != nil {
				a.progress.Log("[WARN] %s -> %s 失败: %v", targetLabel, r.name, r.err)
			}
			if r.use == "all" || r.use == "scan+all" {
				allSubs.AddMany(r.vals)
			}
			if r.use != "scan+all" || len(r.vals) == 0 {
				continue
			}
			scanSubs.AddMany(r.vals)
			// 每子域独立 goroutine 处理，避免单子域卡住整批
			vals := r.vals
			batchWaf := false
			var wafMu sync.Mutex
			for _, subdomain := range vals {
				if batchWaf { break }
				subdomain := subdomain
				prepWg.Add(1)
				subSem <- struct{}{}
				go func() {
					defer prepWg.Done()
					defer func() { <-subSem }()
					// 本批已检测到 WAF，直接跳过
					wafMu.Lock()
					if batchWaf {
						wafMu.Unlock()
						return
					}
					wafMu.Unlock()
					if a.scheduleResolved(ctx, targetLabel, subdomain, resolvedIPs, state, taskCh) {
						wafMu.Lock()
						batchWaf = true
						wafMu.Unlock()
					}
				}()
			}
		}

		// 子域收集完成，立刻落盘
		a.addSubdomains(state, allSubs.Items())

		// 等待所有子域预处理完成
		prepWg.Wait()

		// ——— alterx 词表交叉派生：用已收集子域作语料，派生新子域复用 resolve+扫描 ———
		derived := a.alterxDerive(ctx, domain, allSubs.Items())
		if len(derived) > 0 {
			a.progress.Log("[ALTERX] %s -> 派生存活子域 %d 个", targetLabel, len(derived))
			scanSubs.AddMany(derived)
			allSubs.AddMany(derived)
			a.addSubdomains(state, derived)
			var deriveWg sync.WaitGroup
			for _, sub := range derived {
				sub := sub
				deriveWg.Add(1)
				subSem <- struct{}{}
				go func() {
					defer deriveWg.Done()
					defer func() { <-subSem }()
					a.scheduleResolved(ctx, targetLabel, sub, resolvedIPs, state, taskCh)
				}()
			}
			deriveWg.Wait()
		}

		// 关闭任务通道，等待 worker 结束
		close(taskCh)
		taskWg.Wait()
		a.progress.Log("[%.0f%%] %s -> 子域收集+端口扫描完成，扫描子域 %d 个，汇总子域 %d 个", a.targetPercent(targetIndex, targetTotal, 0.80), targetLabel, scanSubs.Len(), allSubs.Len())

		// ——— 主机名派生路径探测：对本 target 新增 URL 拆 host label 探二级路径 ———
		newURLs := state.URLs.Items()[urlStartIdx:]
		if len(newURLs) > 0 {
			extra := a.probeDerivedPaths(ctx, newURLs)
			if len(extra) > 0 {
				a.progress.Log("[PATH-DERIVE] %s -> 派生命中 URL %d 个", targetLabel, len(extra))
				a.addURLs(state, extra)
			}
		}

		// Save checkpoint: sub-enum is the most expensive phase.
		if err := a.saveCheckpoint(nil, targetIndex, domain, phaseSubdomainsDone, &domainContext{
			ScanSubs: scanSubs.Items(),
			AllSubs:  allSubs.Items(),
		}, nil); err != nil {
			a.progress.Log("[WARN] %s -> 保存断点失败: %v", targetLabel, err)
		}
	}

	if a.opts.CertScan {
		a.progress.Log("[%.0f%%] %s -> 证书关联 IP 探测开始", a.targetPercent(targetIndex, targetTotal, 0.88), targetLabel)
		certIPs, err := a.queryCertIPs(ctx, domain)
		if err != nil {
			a.progress.Log("[WARN] %s -> 证书关联 IP 查询失败: %v", targetLabel, err)
		}
		for idx, ip := range certIPs {
			a.progress.Log("[%.0f%%] %s -> 证书 IP %d/%d: %s", a.targetPercent(targetIndex, targetTotal, 0.88+0.12*progressRatio(idx, len(certIPs))), targetLabel, idx+1, len(certIPs), ip)
			if isInternalIP(ip) || !resolvedIPs.Add(ip) {
				continue
			}
			urls, err := a.scanIPWeb(ctx, ip)
			if err != nil {
				a.progress.Log("[WARN] %s -> 证书 IP 扫描失败 %s: %v", targetLabel, ip, err)
				continue
			}
			a.addURLs(state, urls)
		}
	}

	a.addCIDRs(state, buildCIDRLines(domain, resolvedIPs.Items()))
	a.progress.Log("[%.0f%%] %s -> 普通模式完成，URL 累计 %d", a.targetPercent(targetIndex, targetTotal, 1.00), targetLabel, state.URLs.Len())
	return nil
}

// scheduleResolved 解析单个子域:CDN/WAF 判定后,非 CDN 投递 masscan 任务,CDN 直接探活进 URLs。
// 流式收集与 alterx 派生阶段共用。返回 true 表示命中 WAF CNAME(调用方可据此批级跳过)。
func (a *App) scheduleResolved(ctx context.Context, targetLabel, sub string, resolvedIPs *OrderedSet, state *State, taskCh chan<- scanTask) bool {
	ips, err := a.resolveIPv4s(ctx, sub)
	if err != nil {
		a.progress.Log("[WARN] %s -> DNS解析异常 %s: %v", targetLabel, sub, err)
		return false
	}
	if len(ips) == 0 {
		return false // 子域不存在(no such host)，静默跳过
	}

	cnameCtx, cnameCancel := context.WithTimeout(ctx, 3*time.Second)
	cname, _ := goResolver.LookupCNAME(cnameCtx, sub)
	cnameCancel()

	if a.isCDN(ips, cname) {
		a.progress.Log("[INFO] %s -> %s CDN 探测", targetLabel, sub)
		if isWAFCNAME(cname) {
			a.progress.Log("[WAF] %s -> 检测到 WAF CNAME: %s → %s", targetLabel, sub, cname)
			return true
		}
		urls, err := a.scanCDNDomain(ctx, sub)
		if err != nil {
			a.progress.Log("[WARN] %s -> CDN 端口探测失败 %s: %v", targetLabel, sub, err)
			return false
		}
		a.addURLs(state, urls)
		return false
	}

	a.progress.Log("[INFO] %s -> %s 非CDN → %v 进入扫描", targetLabel, sub, ips)
	for _, ip := range ips {
		if isInternalIP(ip) {
			continue
		}
		if !resolvedIPs.Add(ip) {
			continue
		}
		profile, ports := a.scanPlanForHost(sub)
		taskCh <- scanTask{Host: sub, IP: ip, Ports: ports, Profile: profile}
	}
	return false
}

func (a *App) processIPBatch(ctx context.Context, ips []string, startIndex, targetTotal int, state *State) error {
	concurrency := a.opts.MasscanConcurrency
	if concurrency < 1 { concurrency = 1 }
	if concurrency > len(ips) { concurrency = len(ips) }

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for i, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			targetLabel := fmt.Sprintf("目标 %d/%d %s", startIndex+idx+1, targetTotal, ip)
			a.progress.Log("[%.0f%%] %s -> 直接扫描单 IP", a.targetPercent(startIndex+idx, targetTotal, 0.00), targetLabel)
			urls, err := a.scanIPWeb(ctx, ip)
			if err != nil {
				mu.Lock()
				if firstErr == nil { firstErr = err }
				mu.Unlock()
				a.progress.Log("[WARN] %s -> 扫描失败: %v", targetLabel, err)
				// Save checkpoint even on failure to avoid re-scanning.
				if saveErr := a.saveCheckpoint(nil, startIndex+idx, ip, phaseTargetDone, nil, nil); saveErr != nil {
					a.progress.Log("[WARN] 保存断点失败 (%s): %v", ip, saveErr)
				}
				return
			}
			a.addURLs(state, urls)
			a.progress.Log("[%.0f%%] %s -> 单 IP 扫描完成，新增 URL %d", a.targetPercent(startIndex+idx, targetTotal, 1.00), targetLabel, len(urls))
			// Save checkpoint immediately after each IP to survive interruptions.
			if saveErr := a.saveCheckpoint(nil, startIndex+idx, ip, phaseTargetDone, nil, nil); saveErr != nil {
				a.progress.Log("[WARN] 保存断点失败 (%s): %v", ip, saveErr)
			}
		}(i, ip)
	}
	wg.Wait()

	return firstErr
}

func (a *App) processCIDR(ctx context.Context, cidr string, targetIndex, targetTotal int, state *State, cidrCtx *cidrContext) error {
	targetLabel := fmt.Sprintf("目标 %d/%d %s", targetIndex+1, targetTotal, cidr)
	start, end, err := cidrRange(cidr)
	if err != nil {
		return err
	}
	total := int(end - start + 1)

	offset := uint32(0)
	if cidrCtx != nil {
		// ——— RESUME: skip already-scanned IPs ———
		offset = uint32(cidrCtx.ScannedIPCount)
		a.progress.Log("[RESUME] %s -> 从 IP %d/%d 继续", targetLabel, offset, total)
	} else {
		a.progress.Log("[%.0f%%] %s -> CIDR 扫描开始，IP 数量约 %d", a.targetPercent(targetIndex, targetTotal, 0.00), targetLabel, total)
	}

	for i := offset; start+i <= end; i++ {
		ip := uint32ToIPv4(start + i)
		a.progress.Log("[%.0f%%] %s -> CIDR IP %d/%d: %s", a.targetPercent(targetIndex, targetTotal, progressRatio(int(i), total)), targetLabel, int(i)+1, total, ip)
		urls, err := a.scanIPWeb(ctx, ip)
		if err != nil {
			a.progress.Log("[WARN] %s -> 扫描 %s 失败: %v", targetLabel, ip, err)
		} else {
			a.addURLs(state, urls)
		}
		// Save checkpoint after each IP to avoid re-scanning.
		if saveErr := a.saveCheckpoint(nil, targetIndex, cidr, phaseCIDRScanning, nil, &cidrContext{
			CIDR:           cidr,
			ScannedIPCount: int(i) + 1,
			TotalIPCount:   total,
		}); saveErr != nil {
			a.progress.Log("[WARN] %s -> 保存断点失败: %v", targetLabel, saveErr)
		}
	}
	a.progress.Log("[%.0f%%] %s -> CIDR 扫描完成", a.targetPercent(targetIndex, targetTotal, 1.00), targetLabel)
	return nil
}

func (a *App) runSubfinder(ctx context.Context, domain string, active bool) ([]string, error) {
	outputFile := filepath.Join(a.workspace.RuntimeDir, fmt.Sprintf("%s_subfinder_%t.txt", safeName(domain), active))
	args := []string{"-pc", a.workspace.SubfinderConfig, "-d", domain, "-o", outputFile}
	if active {
		args = append(args, "-active")
	}
	args = append(args, "-silent")
	if err := a.runCommand(ctx, 10*time.Minute, "subfinder", nil, nil, filepath.Join(a.rootDir, "lib", "subfinder", "subfinder"), args...); err != nil {
		return nil, err
	}
	defer os.Remove(outputFile)
	return readLines(outputFile)
}

func (a *App) runESD(ctx context.Context, domain string) ([]string, error) {
	return a.bruteForceSubdomains(ctx, domain)
}

func (a *App) scanResolvedDomainIP(ctx context.Context, domain, ip string, ports []int) ([]string, error) {
	openPorts, err := a.runMasscan(ctx, ip, ports)
	if err != nil {
		return nil, err
	}
	if len(openPorts) == 0 {
		return nil, nil
	}
	if len(openPorts) > 100 && isPortLiar(ctx, ip) {
		a.progress.Log("[WARN] %s(%s) 端口全开防护(masscan返回 %d 端口)，丢弃该 IP", domain, ip, len(openPorts))
		return nil, nil
	}
	inputs := make([]string, 0, len(openPorts))
	for _, port := range openPorts {
		inputs = append(inputs, fmt.Sprintf("%s:%d", domain, port))
	}
	return a.runHTTPProbe(ctx, inputs)
}

func (a *App) scanIPWeb(ctx context.Context, ip string) ([]string, error) {
	ports, err := a.runMasscan(ctx, ip, nil)
	if err != nil {
		return nil, err
	}
	if len(ports) > 100 && isPortLiar(ctx, ip) {
		a.progress.Log("[WARN] %s 端口全开防护(masscan返回 %d 端口)，丢弃该 IP", ip, len(ports))
		return nil, nil
	}
	if len(ports) == 0 {
		return nil, nil
	}
	inputs := make([]string, 0, len(ports))
	for _, port := range ports {
		inputs = append(inputs, fmt.Sprintf("%s:%d", ip, port))
	}
	return a.runHTTPProbe(ctx, inputs)
}

func (a *App) scanCDNDomain(ctx context.Context, domain string) ([]string, error) {
	inputs := make([]string, 0, len(cdnPorts))
	for _, port := range cdnPorts {
		inputs = append(inputs, fmt.Sprintf("%s:%d", domain, port))
	}
	return a.runHTTPProbe(ctx, inputs)
}

// scanPlanForHost picks the port set for a resolved non-CDN subdomain.
// mail/mx/smtp 等前缀 → 轻量端口；其余子域：--fast 用精选 web 端口(defaultWebPorts)，
// 默认 -f 走全端口(nil → runMasscan 自动 -p-)。CDN 子域由调用方走 cdnPorts，不进这里。
func (a *App) scanPlanForHost(host string) (string, []int) {
	if isLowValueSubdomain(host) {
		return "mail-light", lowValueSubdomainPorts
	}
	if a.opts.FastScan {
		return "default-web", defaultWebPorts
	}
	return "full", nil
}

func (a *App) runMasscan(ctx context.Context, ip string, scanPorts []int) ([]int, error) {
	outputFile := filepath.Join(a.workspace.RuntimeDir, fmt.Sprintf("masscan_%s.json", safeName(ip)))
	defer os.Remove(outputFile)

	rate := a.opts.Threads * 10
	if rate < 100 {
		rate = 100
	}
	args := []string{ip}
	if len(scanPorts) > 0 {
		args = append(args, "-p", joinPorts(scanPorts))
	} else {
		args = append(args, "-p-")
	}
	args = append(args, "-Pn", "-oJ", outputFile, "--rate", strconv.Itoa(rate))
	if err := a.runCommand(ctx, 15*time.Minute, "masscan", nil, nil, filepath.Join(a.rootDir, "lib", "masscan", "masscan"), args...); err != nil {
		return nil, err
	}

	file, err := os.Open(outputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ports := NewIntSet()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimSuffix(line, ",")
		if line == "" || line == "[" || line == "]" {
			continue
		}
		var record MasscanRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		for _, port := range record.Ports {
			ports.Add(port.Port)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	values := ports.Items()
	if len(values) > 1000 {
		values = values[:1000]
	}
	return values, nil
}

func (a *App) runHTTPProbe(ctx context.Context, inputs []string) ([]string, error) {
	inputs = trimAndDedupe(inputs)
	if len(inputs) == 0 {
		return nil, nil
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: a.httpClient.Transport,
	}

	results := NewOrderedSet()
	var mu sync.Mutex
	sem := make(chan struct{}, a.opts.Threads)
	var wg sync.WaitGroup

	for _, input := range inputs {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			u := probeSingleHTTP(ctx, client, target)
			if u != "" {
				mu.Lock()
				results.Add(u)
				mu.Unlock()
			}
		}(input)
	}
	wg.Wait()
	return results.Items(), nil
}

// firewallSignatures 防火墙/WAF 拦截页面特征
var firewallSignatures = []string{
	// 阿里云 WAF
	"cloudWaf-noSite",
	"/waf/config/",
	"adminAction",
	"我是网站管理员，我要处理此异常",
	"阿里云 Web应用防火墙",
	"阿里云WAF",
	"云盾",
	"CE-WAF-IP-MM",
	// 腾讯云 WAF
	"qcloudwaf",
	"腾讯云WAF",
	"T-Sec-WAF",
	// Cloudflare
	"cf-browser-verify",
	"cf-chl-",
	"Checking your browser",
	// Imperva
	"_Incapsula_Resource",
	"imperva",
	// 通用 WAF
	"很抱歉，您的访问请求存在异常",
	"访问请求存在异常",
	"Request Rejected",
	"Access Denied",
	"访问被拒绝",
	"请求被拦截",
	"您的IP暂时无法访问",
	"WAF",
	"Firewall",
}

// deadSignatures 无效页面特征（泛解析404、空壳、假200等）
var deadSignatures = []string{
	"页面出错了！",
}

// wafCNAMEs 常见 WAF 服务商 CNAME 特征（域名级 WAF 识别）
var wafCNAMEs = []string{
	"saaswaf.com",
	"dbappwaf.cn",
	"dbappwaf.com",
	"cloudwaf",
	"cdnwaf",
	"aliyunwaf",
	"qcloudwaf",
	"baiduwaf",
}

func isWAFCNAME(cname string) bool {
	cname = strings.ToLower(cname)
	for _, kw := range wafCNAMEs {
		if strings.Contains(cname, kw) {
			return true
		}
	}
	return false
}

// shouldSkipBody 根据状态码和响应体判定是否应丢弃该 URL。
// 返回 true 表示该 URL 为防火墙拦截页或无效页面，不应纳入结果。
func shouldSkipBody(statusCode int, body []byte) bool {
	if len(body) == 0 {
		return false
	}
	s := string(body)

	// Rule 1: Forbid_code + Node_info -> firewall（OpenResty CDN/WAF 拒绝）
	if strings.Contains(s, "Forbid_code") && strings.Contains(s, "Node_info") {
		return true
	}

	// Rule 2: verify*manu.html + CE-WAF-IP-MM -> firewall（阿里云 WAF 验证页）
	if strings.Contains(s, "manu.html") && strings.Contains(s, "CE-WAF-IP-MM") {
		return true
	}

	// Rule 3+原有: 匹配 firewall 特征列表
	for _, sig := range firewallSignatures {
		if strings.Contains(s, sig) {
			return true
		}
	}

	// Rule 4: 页面出错了！ -> dead（lightyy 泛解析 404 等）
	for _, sig := range deadSignatures {
		if strings.Contains(s, sig) {
			return true
		}
	}

	// Rule 5: 200 但 body < 200 字节 -> dead（空壳页面）
	if statusCode == 200 && len(body) < 200 {
		return true
	}

	// Rule 6: body 含 404 Not Found / Not Found 且 < 500 字节 -> dead（标题200内容404）
	if (strings.Contains(s, "404 Not Found") || strings.Contains(s, "Not Found")) && len(body) < 500 {
		return true
	}

	// Rule 7: 403 + body ≤ 150 字节 + openresty -> firewall（OpenResty 拒绝页）
	if statusCode == 403 && len(body) <= 150 && strings.Contains(s, "openresty") {
		return true
	}

	// Rule 8: 502/503 + body < 400 字节 -> dead（后端下线，资产价值为零）
	if (statusCode == 502 || statusCode == 503) && len(body) < 400 {
		return true
	}

	return false
}

func probeSingleHTTP(ctx context.Context, client *http.Client, target string) string {
	targets := make([]string, 0, 2)
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		targets = append(targets, target)
	} else {
		targets = append(targets, "https://"+target, "http://"+target)
	}
	for _, u := range targets {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		// 读取前 2KB 检测 WAF 页面，避免端口全开型 WAF 虚增 URL
		// goroutine+timeout 保护，防止服务端不发数据不断开导致死锁
		bodyReadCh := make(chan []byte, 1)
		go func() {
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			bodyReadCh <- data
		}()
		var body []byte
		select {
		case body = <-bodyReadCh:
		case <-time.After(3 * time.Second):
		}
		resp.Body.Close()
		if shouldSkipBody(resp.StatusCode, body) {
			continue
		}
		if resp.Request != nil && resp.Request.URL != nil {
			return resp.Request.URL.String()
		}
		return u
	}
	return ""
}

func (a *App) runDirscan(ctx context.Context, urls []string) ([]string, error) {
	if len(urls) == 0 {
		return nil, nil
	}
	if err := os.WriteFile(a.workspace.DirscanFile, nil, 0o644); err != nil {
		return nil, err
	}

	for idx, targetURL := range urls {
		a.progress.Log("[%.0f%%] 目录扫描 %d/%d: %s", 82.0+6.0*progressRatio(idx, len(urls)), idx+1, len(urls), targetURL)
		args := []string{"-u", targetURL, "-f", a.workspace.DirscanWordlist, "-o", a.workspace.DirscanFile}
		if err := a.runCommand(ctx, 5*time.Minute, "dirscan", nil, nil, filepath.Join(a.rootDir, "lib", "dirscan", "dirscan"), args...); err != nil {
			a.progress.Log("[WARN] dirscan 失败 %s: %v", targetURL, err)
		}
	}

	return readLines(a.workspace.DirscanFile)
}

func (a *App) runObserverWard(ctx context.Context, urlsFile string) ([]string, error) {
	updateCmd := filepath.Join(a.rootDir, "lib", "ob", "observer_ward")
	if err := a.runCommand(ctx, 5*time.Minute, "observer_ward-update", nil, nil, updateCmd, "-u"); err != nil {
		a.progress.Log("[WARN] observer_ward 更新失败，将继续尝试指纹扫描: %v", err)
	}

	// 动态超时：每 1000 条 URL 分配 6 分钟，最少 15 分钟
	urlCount := countFileLines(urlsFile)
	timeout := 15 * time.Minute
	if perURL := time.Duration(urlCount/1000) * 6 * time.Minute; perURL > timeout {
		timeout = perURL
	}
	a.progress.Log("[INFO] 指纹探测共 %d 条 URL，超时设为 %s", urlCount, timeout)

	var stdout bytes.Buffer
	if err := a.runCommand(ctx, timeout, "observer_ward-scan", &stdout, nil, updateCmd, "-f", urlsFile); err != nil {
		return nil, err
	}
	lines := splitNonEmptyLines(stdout.String())
	if err := writeLines(a.workspace.FingerFile, lines); err != nil {
		return nil, err
	}
	return lines, nil
}

func (a *App) writeWorkbook(state *State, dirscanLines, fingerLines []string) error {
	fingerRecords := parseObserverWardRecords(fingerLines)

	sheets := []Sheet{
		{Name: "子域名", Headers: []string{"子域列表"}, Rows: singleColumnRows(state.Subdomains.Items())},
		{Name: "URL", Headers: []string{"URL列表"}, Rows: singleColumnRows(state.URLs.Items())},
		{Name: "title&指纹识别", Headers: []string{"url", "name", "length", "status_code", "title", "priority"}, Rows: fingerRecordsToRows(fingerRecords)},
		{Name: "目录扫描", Headers: []string{"目录扫描结果"}, Rows: singleColumnRows(dirscanLines)},
		{Name: "c段统计", Headers: []string{"域名-c段-ip命中次数"}, Rows: singleColumnRows(state.CIDRs.Items())},
	}
	return writeWorkbook(a.workspace.ResultXLSX, sheets)
}

func (a *App) runCommand(parent context.Context, timeout time.Duration, label string, stdout io.Writer, stderr io.Writer, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = a.rootDir

	var stdoutBuf, stderrBuf bytes.Buffer
	if stdout != nil {
		cmd.Stdout = io.MultiWriter(stdout, &stdoutBuf)
	} else {
		cmd.Stdout = &stdoutBuf
	}
	if stderr != nil {
		cmd.Stderr = io.MultiWriter(stderr, &stderrBuf)
	} else {
		cmd.Stderr = &stderrBuf
	}

	a.progress.Log("[CMD] %s -> %s %s", label, name, strings.Join(args, " "))
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		start := time.Now()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				a.progress.Log("[RUNNING] %s 已运行 %s", label, time.Since(start).Round(time.Second))
			}
		}
	}()

	err := cmd.Run()
	close(done)

	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s 超时（%s）", label, timeout)
	}
	if err != nil {
		message := strings.TrimSpace(stderrBuf.String())
		if message == "" {
			message = strings.TrimSpace(stdoutBuf.String())
		}
		if message != "" {
			return fmt.Errorf("%w: %s", err, message)
		}
		return err
	}
	return nil
}

// goResolver 纯 Go DNS 解析器，TCP 连接 223.5.5.5（绕过 systemd-resolved UDP 劫持）
var goResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 3 * time.Second}
		return d.DialContext(ctx, "tcp", "223.5.5.5:53")
	},
}

func (a *App) resolveIPv4s(ctx context.Context, host string) ([]string, error) {
	dnsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ipAddrs, err := goResolver.LookupIPAddr(dnsCtx, host)
	if err != nil {
		// no such host 属于字典爆破子域不存在的正常情况，不视为错误
		if strings.Contains(err.Error(), "no such host") {
			return nil, nil
		}
		return nil, err
	}
	set := NewOrderedSet()
	for _, ipAddr := range ipAddrs {
		if ipv4 := ipAddr.IP.To4(); ipv4 != nil {
			set.Add(ipv4.String())
		}
	}
	return set.Items(), nil
}



func (a *App) isCDN(ips []string, cname string) bool {
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		for _, cidr := range a.cdnMatcher.cidrs {
			if cidr.Contains(parsed) {
				return true
			}
		}
	}

	cname = strings.TrimSuffix(strings.ToLower(cname), ".")
	for _, keyword := range a.cdnMatcher.cnameKeywords {
		if strings.Contains(cname, keyword) {
			return true
		}
	}
	return false
}


func (a *App) queryCertIPs(ctx context.Context, domain string) ([]string, error) {
	result := NewOrderedSet()
	fofaIPs, err := a.fofaQueryCert(ctx, domain)
	if err == nil {
		result.AddMany(fofaIPs)
	}
	quakeIPs, err2 := a.quakeQueryCert(ctx, domain)
	if err2 == nil {
		result.AddMany(quakeIPs)
	}
	if err != nil && err2 != nil {
		return result.Items(), fmt.Errorf("FOFA: %v; Quake: %v", err, err2)
	}
	return result.Items(), nil
}

func (a *App) fofaQuerySubdomain(ctx context.Context, domain string) ([]string, error) {
	rows, err := a.fofaSearch(ctx, fmt.Sprintf(`domain="%s"`, domain))
	if err != nil {
		return nil, err
	}
	result := NewOrderedSet()
	for _, row := range rows {
		host := cleanHost(row[0])
		if host != "" {
			result.Add(host)
		}
	}
	return result.Items(), nil
}

func (a *App) fofaQueryCert(ctx context.Context, domain string) ([]string, error) {
	rows, err := a.fofaSearch(ctx, fmt.Sprintf(`cert="%s"`, domain))
	if err != nil {
		return nil, err
	}
	result := NewOrderedSet()
	for _, row := range rows {
		if len(row) > 2 {
			if net.ParseIP(strings.TrimSpace(row[2])) != nil {
				result.Add(strings.TrimSpace(row[2]))
			}
		}
	}
	return result.Items(), nil
}

func (a *App) fofaSearch(ctx context.Context, query string) ([][]string, error) {
	if a.spaceConfig.FofaEmail == "" || a.spaceConfig.FofaKey == "" {
		return nil, errors.New("FOFA 配置缺失")
	}

	endpoint := fmt.Sprintf(
		"https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=%d&page=1&fields=host,title,ip,domain,port,server,protocol,city",
		url.QueryEscape(a.spaceConfig.FofaEmail),
		url.QueryEscape(a.spaceConfig.FofaKey),
		url.QueryEscape(encodeFofaQuery(query)),
		a.spaceConfig.FofaNum,
	)

	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Baiyan-Go/1.0")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload struct {
		Error   bool            `json:"error"`
		Errmsg  string          `json:"errmsg"`
		Results [][]interface{} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Error {
		if payload.Errmsg == "" {
			payload.Errmsg = "FOFA 查询失败"
		}
		return nil, errors.New(payload.Errmsg)
	}
	rows := make([][]string, 0, len(payload.Results))
	for _, row := range payload.Results {
		values := make([]string, len(row))
		for i, item := range row {
			values[i] = fmt.Sprint(item)
		}
		rows = append(rows, values)
	}
	return rows, nil
}

	// ——— Hunter (Qianxin) ———

	// hunterSearch queries the Hunter API and returns all matched subdomains.
	func (a *App) hunterSearch(ctx context.Context, domain string) ([]string, error) {
		if a.spaceConfig.HunterKey == "" {
			return nil, errors.New("Hunter 配置缺失")
		}

		result := NewOrderedSet()
		page := 1
		pageSize := 100
		limit := a.spaceConfig.HunterNum
		if limit <= 0 {
			limit = 1000
		}
		query := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`domain.suffix="%s"`, domain)))

		for {
			select {
			case <-ctx.Done():
				return result.Items(), ctx.Err()
			default:
			}

			endpoint := fmt.Sprintf(
				"https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=%d&is_web=1",
				url.QueryEscape(a.spaceConfig.HunterKey),
				url.QueryEscape(query),
				page,
				pageSize,
			)

			reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
			if err != nil {
				cancel()
				return result.Items(), err
			}
			req.Header.Set("User-Agent", "Baiyan-Go/1.0")

			resp, err := a.httpClient.Do(req)
			cancel()
			if err != nil {
				return result.Items(), err
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return result.Items(), err
			}

			if resp.StatusCode >= 400 {
				return result.Items(), fmt.Errorf("Hunter HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}

			var hunterResp struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
				Data    struct {
					Total int `json:"total"`
					Arr   []struct {
						Domain string `json:"domain"`
						IP     string `json:"ip"`
						Port   int    `json:"port"`
					} `json:"arr"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &hunterResp); err != nil {
				return result.Items(), fmt.Errorf("解析 Hunter 响应失败: %w", err)
			}
			if hunterResp.Code != 200 {
				msg := hunterResp.Message
				if msg == "" {
					msg = "Hunter 查询失败"
				}
				return result.Items(), errors.New(msg)
			}

			for _, item := range hunterResp.Data.Arr {
				host := cleanHost(item.Domain)
				if host != "" {
					result.Add(host)
				}
			}

			// Regex extract domains from raw response body as fallback.
			for _, match := range domainTokenRegexp.FindAllString(string(body), -1) {
				result.Add(strings.Trim(strings.ToLower(match), "."))
			}

			total := hunterResp.Data.Total
			if page*pageSize >= total || len(hunterResp.Data.Arr) == 0 {
				break
			}
			if page*pageSize >= limit {
				break
			}
			page++
			time.Sleep(1 * time.Second)
		}

		return result.Items(), nil
	}

	// hunterQuerySubdomain queries Hunter for subdomains of the given domain.
	func (a *App) hunterQuerySubdomain(ctx context.Context, domain string) ([]string, error) {
		subs, err := a.hunterSearch(ctx, domain)
		if err != nil {
			return nil, err
		}
		result := NewOrderedSet()
		for _, sub := range subs {
			host := cleanHost(sub)
			if host != "" {
				result.Add(host)
			}
		}
		return result.Items(), nil
	}


	// collectFromSpaceEngines runs the tiered fallback: quake+fofa → hunter+fofa → fofa only.
	func (a *App) collectFromSpaceEngines(ctx context.Context, domain string) ([]string, error) {
		result := NewOrderedSet()
		var quakeErr, fofaErr, hunterErr error
		var fofaSubs []string

		// Tier 1: quake + fofa 并行
		var wg sync.WaitGroup
		var quakeSubs []string
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := a.quakeQuerySubdomain(ctx, domain)
			quakeSubs = subs
			quakeErr = err
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := a.fofaQuerySubdomain(ctx, domain)
			fofaSubs = subs
			fofaErr = err
		}()
		wg.Wait()

		if quakeErr == nil {
			result.AddMany(quakeSubs)
			result.AddMany(fofaSubs)
			return result.Items(), nil
		}
		a.progress.Log("[FALLBACK] Quake 不可用 (%v)，降级尝试 Hunter + FOFA", quakeErr)

		// Tier 2: hunter + fofa
		hunterSubs, hunterErr := a.hunterQuerySubdomain(ctx, domain)
		if hunterErr == nil {
			result.AddMany(hunterSubs)
			result.AddMany(fofaSubs)
			return result.Items(), nil
		}
		a.progress.Log("[FALLBACK] Hunter 不可用 (%v)，降级仅 FOFA", hunterErr)

		// Tier 3: fofa only
		if fofaErr == nil && len(fofaSubs) > 0 {
			result.AddMany(fofaSubs)
			return result.Items(), nil
		}

		// Tier 4: all failed
		return nil, fmt.Errorf("所有空间引擎不可用: Quake=%v, Hunter=%v, FOFA=%v", quakeErr, hunterErr, fofaErr)
	}
func (a *App) quakeQuerySubdomain(ctx context.Context, domain string) ([]string, error) {
	rows, err := a.quakeSearch(ctx, fmt.Sprintf(`domain="%s"`, domain))
	if err != nil {
		return nil, err
	}
	result := NewOrderedSet()
	for _, row := range rows {
		if value, ok := row["domain"].(string); ok {
			result.Add(value)
		}
	}
	return result.Items(), nil
}

func (a *App) quakeQueryCert(ctx context.Context, domain string) ([]string, error) {
	rows, err := a.quakeSearch(ctx, fmt.Sprintf(`cert="%s"`, domain))
	if err != nil {
		return nil, err
	}
	result := NewOrderedSet()
	for _, row := range rows {
		if value, ok := row["ip"].(string); ok {
			if net.ParseIP(value) != nil {
				result.Add(value)
			}
		}
	}
	return result.Items(), nil
}

func (a *App) quakeSearch(ctx context.Context, query string) ([]map[string]interface{}, error) {
	if a.spaceConfig.QuakeToken == "" {
		return nil, errors.New("Quake 配置缺失")
	}

	payload := map[string]interface{}{
		"query": query,
		"start": 0,
		"size":  a.spaceConfig.QuakeNum,
	}
	body, _ := json.Marshal(payload)
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, quakeSearchURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-QuakeToken", a.spaceConfig.QuakeToken)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Quake HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var response quakeEnvelope
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, err
	}
	if !response.Code.IsSuccess() {
		if response.Message == "" {
			if code := response.Code.String(); code != "" {
				response.Message = fmt.Sprintf("Quake 查询失败，code=%s", code)
			} else {
				response.Message = "Quake 查询失败"
			}
		}
		return nil, errors.New(response.Message)
	}

	rows, err := decodeQuakeRows(response.Data)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (a *App) targetPercent(targetIndex, targetTotal int, phaseProgress float64) float64 {
	if targetTotal <= 0 {
		return 0
	}
	base := 5.0 + (70.0/float64(targetTotal))*float64(targetIndex)
	share := 70.0 / float64(targetTotal)
	return math.Min(80.0, base+share*phaseProgress)
}

func (p *Progress) Log(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prefix := time.Now().Format("15:04:05")
	fmt.Printf("%s %s\n", prefix, fmt.Sprintf(format, args...))
}

func NewOrderedSet() *OrderedSet {
	return &OrderedSet{
		items: make([]string, 0),
		seen:  map[string]struct{}{},
	}
}

func (s *OrderedSet) Add(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if _, ok := s.seen[value]; ok {
		return false
	}
	s.seen[value] = struct{}{}
	s.items = append(s.items, value)
	return true
}

func (s *OrderedSet) AddMany(values []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	added := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := s.seen[value]; ok {
			continue
		}
		s.seen[value] = struct{}{}
		s.items = append(s.items, value)
		added = append(added, value)
	}
	return added
}

func (s *OrderedSet) Items() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.items))
	copy(out, s.items)
	return out
}

func (s *OrderedSet) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

type IntSet struct {
	items []int
	seen  map[int]struct{}
}

func NewIntSet() *IntSet {
	return &IntSet{items: make([]int, 0), seen: map[int]struct{}{}}
}

func (s *IntSet) Add(value int) bool {
	if value <= 0 {
		return false
	}
	if _, ok := s.seen[value]; ok {
		return false
	}
	s.seen[value] = struct{}{}
	s.items = append(s.items, value)
	return true
}

func (s *IntSet) Items() []int {
	out := make([]int, len(s.items))
	copy(out, s.items)
	sort.Ints(out)
	return out
}

type targetKind int

const (
	targetUnknown targetKind = iota
	targetDomain
	targetIP
	targetCIDR
)

func classifyTarget(value string) targetKind {
	value = strings.TrimSpace(value)
	if value == "" {
		return targetUnknown
	}
	if strings.Contains(value, "/") {
		if _, _, err := net.ParseCIDR(value); err == nil {
			return targetCIDR
		}
	}
	if ip := net.ParseIP(value); ip != nil {
		return targetIP
	}
	if strings.Contains(value, ".") {
		return targetDomain
	}
	return targetUnknown
}

func readTargets(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	set := NewOrderedSet()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		set.Add(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return set.Items(), nil
}

func countFileLines(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	lines := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return trimAndDedupe(lines), nil
}

func writeLines(path string, lines []string) error {
	lines = trimAndDedupe(lines)
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func trimAndDedupe(lines []string) []string {
	set := NewOrderedSet()
	set.AddMany(lines)
	return set.Items()
}

func splitNonEmptyLines(content string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return trimAndDedupe(lines)
}

func singleColumnRows(lines []string) [][]string {
	rows := make([][]string, 0, len(lines))
	for _, line := range lines {
		rows = append(rows, []string{line})
	}
	return rows
}

func fingerRecordsToRows(records []FingerRecord) [][]string {
	rows := make([][]string, 0, len(records))
	for _, record := range records {
		rows = append(rows, []string{
			record.URL,
			record.Name,
			record.Length,
			record.StatusCode,
			record.Title,
			record.Priority,
		})
	}
	return rows
}

func parseObserverWardRecords(lines []string) []FingerRecord {
	records := make([]FingerRecord, 0)
	var current strings.Builder

	flush := func() {
		raw := strings.TrimSpace(current.String())
		current.Reset()
		if raw == "" {
			return
		}
		record, ok := parseObserverWardRecord(raw)
		if ok {
			records = append(records, record)
		}
	}

	for _, line := range lines {
		clean := strings.TrimSpace(ansiRegexp.ReplaceAllString(line, ""))
		if clean == "" {
			continue
		}
		if strings.HasPrefix(clean, "[ ") {
			flush()
			current.WriteString(clean)
			continue
		}
		if current.Len() == 0 {
			continue
		}
		current.WriteString("\n")
		current.WriteString(clean)
		if clean == "]" {
			flush()
		}
	}
	flush()
	return records
}

func parseObserverWardRecord(raw string) (FingerRecord, bool) {
	if !strings.HasPrefix(raw, "[") || !strings.HasSuffix(strings.TrimSpace(raw), "]") {
		return FingerRecord{}, false
	}
	content := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(raw), "["), "]"))
	parts := strings.SplitN(content, "|", 5)
	if len(parts) != 5 {
		return FingerRecord{}, false
	}

	url := strings.TrimSpace(parts[0])
	name := strings.TrimSpace(parts[1])
	length := strings.TrimSpace(parts[2])
	statusCode := strings.TrimSpace(parts[3])
	title := strings.TrimSpace(parts[4])

	name = strings.TrimPrefix(name, "[")
	name = strings.TrimSuffix(name, "]")
	name = strings.ReplaceAll(name, `"`, "")

	title = strings.ReplaceAll(title, "\n", " ")
	title = strings.Join(strings.Fields(title), " ")

	return FingerRecord{
		URL:        url,
		Name:       name,
		Length:     length,
		StatusCode: statusCode,
		Title:      title,
		Priority:   "",
	}, true
}

// ——— 实时写入 txt，防止数据丢失 ———

func (a *App) appendLines(path string, lines []string) {
	if len(lines) == 0 {
		return
	}
	a.fileMu.Lock()
	defer a.fileMu.Unlock()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	for _, line := range lines {
		f.WriteString(line + "\n")
	}
}

func (a *App) addSubdomains(state *State, items []string) {
	added := state.Subdomains.AddMany(items)
	a.appendLines(a.workspace.SubdomainsFile, added)
}

func (a *App) addURLs(state *State, items []string) {
	added := state.URLs.AddMany(items)
	a.appendLines(a.workspace.URLsFile, added)
}

func (a *App) addCIDRs(state *State, items []string) {
	added := state.CIDRs.AddMany(items)
	a.appendLines(a.workspace.CIDRFile, added)
}

func safeName(value string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", ".", "_", " ", "_")
	return replacer.Replace(value)
}

func progressRatio(index, total int) float64 {
	if total <= 0 {
		return 1
	}
	return float64(index+1) / float64(total)
}

func isInternalIP(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsPrivate()
}

func buildCIDRLines(target string, ips []string) []string {
	counts := map[string]int{}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		ipv4 := parsed.To4()
		if ipv4 == nil {
			continue
		}
		key := fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
		counts[key]++
	}
	keys := make([]string, 0, len(counts))
	for key, count := range counts {
		if count >= 3 {
			keys = append(keys, fmt.Sprintf("%s-%s-%d", target, key, count))
		}
	}
	sort.Strings(keys)
	return keys
}

func cleanHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			return parsed.Hostname()
		}
	}
	host := value
	if strings.Contains(host, ":") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			return parsedHost
		}
		host = strings.Split(host, ":")[0]
	}
	return strings.TrimSpace(host)
}

func isLowValueSubdomain(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	label := host
	if idx := strings.Index(label, "."); idx >= 0 {
		label = label[:idx]
	}
	for _, prefix := range lowValueSubdomainPrefixes {
		if strings.HasPrefix(label, prefix) {
			return true
		}
	}
	return false
}

func joinPorts(values []int) string {
	values = uniqueIntSlice(values)
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

func uniqueIntSlice(values []int) []int {
	set := NewIntSet()
	for _, value := range values {
		set.Add(value)
	}
	return set.Items()
}

func cidrRange(value string) (uint32, uint32, error) {
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return 0, 0, err
	}
	start := ipv4ToUint32(ip.Mask(network.Mask))
	maskSize, bits := network.Mask.Size()
	if bits != 32 {
		return 0, 0, fmt.Errorf("暂不支持 IPv6 CIDR: %s", value)
	}
	size := uint32(1 << uint32(bits-maskSize))
	end := start + size - 1
	return start, end, nil
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	value := big.NewInt(0).SetBytes(ip)
	return uint32(value.Uint64())
}

func uint32ToIPv4(value uint32) string {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)).String()
}

// ——— checkpoint persistence ———

func (a *App) checkpointPath() string {
	return filepath.Join(a.workspace.ExternalDir, "checkpoint.json")
}

func (a *App) loadCheckpoint() (*Checkpoint, error) {
	data, err := os.ReadFile(a.checkpointPath())
	if err != nil {
		return nil, err
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("解析 checkpoint 失败: %w", err)
	}
	if cp.Version != checkpointVersion {
		return nil, fmt.Errorf("checkpoint 版本不兼容: %d (当前 %d)", cp.Version, checkpointVersion)
	}
	return &cp, nil
}

func (a *App) saveCheckpoint(targets []string, lastIdx int, lastTarget string, phase TargetPhase, domCtx *domainContext, cidrCtx *cidrContext) error {
	cpTargets := targets
	if cpTargets == nil {
		cpTargets = a.targets
	}
	cp := &Checkpoint{
		Version:      checkpointVersion,
		TargetsFile:  a.opts.TargetsFile,
		Targets:      cpTargets,
		Options: checkpointOpts{
			CertScan:           a.opts.CertScan,
			DirScan:            a.opts.DirScan,
			FastScan:           a.opts.FastScan,
			NoFinger:           a.opts.NoFinger,
			Threads:            a.opts.Threads,
			MasscanConcurrency: a.opts.MasscanConcurrency,
		},
		LastTargetIdx: lastIdx,
		LastTarget:    lastTarget,
		Phase:         phase,
		DomainCtx:     domCtx,
		CIDRCtx:       cidrCtx,
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := a.checkpointPath() + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, a.checkpointPath())
}

func (a *App) clearCheckpoint() {
	os.Remove(a.checkpointPath())
}

func (a *App) canResumeFrom(cp *Checkpoint, newTargets []string) bool {
	if cp.TargetsFile != a.opts.TargetsFile {
		a.progress.Log("[CHECKPOINT] 目标文件变更，忽略断点")
		return false
	}
	if !stringSlicesEqual(cp.Targets, newTargets) {
		a.progress.Log("[CHECKPOINT] 目标列表变更，忽略断点")
		return false
	}
	if cp.Options.FastScan != a.opts.FastScan {
		a.progress.Log("[CHECKPOINT] --fast 选项变更，忽略断点")
		return false
	}
	if cp.Options.Threads != a.opts.Threads || cp.Options.MasscanConcurrency != a.opts.MasscanConcurrency {
		a.progress.Log("[CHECKPOINT] 线程/并发参数已变更，将使用新值")
	}
	return true
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
