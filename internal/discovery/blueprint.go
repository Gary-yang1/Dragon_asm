//revive:disable:exported

package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	BlueprintExecutionModePreviewOnly = "preview_only"
	BlueprintExecutionModeTemplates   = "templates_only"

	BlueprintScopeSelectionExplicit       = "explicit"
	BlueprintScopeSelectionDefault        = "project_default"
	BlueprintScopeSelectionOnlyCompatible = "only_compatible"

	BlueprintRiskPassive = "passive"
	BlueprintRiskActive  = "active"
	BlueprintRiskMixed   = "mixed"

	BlueprintIssueProjectNotActive    = "PROJECT_NOT_ACTIVE"
	BlueprintIssueScopeInactive       = "SCOPE_INACTIVE"
	BlueprintIssueScopeNotStarted     = "SCOPE_NOT_STARTED"
	BlueprintIssueScopeExpired        = "SCOPE_EXPIRED"
	BlueprintIssueTargetTypeMissing   = "TARGET_TYPE_MISSING"
	BlueprintIssueEngineNotConfigured = "ENGINE_NOT_CONFIGURED"
	BlueprintIssueActiveNotEnabled    = "ACTIVE_DISCOVERY_NOT_ENABLED"
	BlueprintIssueDependencyNotReady  = "DEPENDENCY_NOT_READY"
)

var (
	ErrBlueprintNotFound         = errors.New("discovery: blueprint not found")
	ErrBlueprintScopeUnavailable = errors.New("discovery: no compatible scope for blueprint")
	ErrBlueprintScopeAmbiguous   = errors.New("discovery: multiple compatible scopes require selection")
	ErrBlueprintNotReady         = errors.New("discovery: blueprint is not ready")
	ErrBlueprintTemplateConflict = errors.New("discovery: blueprint template name conflicts with an existing template")

	blueprintKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
)

// BlueprintStepDefaults are conservative task-template defaults. Preview is
// read-only; operators can explicitly materialize a ready preview as manual
// templates without starting runs.
type BlueprintStepDefaults struct {
	TimeoutSeconds int `json:"timeout_seconds"`
	RateLimit      int `json:"rate_limit"`
	Concurrency    int `json:"concurrency"`
	RetryLimit     int `json:"retry_limit"`
}

// DiscoveryBlueprintStep describes one engine task in a curated ASM scenario.
type DiscoveryBlueprintStep struct {
	Key                 string                `json:"key"`
	Name                string                `json:"name"`
	Description         string                `json:"description"`
	TaskType            string                `json:"task_type"`
	EngineRoute         EngineRoute           `json:"engine_route"`
	RequiredTargetTypes []string              `json:"required_target_types"`
	DependsOn           []string              `json:"depends_on"`
	Defaults            BlueprintStepDefaults `json:"defaults"`
}

// DiscoveryBlueprint is a versioned, built-in discovery scenario. Catalog
// entries contain no credentials, real targets, or project-specific state.
type DiscoveryBlueprint struct {
	Key                 string                   `json:"key"`
	Version             string                   `json:"version"`
	Name                string                   `json:"name"`
	Description         string                   `json:"description"`
	Category            string                   `json:"category"`
	RiskLevel           string                   `json:"risk_level"`
	RequiredTargetTypes []string                 `json:"required_target_types"`
	Steps               []DiscoveryBlueprintStep `json:"steps"`
}

// BlueprintPreviewIssue is a machine-readable reason why a scenario or step is
// not ready. Messages contain no target values or engine configuration details.
type BlueprintPreviewIssue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	StepKey string `json:"step_key,omitempty"`
}

// BlueprintStepPreview reports current platform prerequisites for one step.
type BlueprintStepPreview struct {
	TargetCount      *int                    `json:"target_count,omitempty"`
	BatchCount       int                     `json:"batch_count,omitempty"`
	TargetExamples   []string                `json:"target_examples,omitempty"`
	TargetsTruncated bool                    `json:"targets_truncated,omitempty"`
	Step             DiscoveryBlueprintStep  `json:"step"`
	Ready            bool                    `json:"ready"`
	Issues           []BlueprintPreviewIssue `json:"issues"`
}

// BlueprintScopeSummary is the non-sensitive scope subset needed by the UI.
type BlueprintScopeSummary struct {
	ID          uint64   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	ValidFrom   string   `json:"valid_from"`
	ValidUntil  string   `json:"valid_until"`
	TargetTypes []string `json:"target_types"`
}

// BlueprintPreview is read-only. Ready means the currently visible
// prerequisites are satisfied; execution remains unavailable in preview-only
// mode and must not be interpreted as a dispatched scan.
type BlueprintPreview struct {
	ExecutionMode  string                  `json:"execution_mode"`
	Blueprint      DiscoveryBlueprint      `json:"blueprint"`
	ProjectStatus  string                  `json:"project_status"`
	ScopeSelection string                  `json:"scope_selection"`
	Scope          BlueprintScopeSummary   `json:"scope"`
	Ready          bool                    `json:"ready"`
	Issues         []BlueprintPreviewIssue `json:"issues"`
	Steps          []BlueprintStepPreview  `json:"steps"`
	Notice         string                  `json:"notice"`
}

// PreviewBlueprintInput identifies the project and authorization scope used by
// a read-only scenario preview.
type PreviewBlueprintInput struct {
	ProjectID     uint64
	ProjectStatus string
	ScopeID       uint64
	BlueprintKey  string
}

// CreateBlueprintTemplatesInput materializes a ready preview as manual task
// templates. It never creates a run or calls an engine.
type CreateBlueprintTemplatesInput struct {
	TenantID      string
	OrgID         string
	ProjectID     uint64
	ProjectStatus string
	ScopeID       uint64
	BlueprintKey  string
	ActorID       string
	Meta          AuditMeta
}

type BlueprintTemplateResult struct {
	StepKey     string        `json:"step_key"`
	BatchIndex  int           `json:"batch_index"`
	BatchCount  int           `json:"batch_count"`
	TargetCount int           `json:"target_count"`
	Created     bool          `json:"created"`
	Template    *TaskTemplate `json:"-"`
}

type BlueprintTemplateMaterialization struct {
	ExecutionMode string                    `json:"execution_mode"`
	BlueprintKey  string                    `json:"blueprint_key"`
	Version       string                    `json:"version"`
	ScopeID       uint64                    `json:"scope_id"`
	CreatedCount  int                       `json:"created_count"`
	ExistingCount int                       `json:"existing_count"`
	TargetCount   int                       `json:"target_count"`
	Templates     []BlueprintTemplateResult `json:"-"`
	Notice        string                    `json:"notice"`
}

var builtinDiscoveryBlueprints = []DiscoveryBlueprint{
	{
		Key:                 "domain_asset_inventory",
		Version:             "1.0.0",
		Name:                "域名资产盘点",
		Description:         "从授权根域名收集被动情报，并建立授权域名的 DNS 解析基线。",
		Category:            "asset_inventory",
		RiskLevel:           BlueprintRiskPassive,
		RequiredTargetTypes: []string{TargetTypeDomain},
		Steps: []DiscoveryBlueprintStep{
			{
				Key: "passive_intel", Name: "被动子域名情报", TaskType: TaskTypePassiveIntel,
				EngineRoute: EngineRoutePassive, RequiredTargetTypes: []string{TargetTypeDomain},
				Description: "通过白眼/FOFA 等已配置被动来源收集授权域名相关资产。",
				Defaults:    passiveBlueprintDefaults(),
			},
			{
				Key: "dns_baseline", Name: "DNS 解析基线", TaskType: TaskTypeDNS,
				EngineRoute: EngineRoutePassive, RequiredTargetTypes: []string{TargetTypeDomain},
				DependsOn:   []string{"passive_intel"},
				Description: "解析授权域名并形成 A、AAAA、CNAME 基线；结果驱动的子域名接力将在后续编排阶段接入。",
				Defaults:    passiveBlueprintDefaults(),
			},
		},
	},
	{
		Key:                 "enterprise_profile",
		Version:             "1.0.0",
		Name:                "企业主体画像",
		Description:         "从已授权企业名称收集主体、备案和候选根域名信息。",
		Category:            "organization_intelligence",
		RiskLevel:           BlueprintRiskPassive,
		RequiredTargetTypes: []string{TargetTypeCompany},
		Steps: []DiscoveryBlueprintStep{
			{
				Key: "org_intel", Name: "企业与备案情报", TaskType: TaskTypeOrgIntel,
				EngineRoute: EngineRoutePassive, RequiredTargetTypes: []string{TargetTypeCompany},
				Description: "收集企业主体、ICP备案与候选域名；候选域名不会自动扩展授权范围。",
				Defaults:    passiveBlueprintDefaults(),
			},
		},
	},
	{
		Key:                 "ip_exposure_baseline",
		Version:             "1.0.0",
		Name:                "IP 暴露面基线",
		Description:         "对授权 IP 执行低影响端口发现，形成端口和服务入口基线。",
		Category:            "exposure_baseline",
		RiskLevel:           BlueprintRiskActive,
		RequiredTargetTypes: []string{TargetTypeIP},
		Steps: []DiscoveryBlueprintStep{
			{
				Key: "port_probe", Name: "端口发现", TaskType: TaskTypePortProbe,
				EngineRoute: EngineRouteActive, RequiredTargetTypes: []string{TargetTypeIP},
				Description: "调用主动引擎探测授权 IP 的端口；仍受主动能力开关和执行审批约束。",
				Defaults:    activeBlueprintDefaults(),
			},
		},
	},
	{
		Key:                 "web_exposure_baseline",
		Version:             "1.0.0",
		Name:                "Web 暴露面基线",
		Description:         "按域名或 URL 授权匹配项目已有资产，自动分批完成全量只读 Web 与指纹探测。",
		Category:            "exposure_baseline",
		RiskLevel:           BlueprintRiskActive,
		RequiredTargetTypes: []string{TargetTypeURL},
		Steps: []DiscoveryBlueprintStep{
			{
				Key: "web_probe", Name: "Web 与指纹发现", TaskType: TaskTypeWebProbe,
				EngineRoute: EngineRouteActive, RequiredTargetTypes: []string{TargetTypeURL},
				Description: "调用主动引擎进行 nopoc 只读探测，收集状态、标题与技术指纹。",
				Defaults:    activeBlueprintDefaults(),
			},
		},
	},
	{
		Key:                 "asm_initial_baseline",
		Version:             "1.0.0",
		Name:                "ASM 首次全量基线",
		Description:         "面向同时包含域名和 IP 的授权范围，预览被动与主动发现组合；Web 目标沿用域名或 URL 授权。",
		Category:            "initial_baseline",
		RiskLevel:           BlueprintRiskMixed,
		RequiredTargetTypes: []string{TargetTypeDomain, TargetTypeIP, TargetTypeURL},
		Steps: []DiscoveryBlueprintStep{
			{
				Key: "passive_intel", Name: "域名被动情报", TaskType: TaskTypePassiveIntel,
				EngineRoute: EngineRoutePassive, RequiredTargetTypes: []string{TargetTypeDomain},
				Description: "收集授权域名的外部被动情报。",
				Defaults:    passiveBlueprintDefaults(),
			},
			{
				Key: "dns_baseline", Name: "DNS 解析基线", TaskType: TaskTypeDNS,
				EngineRoute: EngineRoutePassive, RequiredTargetTypes: []string{TargetTypeDomain},
				DependsOn:   []string{"passive_intel"},
				Description: "建立授权域名的 DNS 解析基线。",
				Defaults:    passiveBlueprintDefaults(),
			},
			{
				Key: "port_probe", Name: "IP 端口发现", TaskType: TaskTypePortProbe,
				EngineRoute: EngineRouteActive, RequiredTargetTypes: []string{TargetTypeIP},
				Description: "对授权 IP 执行端口发现。",
				Defaults:    activeBlueprintDefaults(),
			},
			{
				Key: "web_probe", Name: "Web 与指纹发现", TaskType: TaskTypeWebProbe,
				EngineRoute: EngineRouteActive, RequiredTargetTypes: []string{TargetTypeURL},
				DependsOn:   []string{"port_probe"},
				Description: "匹配域名或 URL 授权下的全部已有网站并分批只读探测；不会扩大子域、IP 或端口授权。",
				Defaults:    activeBlueprintDefaults(),
			},
		},
	},
}

func passiveBlueprintDefaults() BlueprintStepDefaults {
	return BlueprintStepDefaults{TimeoutSeconds: 1800, RateLimit: 200, Concurrency: 10, RetryLimit: 3}
}

func activeBlueprintDefaults() BlueprintStepDefaults {
	return BlueprintStepDefaults{
		TimeoutSeconds: 1800,
		RateLimit:      MaxActiveRateLimit,
		Concurrency:    MaxActiveConcurrency,
		RetryLimit:     3,
	}
}

// ListDiscoveryBlueprints returns defensive copies of the built-in catalog.
func ListDiscoveryBlueprints() []DiscoveryBlueprint {
	out := make([]DiscoveryBlueprint, 0, len(builtinDiscoveryBlueprints))
	for _, blueprint := range builtinDiscoveryBlueprints {
		out = append(out, cloneDiscoveryBlueprint(blueprint))
	}
	return out
}

// GetDiscoveryBlueprint returns one defensive catalog copy.
func GetDiscoveryBlueprint(key string) (DiscoveryBlueprint, error) {
	key = strings.TrimSpace(key)
	for _, blueprint := range builtinDiscoveryBlueprints {
		if blueprint.Key == key {
			return cloneDiscoveryBlueprint(blueprint), nil
		}
	}
	return DiscoveryBlueprint{}, ErrBlueprintNotFound
}

// ValidateDiscoveryBlueprintCatalog checks the immutable built-in contract. It
// is exported for tests and startup diagnostics without coupling registration
// to a database migration.
func ValidateDiscoveryBlueprintCatalog() error {
	seenBlueprints := make(map[string]struct{}, len(builtinDiscoveryBlueprints))
	for _, blueprint := range builtinDiscoveryBlueprints {
		if !blueprintKeyPattern.MatchString(blueprint.Key) ||
			strings.TrimSpace(blueprint.Version) == "" ||
			strings.TrimSpace(blueprint.Name) == "" ||
			len(blueprint.Steps) == 0 {
			return fmt.Errorf("invalid discovery blueprint %q", blueprint.Key)
		}
		if _, exists := seenBlueprints[blueprint.Key]; exists {
			return fmt.Errorf("duplicate discovery blueprint %q", blueprint.Key)
		}
		seenBlueprints[blueprint.Key] = struct{}{}
		if err := validateBlueprintTargetTypes(blueprint.RequiredTargetTypes); err != nil {
			return fmt.Errorf("blueprint %q: %w", blueprint.Key, err)
		}

		seenSteps := make(map[string]struct{}, len(blueprint.Steps))
		for _, step := range blueprint.Steps {
			if !blueprintKeyPattern.MatchString(step.Key) || strings.TrimSpace(step.Name) == "" {
				return fmt.Errorf("blueprint %q has invalid step %q", blueprint.Key, step.Key)
			}
			if _, exists := seenSteps[step.Key]; exists {
				return fmt.Errorf("blueprint %q has duplicate step %q", blueprint.Key, step.Key)
			}
			for _, dependency := range step.DependsOn {
				if _, exists := seenSteps[dependency]; !exists {
					return fmt.Errorf("blueprint %q step %q has invalid dependency %q", blueprint.Key, step.Key, dependency)
				}
			}
			seenSteps[step.Key] = struct{}{}
			if !IsDispatchableTaskType(step.TaskType) {
				return fmt.Errorf("blueprint %q step %q is not dispatchable", blueprint.Key, step.Key)
			}
			route, err := EngineRouteForTaskType(step.TaskType)
			if err != nil || route != step.EngineRoute {
				return fmt.Errorf("blueprint %q step %q has invalid engine route", blueprint.Key, step.Key)
			}
			if err := validateBlueprintTargetTypes(step.RequiredTargetTypes); err != nil {
				return fmt.Errorf("blueprint %q step %q: %w", blueprint.Key, step.Key, err)
			}
			if step.Defaults.TimeoutSeconds < 1 || step.Defaults.RateLimit < 1 ||
				step.Defaults.Concurrency < 1 || step.Defaults.RetryLimit < 0 {
				return fmt.Errorf("blueprint %q step %q has invalid defaults", blueprint.Key, step.Key)
			}
			if err := ValidateActiveTaskLimits(step.TaskType, step.Defaults.RateLimit, step.Defaults.Concurrency); err != nil {
				return fmt.Errorf("blueprint %q step %q: %w", blueprint.Key, step.Key, err)
			}
			if len(blueprintTemplateName(blueprint, step, ^uint64(0))) > maxTemplateName {
				return fmt.Errorf("blueprint %q step %q creates an overlong template name", blueprint.Key, step.Key)
			}
		}
	}
	return nil
}

func validateBlueprintTargetTypes(targetTypes []string) error {
	if len(targetTypes) == 0 {
		return errors.New("target types are required")
	}
	seen := make(map[string]struct{}, len(targetTypes))
	for _, targetType := range targetTypes {
		if !validTargetTypes[targetType] {
			return fmt.Errorf("invalid target type %q", targetType)
		}
		if _, exists := seen[targetType]; exists {
			return fmt.Errorf("duplicate target type %q", targetType)
		}
		seen[targetType] = struct{}{}
	}
	return nil
}

func cloneDiscoveryBlueprint(blueprint DiscoveryBlueprint) DiscoveryBlueprint {
	blueprint.RequiredTargetTypes = nonNilStringClone(blueprint.RequiredTargetTypes)
	blueprint.Steps = append([]DiscoveryBlueprintStep{}, blueprint.Steps...)
	for i := range blueprint.Steps {
		blueprint.Steps[i].RequiredTargetTypes = nonNilStringClone(blueprint.Steps[i].RequiredTargetTypes)
		blueprint.Steps[i].DependsOn = nonNilStringClone(blueprint.Steps[i].DependsOn)
	}
	return blueprint
}

func nonNilStringClone(values []string) []string {
	return append([]string{}, values...)
}

// PreviewDiscoveryBlueprint evaluates local prerequisites only. It never calls
// an external provider, writes templates, or dispatches a run.
func (s *Service) PreviewDiscoveryBlueprint(ctx context.Context, in PreviewBlueprintInput) (*BlueprintPreview, error) {
	if s.engineSettings != nil {
		scoped, err := s.withLatestSettings(ctx)
		if err != nil {
			return nil, err
		}
		return scoped.PreviewDiscoveryBlueprint(ctx, in)
	}

	if in.ProjectID == 0 {
		return nil, ErrInvalidProjectID
	}
	blueprint, err := GetDiscoveryBlueprint(in.BlueprintKey)
	if err != nil {
		return nil, err
	}
	scope, selection, err := s.resolveBlueprintScope(ctx, in.ProjectID, in.ScopeID, blueprint)
	if err != nil {
		return nil, err
	}

	now := s.nowFn().UTC()
	targetTypes := includedScopeTargetTypes(scope)
	preview := &BlueprintPreview{
		ExecutionMode:  BlueprintExecutionModePreviewOnly,
		Blueprint:      blueprint,
		ProjectStatus:  strings.TrimSpace(in.ProjectStatus),
		ScopeSelection: selection,
		Scope: BlueprintScopeSummary{
			ID:          scope.ID,
			Name:        scope.Name,
			Status:      scope.Status,
			ValidFrom:   blueprintTime(scope.ValidFrom),
			ValidUntil:  blueprintTime(scope.ValidUntil),
			TargetTypes: sortedTargetTypes(targetTypes),
		},
		Issues: make([]BlueprintPreviewIssue, 0),
		Steps:  make([]BlueprintStepPreview, 0, len(blueprint.Steps)),
		Notice: "预检本身不会创建任务模板、调用外部引擎或启动扫描；通过后可由操作人显式生成手动任务模板。",
	}

	if preview.ProjectStatus != "active" {
		preview.Issues = append(preview.Issues, BlueprintPreviewIssue{
			Code: BlueprintIssueProjectNotActive, Message: "项目未启用，不能执行发现任务。",
		})
	}
	switch {
	case scope.Status != StatusActive:
		preview.Issues = append(preview.Issues, BlueprintPreviewIssue{
			Code: BlueprintIssueScopeInactive, Message: "授权范围未启用。",
		})
	case now.Before(scope.ValidFrom):
		preview.Issues = append(preview.Issues, BlueprintPreviewIssue{
			Code: BlueprintIssueScopeNotStarted, Message: "授权范围尚未生效。",
		})
	case now.After(scope.ValidUntil):
		preview.Issues = append(preview.Issues, BlueprintPreviewIssue{
			Code: BlueprintIssueScopeExpired, Message: "授权范围已过期。",
		})
	}
	hasGlobalIssue := len(preview.Issues) > 0
	stepReadiness := make(map[string]bool, len(blueprint.Steps))

	for _, step := range blueprint.Steps {
		stepPreview := BlueprintStepPreview{
			Step:   step,
			Issues: make([]BlueprintPreviewIssue, 0),
		}
		missing := missingTargetTypes(step.RequiredTargetTypes, blueprintScopeTargetTypes(scope))
		if len(missing) > 0 {
			stepPreview.Issues = append(stepPreview.Issues, BlueprintPreviewIssue{
				Code:    BlueprintIssueTargetTypeMissing,
				Message: "授权范围缺少 include 目标类型：" + strings.Join(missing, "、"),
				StepKey: step.Key,
			})
		}
		if slices.Contains(step.RequiredTargetTypes, TargetTypeURL) && len(missing) == 0 {
			resolved, resolveErr := s.resolveWebBlueprintTargets(ctx, scope)
			if resolveErr != nil {
				return nil, resolveErr
			}
			count := len(resolved.URLs)
			stepPreview.TargetCount = &count
			if count > 0 {
				batches, batchErr := blueprintWebTargetBatches(blueprint, step, scope, resolved.URLs)
				if batchErr != nil {
					return nil, batchErr
				}
				stepPreview.BatchCount = len(batches)
			}
			stepPreview.TargetExamples = append([]string(nil), resolved.URLs[:min(3, count)]...)
			stepPreview.TargetsTruncated = resolved.Truncated
			if count == 0 {
				message := "项目中尚无符合当前域名或 URL 授权的具体网址。请先发现或导入域名，并检查授权的子域覆盖与排除项。"
				stepPreview.Issues = append(stepPreview.Issues, BlueprintPreviewIssue{Code: "URL_TARGETS_EMPTY", StepKey: step.Key, Message: message})
			}
		}
		if engineErr := s.validateEngineProject(scope.ProjectID, step.TaskType); engineErr != nil {
			code := BlueprintIssueEngineNotConfigured
			message := "该步骤对应的" + blueprintRouteLabel(step.EngineRoute) + "引擎未配置。"
			if errors.Is(engineErr, ErrActiveEngineProjectMapping) {
				code = "ENGINE_PROJECT_MAPPING_MISSING"
				message = "当前项目尚未绑定主动引擎项目，请到系统设置 → 引擎配置补齐项目映射。"
			}
			stepPreview.Issues = append(stepPreview.Issues, BlueprintPreviewIssue{
				Code:    code,
				Message: message,
				StepKey: step.Key,
			})
		}
		if IsActiveTaskType(step.TaskType) && !s.activePolicy.Enabled {
			stepPreview.Issues = append(stepPreview.Issues, BlueprintPreviewIssue{
				Code:    BlueprintIssueActiveNotEnabled,
				Message: "平台尚未开放主动发现任务。",
				StepKey: step.Key,
			})
		}
		for _, dependency := range step.DependsOn {
			if !stepReadiness[dependency] {
				stepPreview.Issues = append(stepPreview.Issues, BlueprintPreviewIssue{
					Code:    BlueprintIssueDependencyNotReady,
					Message: "前置步骤尚未就绪：" + dependency,
					StepKey: step.Key,
				})
			}
		}
		stepPreview.Ready = !hasGlobalIssue && len(stepPreview.Issues) == 0
		stepReadiness[step.Key] = stepPreview.Ready
		preview.Steps = append(preview.Steps, stepPreview)
		preview.Issues = append(preview.Issues, stepPreview.Issues...)
	}
	preview.Ready = len(preview.Issues) == 0
	return preview, nil
}

// CreateBlueprintTaskTemplates converts one ready preview into enabled manual
// templates. The empty schedule keeps this operation side-effect free: no run is
// created and no engine is called until an operator explicitly triggers one.
func (s *Service) CreateBlueprintTaskTemplates(
	ctx context.Context,
	in CreateBlueprintTemplatesInput,
) (*BlueprintTemplateMaterialization, error) {
	if s.engineSettings != nil {
		scoped, err := s.withLatestSettings(ctx)
		if err != nil {
			return nil, err
		}
		return scoped.CreateBlueprintTaskTemplates(ctx, in)
	}

	preview, err := s.PreviewDiscoveryBlueprint(ctx, PreviewBlueprintInput{
		ProjectID:     in.ProjectID,
		ProjectStatus: in.ProjectStatus,
		ScopeID:       in.ScopeID,
		BlueprintKey:  in.BlueprintKey,
	})
	if err != nil {
		return nil, err
	}
	if !preview.Ready {
		return nil, ErrBlueprintNotReady
	}

	scope, err := s.GetScope(ctx, in.ProjectID, preview.Scope.ID)
	if err != nil {
		return nil, err
	}
	plans := make([]blueprintTemplatePlan, 0, len(preview.Blueprint.Steps))
	for _, step := range preview.Blueprint.Steps {
		batches := [][]string{nil}
		if slices.Contains(step.RequiredTargetTypes, TargetTypeURL) {
			targets, resolveErr := s.resolveWebBlueprintTargets(ctx, scope)
			if resolveErr != nil {
				return nil, resolveErr
			}
			batches, resolveErr = blueprintWebTargetBatches(preview.Blueprint, step, scope, targets.URLs)
			if resolveErr != nil {
				return nil, resolveErr
			}
		}
		for batchIndex, resolved := range batches {
			config, configErr := blueprintTaskConfig(preview.Blueprint, step, scope, resolved)
			if configErr != nil {
				return nil, configErr
			}
			name := blueprintTemplateName(preview.Blueprint, step, scope.ID)
			if resolved != nil {
				sum := sha256.Sum256([]byte(config))
				name += fmt.Sprintf(" [%x] · %d 个网址", sum[:5], len(resolved))
			}
			prepared, prepareErr := s.prepareTaskTemplateInput(CreateTaskTemplateInput{
				TenantID:       in.TenantID,
				OrgID:          in.OrgID,
				ProjectID:      in.ProjectID,
				ScopeID:        scope.ID,
				Name:           name,
				TaskType:       step.TaskType,
				Config:         config,
				Schedule:       "",
				Enabled:        true,
				TimeoutSeconds: step.Defaults.TimeoutSeconds,
				RateLimit:      step.Defaults.RateLimit,
				Concurrency:    step.Defaults.Concurrency,
				RetryLimit:     step.Defaults.RetryLimit,
				ActorID:        in.ActorID,
				Meta:           in.Meta,
			})
			if prepareErr != nil {
				return nil, prepareErr
			}
			parsed, parseErr := parseDispatchConfig(config)
			if parseErr != nil {
				return nil, parseErr
			}
			plans = append(plans, blueprintTemplatePlan{StepKey: step.Key, BatchIndex: batchIndex + 1, BatchCount: len(batches), TargetCount: len(parsed.Targets), Input: prepared})
		}
	}

	result := &BlueprintTemplateMaterialization{}
	err = s.runInTx(ctx, func(ctx context.Context, repo Repository, txAudit auditRecorder) error {
		if _, scopeErr := repo.GetScope(ctx, in.ProjectID, scope.ID); scopeErr != nil {
			return scopeErr
		}
		existing, listErr := repo.ListTaskTemplates(ctx, in.ProjectID)
		if listErr != nil {
			return listErr
		}
		result = &BlueprintTemplateMaterialization{
			ExecutionMode: BlueprintExecutionModeTemplates,
			BlueprintKey:  preview.Blueprint.Key,
			Version:       preview.Blueprint.Version,
			ScopeID:       scope.ID,
			Templates:     make([]BlueprintTemplateResult, 0, len(plans)),
			Notice:        "已生成手动任务模板；未创建运行记录，也未调用外部引擎。",
		}
		for _, plan := range plans {
			result.TargetCount += plan.TargetCount
			if item := findMaterializedBlueprintTemplate(existing, preview.Blueprint, plan.StepKey, scope.ID, plan.Input.Config); item != nil {
				result.ExistingCount++
				result.Templates = append(result.Templates, BlueprintTemplateResult{
					StepKey: plan.StepKey, BatchIndex: plan.BatchIndex, BatchCount: plan.BatchCount, TargetCount: plan.TargetCount, Created: false, Template: item,
				})
				continue
			}
			for _, item := range existing {
				if item.Name == plan.Input.Name {
					return ErrBlueprintTemplateConflict
				}
			}

			id, createErr := repo.CreateTaskTemplate(ctx, CreateTaskTemplateParams{
				TenantID:       plan.Input.TenantID,
				OrgID:          plan.Input.OrgID,
				ProjectID:      plan.Input.ProjectID,
				ScopeID:        plan.Input.ScopeID,
				Name:           plan.Input.Name,
				TaskType:       plan.Input.TaskType,
				Config:         plan.Input.Config,
				Schedule:       plan.Input.Schedule,
				Enabled:        plan.Input.Enabled,
				TimeoutSeconds: plan.Input.TimeoutSeconds,
				RateLimit:      plan.Input.RateLimit,
				Concurrency:    plan.Input.Concurrency,
				RetryLimit:     plan.Input.RetryLimit,
				ActorID:        plan.Input.ActorID,
			})
			if createErr != nil {
				return createErr
			}
			item, getErr := repo.GetTaskTemplate(ctx, in.ProjectID, id)
			if getErr != nil {
				return getErr
			}
			if auditErr := s.recordAuditWithSink(
				ctx, txAudit, ActionTemplateCreate, nil, item, in.ActorID, in.Meta,
			); auditErr != nil {
				return auditErr
			}
			existing = append(existing, item)
			result.CreatedCount++
			result.Templates = append(result.Templates, BlueprintTemplateResult{
				StepKey: plan.StepKey, BatchIndex: plan.BatchIndex, BatchCount: plan.BatchCount, TargetCount: plan.TargetCount, Created: true, Template: item,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

type blueprintTemplatePlan struct {
	StepKey     string
	BatchIndex  int
	BatchCount  int
	TargetCount int
	Input       CreateTaskTemplateInput
}

type blueprintConfigTarget struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Keep engine batches within both the target contract and the persisted
// template's byte limit. A long URL list can hit the byte limit before 1000.
func blueprintWebTargetBatches(blueprint DiscoveryBlueprint, step DiscoveryBlueprintStep, scope *Scope, urls []string) ([][]string, error) {
	if len(urls) == 0 {
		return nil, ErrBlueprintNotReady
	}
	batches := make([][]string, 0, (len(urls)+activeAPIMaxTargets-1)/activeAPIMaxTargets)
	for offset := 0; offset < len(urls); {
		low, high, fits := 1, min(activeAPIMaxTargets, len(urls)-offset), 0
		for low <= high {
			size := low + (high-low)/2
			config, err := blueprintTaskConfig(blueprint, step, scope, urls[offset:offset+size])
			if err != nil {
				return nil, err
			}
			if len(config) <= maxTemplateConfigLen {
				fits, low = size, size+1
			} else {
				high = size - 1
			}
		}
		if fits == 0 {
			return nil, ErrInvalidTaskConfig
		}
		batches = append(batches, urls[offset:offset+fits])
		offset += fits
	}
	return batches, nil
}

func blueprintTaskConfig(
	blueprint DiscoveryBlueprint,
	step DiscoveryBlueprintStep,
	scope *Scope,
	resolvedURLs ...[]string,
) (string, error) {
	required := make(map[string]struct{}, len(step.RequiredTargetTypes))
	for _, targetType := range step.RequiredTargetTypes {
		required[targetType] = struct{}{}
	}
	targets := make([]blueprintConfigTarget, 0)
	for _, target := range scope.Targets {
		if target.MatchMode != MatchModeInclude {
			continue
		}
		if _, ok := required[target.TargetType]; !ok {
			continue
		}
		if target.TargetType == TargetTypeURL && target.URLRule != nil {
			for _, value := range scopeURLSeeds(target) {
				targets = append(targets, blueprintConfigTarget{Type: target.TargetType, Value: value})
			}
		} else {
			targets = append(targets, blueprintConfigTarget{Type: target.TargetType, Value: target.Value})
		}
	}
	if len(resolvedURLs) > 0 && resolvedURLs[0] != nil {
		filtered := targets[:0]
		for _, target := range targets {
			if target.Type != TargetTypeURL {
				filtered = append(filtered, target)
			}
		}
		targets = filtered
		for _, value := range resolvedURLs[0] {
			targets = append(targets, blueprintConfigTarget{Type: TargetTypeURL, Value: value})
		}
	}
	if len(targets) == 0 {
		return "", ErrBlueprintNotReady
	}
	slices.SortFunc(targets, func(left, right blueprintConfigTarget) int {
		return strings.Compare(left.Type+"\x00"+left.Value, right.Type+"\x00"+right.Value)
	})

	options := map[string]any{
		"blueprint_key":      blueprint.Key,
		"blueprint_version":  blueprint.Version,
		"blueprint_step_key": step.Key,
		"blueprint_scope_id": scope.ID,
		"depends_on":         nonNilStringClone(step.DependsOn),
	}
	if len(resolvedURLs) > 0 && resolvedURLs[0] != nil {
		options["target_selection"] = "project_assets_snapshot_v2"
	}
	switch step.TaskType {
	case TaskTypePassiveIntel:
		options["profile"] = "subdomain_passive"
		options["max_results"] = 1000
		options["sources"] = []string{"auto"}
	case TaskTypeDNS:
		options["profile"] = "resolve"
		options["max_results"] = 1000
		options["record_types"] = []string{"A", "AAAA", "CNAME"}
	case TaskTypeOrgIntel:
		options["profile"] = "organization_intelligence"
		options["max_results"] = 1000
	case TaskTypePortProbe:
		options["ports"] = "80,443"
	}

	payload, err := json.Marshal(struct {
		Targets []blueprintConfigTarget `json:"targets"`
		Options map[string]any          `json:"options"`
	}{Targets: targets, Options: options})
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func blueprintTemplateName(blueprint DiscoveryBlueprint, step DiscoveryBlueprintStep, scopeID uint64) string {
	return fmt.Sprintf("%s · %s [%s@%s/scope-%d]", blueprint.Name, step.Name, blueprint.Key, blueprint.Version, scopeID)
}

func findMaterializedBlueprintTemplate(
	items []*TaskTemplate,
	blueprint DiscoveryBlueprint,
	stepKey string,
	scopeID uint64,
	expectedConfig ...string,
) *TaskTemplate {
	for _, item := range items {
		if item.ScopeID != scopeID {
			continue
		}
		if len(expectedConfig) > 0 && !sameInheritanceConfig(item.Config, expectedConfig[0]) {
			continue
		}
		var config struct {
			Options map[string]any `json:"options"`
		}
		if json.Unmarshal([]byte(item.Config), &config) != nil {
			continue
		}
		if config.Options["blueprint_key"] == blueprint.Key &&
			config.Options["blueprint_version"] == blueprint.Version &&
			config.Options["blueprint_step_key"] == stepKey {
			return item
		}
	}
	return nil
}

func (s *Service) resolveBlueprintScope(
	ctx context.Context,
	projectID, requestedScopeID uint64,
	blueprint DiscoveryBlueprint,
) (*Scope, string, error) {
	if requestedScopeID != 0 {
		scope, err := s.GetScope(ctx, projectID, requestedScopeID)
		return scope, BlueprintScopeSelectionExplicit, err
	}

	scopes, err := s.ListScopes(ctx, projectID)
	if err != nil {
		return nil, "", err
	}
	now := s.nowFn().UTC()
	compatible := make([]*Scope, 0, len(scopes))
	for _, scope := range scopes {
		if !scopeCompatibleWithBlueprint(scope, blueprint, now) {
			continue
		}
		if scope.IsDefault {
			return scope, BlueprintScopeSelectionDefault, nil
		}
		compatible = append(compatible, scope)
	}
	switch len(compatible) {
	case 0:
		return nil, "", ErrBlueprintScopeUnavailable
	case 1:
		return compatible[0], BlueprintScopeSelectionOnlyCompatible, nil
	default:
		return nil, "", ErrBlueprintScopeAmbiguous
	}
}

func scopeCompatibleWithBlueprint(scope *Scope, blueprint DiscoveryBlueprint, now time.Time) bool {
	if scope == nil || scope.Status != StatusActive ||
		now.Before(scope.ValidFrom) || now.After(scope.ValidUntil) {
		return false
	}
	return len(missingTargetTypes(blueprint.RequiredTargetTypes, blueprintScopeTargetTypes(scope))) == 0
}

// Domain grants already authorize matching host URLs in scopeMatchDecision.
// This only makes that existing capability visible to scenario readiness; it
// does not change exact/subdomain coverage or authorize any new host or IP.
func blueprintScopeTargetTypes(scope *Scope) map[string]struct{} {
	types := includedScopeTargetTypes(scope)
	if _, ok := types[TargetTypeDomain]; ok {
		types[TargetTypeURL] = struct{}{}
	}
	return types
}

func includedScopeTargetTypes(scope *Scope) map[string]struct{} {
	out := make(map[string]struct{})
	if scope == nil {
		return out
	}
	for _, target := range scope.Targets {
		if target != nil && target.MatchMode == MatchModeInclude {
			out[target.TargetType] = struct{}{}
		}
	}
	return out
}

func missingTargetTypes(required []string, present map[string]struct{}) []string {
	missing := make([]string, 0, len(required))
	for _, targetType := range required {
		if _, exists := present[targetType]; !exists {
			missing = append(missing, targetType)
		}
	}
	return missing
}

func sortedTargetTypes(targetTypes map[string]struct{}) []string {
	out := make([]string, 0, len(targetTypes))
	for targetType := range targetTypes {
		out = append(out, targetType)
	}
	slices.Sort(out)
	return out
}

func blueprintRouteLabel(route EngineRoute) string {
	if route == EngineRouteActive {
		return "主动"
	}
	return "被动"
}

func blueprintTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
