import { getJSON, postJSON, patchJSON, http } from './http';
import type { PageData } from './assets';

export type URLAuthorizationRule = {
  protocol: 'http' | 'https' | 'both';
  include_subdomains: boolean;
  include_root: boolean;
  ports: number[];
};

export type ScopeTarget = {
  url_rule?: URLAuthorizationRule | null;
  id?: number;
  target_type: 'domain' | 'ip' | 'cidr' | 'url' | 'company';
  match_mode: 'include' | 'exclude';
  coverage_mode: 'exact' | 'subdomains';
  value: string;
};

export type Scope = {
  id: number;
  project_id: number;
  name: string;
  status: 'active' | 'inactive';
  authorized_by: string;
  valid_from: string;
  valid_until: string;
  is_default: boolean;
  targets: ScopeTarget[];
};

export type TaskTemplateTaskType =
  | 'passive_intel'
  | 'dns'
  | 'ct_log'
  | 'port_probe'
  | 'web_probe'
  | 'fingerprint'
  | 'dirscan'
  | 'org_intel'
  | 'cloud_sync'
  | 'import';

export type TaskTemplate = {
  id: number;
  project_id: number;
  name: string;
  task_type: TaskTemplateTaskType;
  scope_id: number;
  config: {
    inheritance?: {
      source_run_id: number;
      parent_scope_id: number;
      parent_fingerprint?: string;
      evidence: Array<{ observation_id: number; hash: string; observed_at: string }>;
    };
    targets: Array<{ type: string; value: string }>;
    options: {
      profile?: 'subdomain_passive' | 'resolve';
      sources?: string[];
      record_types?: Array<'A' | 'AAAA' | 'CNAME'>;
      max_results?: number;
      ports?: string;
      node_id?: string;
      blueprint_key?: string;
      blueprint_version?: string;
      blueprint_step_key?: string;
      blueprint_scope_id?: number;
      depends_on?: string[];
      target_selection?: string;
    };
  };
  schedule: string;
  enabled: boolean;
  timeout_seconds: number;
  rate_limit: number;
  concurrency: number;
  retry_limit: number;
};

export type TaskRun = {
  id: number;
  project_id: number;
  template_id: number;
  scope_id: number;
  task_type: TaskTemplateTaskType;
  status: 'pending' | 'running' | 'success' | 'partial_success' | 'failed' | 'cancelled';
  progress: number;
  timeout_seconds?: number;
  concurrency?: number;
  attempt?: number;
  engine_job_id?: string;
  result_count?: number;
  last_callback_at?: string;
  error_summary?: string;
  started_at?: string;
  finished_at?: string;
};

export type Exposure = {
  id: number;
  project_id: number;
  asset_id: number;
  exposure_type: 'port' | 'service' | 'web' | 'certificate' | 'cloud_config';
  name: string;
  value: string;
  protocol: string;
  port: number;
  service: string;
  version: string;
  url: string;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
};

export type BlueprintRiskLevel = 'passive' | 'active' | 'mixed';

export type BlueprintStepDefaults = {
  timeout_seconds: number;
  rate_limit: number;
  concurrency: number;
  retry_limit: number;
};

export type DiscoveryBlueprintStep = {
  key: string;
  name: string;
  description: string;
  task_type: TaskTemplateTaskType;
  engine_route: 'passive' | 'active';
  required_target_types: ScopeTarget['target_type'][];
  depends_on: string[];
  defaults: BlueprintStepDefaults;
};

export type DiscoveryBlueprint = {
  key: string;
  version: string;
  name: string;
  description: string;
  category: string;
  risk_level: BlueprintRiskLevel;
  required_target_types: ScopeTarget['target_type'][];
  steps: DiscoveryBlueprintStep[];
};

export type BlueprintPreviewIssue = {
  code: string;
  message: string;
  step_key?: string;
};

export type DiscoveryBlueprintPreview = {
  execution_mode: 'preview_only';
  blueprint: DiscoveryBlueprint;
  project_status: string;
  scope_selection: 'explicit' | 'project_default' | 'only_compatible';
  scope: {
    id: number;
    name: string;
    status: Scope['status'];
    valid_from: string;
    valid_until: string;
    target_types: ScopeTarget['target_type'][];
  };
  ready: boolean;
  issues: BlueprintPreviewIssue[];
  steps: Array<{
    target_count?: number;
    batch_count?: number;
    target_examples?: string[];
    targets_truncated?: boolean;
    step: DiscoveryBlueprintStep;
    ready: boolean;
    issues: BlueprintPreviewIssue[];
  }>;
  notice: string;
};

export type BlueprintTemplateMaterialization = {
  execution_mode: 'templates_only';
  target_count?: number;
  blueprint_key: string;
  version: string;
  scope_id: number;
  created_count: number;
  existing_count: number;
  templates: Array<{
    step_key: string;
    batch_index?: number;
    batch_count?: number;
    target_count?: number;
    created: boolean;
    template: TaskTemplate;
  }>;
  notice: string;
};

function normalizeDiscoveryBlueprintStep(step: DiscoveryBlueprintStep): DiscoveryBlueprintStep {
  return {
    ...step,
    required_target_types: Array.isArray(step.required_target_types) ? step.required_target_types : [],
    depends_on: Array.isArray(step.depends_on) ? step.depends_on : []
  };
}

function normalizeDiscoveryBlueprint(blueprint: DiscoveryBlueprint): DiscoveryBlueprint {
  return {
    ...blueprint,
    required_target_types: Array.isArray(blueprint.required_target_types) ? blueprint.required_target_types : [],
    steps: Array.isArray(blueprint.steps) ? blueprint.steps.map(normalizeDiscoveryBlueprintStep) : []
  };
}

function normalizeDiscoveryBlueprintPreview(preview: DiscoveryBlueprintPreview): DiscoveryBlueprintPreview {
  return {
    ...preview,
    blueprint: normalizeDiscoveryBlueprint(preview.blueprint),
    scope: {
      ...preview.scope,
      target_types: Array.isArray(preview.scope.target_types) ? preview.scope.target_types : []
    },
    issues: Array.isArray(preview.issues) ? preview.issues : [],
    steps: Array.isArray(preview.steps)
      ? preview.steps.map((item) => ({
        ...item,
        step: normalizeDiscoveryBlueprintStep(item.step),
        issues: Array.isArray(item.issues) ? item.issues : []
      }))
      : []
  };
}

function normalizeScopeTarget(target: ScopeTarget): ScopeTarget {
  return {
    ...target,
    coverage_mode: target.coverage_mode === 'subdomains' ? 'subdomains' : 'exact'
  };
}

function normalizeScope(scope: Scope): Scope {
  return {
    ...scope,
    is_default: Boolean(scope.is_default),
    targets: Array.isArray(scope.targets) ? scope.targets.map(normalizeScopeTarget) : []
  };
}

export type ScopeInput = {
  name: string;
  status: 'active' | 'inactive';
  authorized_by: string;
  valid_from: string;
  valid_until: string;
  is_default: boolean;
  targets: ScopeTarget[];
};

export type DiscoveryListOptions = {
  pageNumber?: number;
  pageSize?: number;
  signal?: globalThis.AbortSignal;
};

export async function listScopes(projectId: number, options: DiscoveryListOptions = {}) {
  const result = await getJSON<PageData<Scope>>(`/projects/${projectId}/scopes`, {
    page_size: options.pageSize ?? 50,
    page_number: options.pageNumber ?? 1
  }, options.signal);
  return {
    ...result,
    items: Array.isArray(result.items) ? result.items.map(normalizeScope) : []
  };
}

export async function listDiscoveryBlueprints(projectId: number, options: DiscoveryListOptions = {}) {
  const result = await getJSON<PageData<DiscoveryBlueprint>>(`/projects/${projectId}/discovery/blueprints`, {
    page_size: options.pageSize ?? 100,
    page_number: options.pageNumber ?? 1
  }, options.signal);
  return {
    ...result,
    items: Array.isArray(result.items) ? result.items.map(normalizeDiscoveryBlueprint) : []
  };
}

export async function previewDiscoveryBlueprint(projectId: number, blueprintKey: string, scopeId?: number) {
  const result = await postJSON<DiscoveryBlueprintPreview>(
    `/projects/${projectId}/discovery/blueprints/${encodeURIComponent(blueprintKey)}/preview`,
    scopeId ? { scope_id: scopeId } : {}
  );
  return normalizeDiscoveryBlueprintPreview(result);
}

export async function createBlueprintTemplates(projectId: number, blueprintKey: string, scopeId: number) {
  const result = await postJSON<BlueprintTemplateMaterialization>(
    `/projects/${projectId}/discovery/blueprints/${encodeURIComponent(blueprintKey)}/templates`,
    { scope_id: scopeId }
  );
  return { ...result, templates: Array.isArray(result.templates) ? result.templates : [] };
}

export async function createScope(projectId: number, input: ScopeInput) {
  return normalizeScope(await postJSON<Scope>(`/projects/${projectId}/scopes`, input));
}

export type UpdateScopeInput = Partial<ScopeInput>;

export async function updateScope(projectId: number, scopeId: number, input: UpdateScopeInput) {
  return normalizeScope(await patchJSON<Scope>(`/projects/${projectId}/scopes/${scopeId}`, input));
}

export function updateScopeStatus(projectId: number, scopeId: number, status: Scope['status']) {
  return updateScope(projectId, scopeId, { status });
}

export function listTaskTemplates(projectId: number, options: DiscoveryListOptions = {}) {
  return getJSON<PageData<TaskTemplate>>(`/projects/${projectId}/discovery/templates`, {
    page_size: options.pageSize ?? 50,
    page_number: options.pageNumber ?? 1
  }, options.signal);
}

export function triggerTaskRun(projectId: number, templateId: number) {
  return postJSON<TaskRun>(`/projects/${projectId}/discovery/templates/${templateId}/runs`);
}

export function listTaskRuns(projectId: number, options: DiscoveryListOptions = {}) {
  return getJSON<PageData<TaskRun>>(`/projects/${projectId}/discovery/runs`, {
    page_size: options.pageSize ?? 20,
    page_number: options.pageNumber ?? 1
  }, options.signal);
}

export function cancelTaskRun(projectId: number, runId: number) {
  return postJSON<TaskRun>(`/projects/${projectId}/discovery/runs/${runId}/cancel`);
}

export function listExposures(projectId: number, exposureType?: string, options: DiscoveryListOptions = {}) {
  return getJSON<PageData<Exposure>>(`/projects/${projectId}/exposures`, {
    page_size: options.pageSize ?? 20,
    page_number: options.pageNumber ?? 1,
    exposure_type: exposureType
  }, options.signal);
}

export type CreateTemplateInput = {
  name: string;
  task_type: 'passive_intel' | 'dns' | 'port_probe' | 'web_probe' | 'fingerprint';
  scope_id: number;
  config: TaskTemplate['config'];
  schedule?: string;
  enabled?: boolean;
  timeout_seconds: number;
  rate_limit: number;
  concurrency: number;
  retry_limit?: number;
};

export type UpdateTemplateInput = {
  name?: string;
  config?: TaskTemplate['config'];
  schedule?: string;
  timeout_seconds?: number;
  rate_limit?: number;
  concurrency?: number;
  retry_limit?: number;
};

export function createTemplate(projectId: number, input: CreateTemplateInput) {
  return postJSON<TaskTemplate>(`/projects/${projectId}/discovery/templates`, input);
}

export function updateTemplate(projectId: number, templateId: number, input: UpdateTemplateInput) {
  return patchJSON<TaskTemplate>(`/projects/${projectId}/discovery/templates/${templateId}`, input);
}

export function toggleTemplate(projectId: number, templateId: number, enabled: boolean) {
  return patchJSON<TaskTemplate>(`/projects/${projectId}/discovery/templates/${templateId}/enabled`, { enabled });
}

export function deleteTemplate(projectId: number, templateId: number) {
  return http.delete(`/projects/${projectId}/discovery/templates/${templateId}`);
}

export function getTaskRun(projectId: number, runId: number, signal?: globalThis.AbortSignal) {
  return getJSON<TaskRun>(`/projects/${projectId}/discovery/runs/${runId}`, undefined, signal);
}

export type DerivedTarget = {
  observation_id: number;
  target_type: 'domain' | 'ip' | 'url';
  value: string;
  status: 'inherited' | 'pending' | 'excluded' | 'blocked';
  reason: string;
  provider: string;
  observed_at: string;
  evidence_hash: string;
};
export type DerivedTargetPage = {
  source_run_id: number;
  parent_scope_id: number;
  parent_scope_name: string;
  scope_fingerprint: string;
  valid_until: string;
  parent_active: boolean;
  source_complete: boolean;
  items: DerivedTarget[];
  next_cursor: number;
};
export function listDerivedTargets(projectId: number, runId: number, afterId = 0, signal?: globalThis.AbortSignal) {
  return getJSON<DerivedTargetPage>(`/projects/${projectId}/discovery/runs/${runId}/derived-targets`, { after_id: afterId }, signal);
}
export function createContinuation(projectId: number, runId: number, input: { task_type: string; observation_ids: number[]; scope_fingerprint: string }) {
  return postJSON<TaskTemplate>(`/projects/${projectId}/discovery/runs/${runId}/continuations`, input);
}
export function authorizeDerivedTargets(projectId: number, runId: number, input: { observation_ids: number[]; scope_fingerprint: string; reason: string }) {
  return postJSON<Scope>(`/projects/${projectId}/discovery/runs/${runId}/derived-targets/authorize`, input);
}
