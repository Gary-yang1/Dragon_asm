import { getJSON, postJSON, patchJSON, http } from './http';
import type { PageData } from './assets';

export type ScopeTarget = {
  id?: number;
  target_type: 'domain' | 'ip' | 'cidr' | 'url';
  match_mode: 'include' | 'exclude';
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
  targets: ScopeTarget[];
};

export type TaskTemplateTaskType =
  | 'passive_intel'
  | 'dns'
  | 'ct_log'
  | 'port_probe'
  | 'web_probe'
  | 'fingerprint'
  | 'cloud_sync'
  | 'import';

export type TaskTemplate = {
  id: number;
  project_id: number;
  name: string;
  task_type: TaskTemplateTaskType;
  scope_id: number;
  config: {
    targets: Array<{ type: string; value: string }>;
    options: {
      profile: 'subdomain_passive' | 'resolve';
      sources?: string[];
      record_types?: Array<'A' | 'AAAA' | 'CNAME'>;
      max_results: number;
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
  task_type: string;
  status: 'pending' | 'running' | 'success' | 'partial_success' | 'failed' | 'cancelled';
  progress: number;
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

export type ScopeInput = {
  name: string;
  status: 'active' | 'inactive';
  authorized_by: string;
  valid_from: string;
  valid_until: string;
  targets: ScopeTarget[];
};

export type DiscoveryListOptions = {
  pageNumber?: number;
  pageSize?: number;
  signal?: globalThis.AbortSignal;
};

export function listScopes(projectId: number, options: DiscoveryListOptions = {}) {
  return getJSON<PageData<Scope>>(`/projects/${projectId}/scopes`, {
    page_size: options.pageSize ?? 50,
    page_number: options.pageNumber ?? 1
  }, options.signal);
}

export function createScope(projectId: number, input: ScopeInput) {
  return postJSON<Scope>(`/projects/${projectId}/scopes`, input);
}

export type UpdateScopeInput = Partial<ScopeInput>;

export function updateScope(projectId: number, scopeId: number, input: UpdateScopeInput) {
  return patchJSON<Scope>(`/projects/${projectId}/scopes/${scopeId}`, input);
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
  task_type: 'passive_intel' | 'dns';
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
