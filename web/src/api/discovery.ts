import { getJSON, postJSON } from './http';
import type { PageData } from './assets';

export type ScopeTarget = {
  id?: number;
  target_type: 'domain' | 'ip' | 'cidr' | 'url';
  match_type: 'include' | 'exclude';
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

export type TaskTemplate = {
  id: number;
  project_id: number;
  name: string;
  task_type: string;
  scope_id: number;
  schedule: string;
  enabled: boolean;
  rate_limit_per_minute: number;
  concurrency: number;
};

export type TaskRun = {
  id: number;
  project_id: number;
  template_id: number;
  scope_id: number;
  task_type: string;
  status: 'pending' | 'running' | 'success' | 'partial_success' | 'failed' | 'cancelled';
  progress: number;
  error_summary?: string;
  started_at?: string;
  finished_at?: string;
};

export type Exposure = {
  id: number;
  project_id: number;
  asset_id: number;
  exposure_type: 'port' | 'service' | 'web' | 'certificate';
  title: string;
  endpoint: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  last_seen: string;
};

export type ChangeEvent = {
  id: number;
  project_id: number;
  entity_type: string;
  change_type: 'created' | 'updated' | 'removed' | 'risk';
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  detected_at: string;
};

export type ScopeInput = {
  name: string;
  authorized_by: string;
  valid_from: string;
  valid_until: string;
  targets: ScopeTarget[];
};

export function listScopes(projectId: number) {
  return getJSON<PageData<Scope>>(`/projects/${projectId}/discovery/scopes`, { page_size: 50, page_number: 1 });
}

export function createScope(projectId: number, input: ScopeInput) {
  return postJSON<Scope>(`/projects/${projectId}/discovery/scopes`, input);
}

export function listTaskTemplates(projectId: number) {
  return getJSON<PageData<TaskTemplate>>(`/projects/${projectId}/discovery/templates`, { page_size: 50, page_number: 1 });
}

export function triggerTaskRun(projectId: number, templateId: number) {
  return postJSON<TaskRun>(`/projects/${projectId}/discovery/templates/${templateId}/runs`);
}

export function listTaskRuns(projectId: number) {
  return getJSON<PageData<TaskRun>>(`/projects/${projectId}/discovery/runs`, { page_size: 20, page_number: 1 });
}

export function cancelTaskRun(projectId: number, runId: number) {
  return postJSON<TaskRun>(`/projects/${projectId}/discovery/runs/${runId}/cancel`);
}

export function listExposures(projectId: number, exposureType?: string) {
  return getJSON<PageData<Exposure>>(`/projects/${projectId}/exposures`, { page_size: 20, page_number: 1, exposure_type: exposureType });
}

export function listChangeEvents(projectId: number, params: { entityType?: string; severity?: string }) {
  return getJSON<PageData<ChangeEvent>>(`/projects/${projectId}/change-events`, {
    page_size: 20,
    page_number: 1,
    entity_type: params.entityType,
    severity: params.severity
  });
}
