import { getJSON, postJSON } from './http';
import type { PageData } from './assets';

export type RiskSeverity = 'low' | 'medium' | 'high' | 'critical';
export type RiskStatus = 'new' | 'confirmed' | 'assigned' | 'fixing' | 'risk_accepted' | 'false_positive' | 'fixed' | 'reopened';

export type Risk = {
  id: number;
  project_id: number;
  risk_key: string;
  title: string;
  severity: RiskSeverity;
  status: RiskStatus;
  owner: string;
  business_unit: string;
  score: number;
  sla_due_at?: string;
  available_actions: string[];
  created_at: string;
};

export type RiskDetail = Risk & {
  evidence: Array<{ label: string; value: string }>;
  score_factors: Array<{ name: string; value: number; reason: string }>;
  timeline: Array<{ id: number; action: string; actor: string; at: string; note?: string }>;
  tickets: Array<{ id: number; title: string; status: string }>;
};

export type SuppressionRule = {
  id: number;
  name: string;
  pattern: string;
  expires_at: string;
  enabled: boolean;
};

export type RiskQuery = {
  projectId: number;
  pageSize: number;
  pageNumber: number;
  severity?: string;
  status?: string;
  owner?: string;
};

export function listRisks(query: RiskQuery) {
  return getJSON<PageData<Risk>>(`/projects/${query.projectId}/risks`, {
    page_size: query.pageSize,
    page_number: query.pageNumber,
    severity: query.severity,
    status: query.status,
    owner: query.owner
  });
}

export function getRisk(projectId: number, riskId: number) {
  return getJSON<RiskDetail>(`/projects/${projectId}/risks/${riskId}`);
}

export function transitionRisk(projectId: number, riskId: number, action: string, reason: string) {
  return postJSON<RiskDetail>(`/projects/${projectId}/risks/${riskId}/status-transitions`, { action, reason });
}

export function createManualRisk(projectId: number, input: { title: string; severity: RiskSeverity; owner: string; evidence: string }) {
  return postJSON<Risk>(`/projects/${projectId}/risks/manual`, input);
}

export function batchAssignRisks(projectId: number, riskIds: number[], owner: string) {
  return postJSON<{ updated: number }>(`/projects/${projectId}/risks/batch-assign`, { risk_ids: riskIds, owner });
}

export function listSuppressionRules(projectId: number) {
  return getJSON<PageData<SuppressionRule>>(`/projects/${projectId}/risk-suppressions`, { page_size: 50, page_number: 1 });
}

export function createSuppressionRule(projectId: number, input: { name: string; pattern: string; expires_at: string }) {
  return postJSON<SuppressionRule>(`/projects/${projectId}/risk-suppressions`, input);
}
