import { getJSON, patchJSON, postJSON } from './http';
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
  available_actions?: string[];
  created_at: string;
};

// Mirrors the Go response DTO in internal/risk/handler.go. Fields the backend
// does not (yet) return are optional so a missing one renders as empty rather
// than throwing — score_factors in particular is a JSON object keyed by factor
// name, not an array.
export type RiskDetail = Risk & {
  risk_type?: string;
  score_level?: string;
  score_model_version?: string;
  score_factors?: Record<string, number>;
  scored_at?: string;
  rule_id?: string;
  source?: string;
  evidence_summary?: string;
  evidence_ref?: string;
  suppressed?: boolean;
  suppressed_until?: string;
  first_seen?: string;
  last_seen?: string;
  confirmed_at?: string;
  fixed_at?: string;
  updated_at?: string;
};

// Mirrors the Go DTO in internal/risk/handler.go. Suppression matches on
// risk_type / rule_id / asset_id — there is no generic "pattern" field; the
// console previously invented one, against an endpoint that did not exist.
export type SuppressionRule = {
  id: number;
  project_id: number;
  name: string;
  risk_type: string;
  rule_id: string;
  asset_id?: number;
  reason: string;
  expires_at: string;
  enabled: boolean;
  created_at?: string;
  created_by?: string;
};

export type SuppressionRuleInput = {
  name: string;
  risk_type?: string;
  rule_id?: string;
  asset_id?: number;
  reason: string;
  expires_at?: string;
};

export type RiskQuery = {
  projectId: number;
  pageSize: number;
  pageNumber: number;
  severity?: string;
  status?: string;
  owner?: string;
  keyword?: string;
  assetId?: number;
};

export function listRisks(query: RiskQuery) {
  return getJSON<PageData<Risk>>(`/projects/${query.projectId}/risks`, {
    page_size: query.pageSize,
    page_number: query.pageNumber,
    severity: query.severity,
    status: query.status,
    owner: query.owner,
    keyword: query.keyword,
    asset_id: query.assetId
  });
}

export function getRisk(projectId: number, riskId: number) {
  return getJSON<RiskDetail>(`/projects/${projectId}/risks/${riskId}`);
}

// Fields the backend requires depend on the action: assign needs owner and an SLA
// date, mark_fixed/reopen need a reason, and the two decision actions
// (accept / false_positive) additionally need a distinct approver plus an expiry
// or review date. See internal/risk/service.go validateTransitionInput.
export type RiskTransitionInput = {
  action: string;
  reason?: string;
  owner?: string;
  sla_due_at?: string;
  approved_by?: string;
  expires_at?: string;
  review_required_at?: string;
};

export function transitionRisk(projectId: number, riskId: number, input: RiskTransitionInput) {
  return postJSON<RiskDetail>(`/projects/${projectId}/risks/${riskId}/status-transitions`, input);
}

// requiresReason / isDecisionAction mirror the server-side rules so the form can
// ask for what the action needs instead of failing the request.
export const riskActionsRequiringReason = ['mark_fixed', 'reopen', 'accept', 'false_positive'];
export const riskDecisionActions = ['accept', 'false_positive'];

export function listSuppressionRules(projectId: number) {
  return getJSON<PageData<SuppressionRule>>(`/projects/${projectId}/risk-suppressions`, { page_size: 50, page_number: 1 });
}

export function createSuppressionRule(projectId: number, input: SuppressionRuleInput) {
  return postJSON<SuppressionRule>(`/projects/${projectId}/risk-suppressions`, input);
}

export function setSuppressionRuleEnabled(projectId: number, ruleId: number, enabled: boolean) {
  return patchJSON<{ updated: boolean }>(`/projects/${projectId}/risk-suppressions/${ruleId}/enabled`, { enabled });
}
