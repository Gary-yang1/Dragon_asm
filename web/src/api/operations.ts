import { getJSON, postJSON, putJSON } from './http';
import type { PageData } from './assets';

// Mirrors the Go response DTO in internal/ticket/handler.go. Fields the backend
// does not return are optional so a missing one renders empty rather than
// throwing; note the backend sends due_at, not sla_due_at.
export type Ticket = {
  id: number;
  project_id?: number;
  title: string;
  status: 'open' | 'assigned' | 'in_progress' | 'pending_retest' | 'resolved' | 'closed' | 'rejected' | 'cancelled' | 'extended';
  assignee: string;
  business_unit?: string;
  priority?: 'urgent' | 'high' | 'medium' | 'low';
  due_at?: string;
  risk_count?: number;
  available_actions?: string[];
  created_at?: string;
};

export type TicketDetail = Ticket & {
  description?: string;
  resolution?: string;
  retest_result?: string;
  external_ticket_id?: string;
  closed_at?: string;
  updated_at?: string;
};

type DashboardLegacySummary = {
  risk_total: number;
  mttr_hours: number;
  sla_rate: number;
  recurrence_rate: number;
  trend: Array<{
    date: string;
    risks: number;
    fixed: number;
  }>;
};

export type DashboardReport = {
  risk: {
    total: number;
    open: number;
    critical: number;
    high: number;
    overdue: number;
    fixed: number;
  };
  ticket: {
    total: number;
    open: number;
    overdue: number;
    closed: number;
  };
  exposure: {
    total: number;
    ports: number;
    web: number;
    expiring_certs: number;
  };
  trend?: Array<{
    day: string;
    new: number;
    fixed: number;
  }>;
} & Partial<DashboardLegacySummary>;

export type ReportTrendPoint = {
  day: string;
  new: number;
  fixed: number;
};

export type ReportRemediation = {
  total_risks: number;
  fixed_risks: number;
  sla_met_risks: number;
  sla_hit_rate: number;
  mttr_hours: number;
  age_0_7: number;
  age_8_30: number;
  age_over_30: number;
  reopened_risks: number;
  recurrence_rate: number;
};

export type ReportTrend = {
  day: string;
  new: number;
  fixed: number;
};

export type ReportTrendLegacy = {
  date: string;
  risks: number;
  fixed: number;
};

export type ReportTrendResponse = ReportTrend | ReportTrendLegacy;

export type ExportTask = {
  id: number;
  report_type: string;
  status: 'pending' | 'running' | 'success' | 'failed';
  file_name?: string;
  download_url?: string;
  created_at: string;
};

export type SlaPolicy = {
  id: number;
  severity: string;
  business_unit: string;
  response_hours: number;
  resolution_hours: number;
  enabled: boolean;
};

export type NotificationRule = {
  id: number;
  name: string;
  trigger: string;
  channel: 'email' | 'webhook';
  recipients: string[];
  throttle_window: number;
  enabled: boolean;
};

export type SlaPolicyInput = Pick<SlaPolicy, 'severity' | 'business_unit' | 'response_hours' | 'resolution_hours'>;
export type NotificationRuleInput = Omit<NotificationRule, 'id'>;

export function listTickets(projectId: number, pageSize = 20, pageNumber = 1) {
  return getJSON<PageData<Ticket>>(`/projects/${projectId}/tickets`, { page_size: pageSize, page_number: pageNumber });
}

export function getTicket(projectId: number, ticketId: number) {
  return getJSON<TicketDetail>(`/projects/${projectId}/tickets/${ticketId}`);
}

export function transitionTicket(projectId: number, ticketId: number, action: string) {
  return postJSON<TicketDetail>(`/projects/${projectId}/tickets/${ticketId}/status-transitions`, { action });
}

export function submitRetest(projectId: number, ticketId: number) {
  return postJSON<TicketDetail>(`/projects/${projectId}/tickets/${ticketId}/status-transitions`, { action: 'submit_retest' });
}

export function getDashboardReport(projectId: number) {
  return getJSON<DashboardReport>(`/projects/${projectId}/reports/dashboard`);
}

export function getReportTrend(projectId: number, from?: string, to?: string) {
  return getJSON<ReportTrendResponse[]>(`/projects/${projectId}/reports/trends`, {
    ...(from ? { from } : {}),
    ...(to ? { to } : {})
  });
}

export function getReportRemediation(projectId: number) {
  return getJSON<ReportRemediation>(`/projects/${projectId}/reports/remediation`);
}

export function createExport(projectId: number, reportType: string) {
  return postJSON<ExportTask>(`/projects/${projectId}/reports/exports`, { report_type: reportType });
}

export function listExports(projectId: number, pageSize = 20, pageNumber = 1) {
  return getJSON<PageData<ExportTask>>(`/projects/${projectId}/reports/exports`, { page_size: pageSize, page_number: pageNumber });
}

export function listSlaPolicies(projectId: number) {
  return getJSON<SlaPolicy[]>(`/projects/${projectId}/sla-policies`);
}

export function saveSlaPolicy(projectId: number, input: SlaPolicyInput) {
  return putJSON<{ updated: boolean }>(`/projects/${projectId}/sla-policies`, input);
}

export function listNotificationRules(projectId: number) {
  return getJSON<NotificationRule[]>(`/projects/${projectId}/notification-rules`);
}

export function saveNotificationRule(projectId: number, input: NotificationRuleInput) {
  return postJSON<NotificationRule>(`/projects/${projectId}/notification-rules`, input);
}
