import type { PageData } from './assets';
import { getJSON, patchJSON, postJSON } from './http';

export type ProjectStatus = 'draft' | 'active' | 'suspended' | 'archived';

export type Project = {
  id: number;
  project_code: string;
  name: string;
  owner_user_id: string;
  business_unit: string;
  criticality: 'low' | 'medium' | 'high' | 'critical';
  status: ProjectStatus;
  description: string;
  created_at: string;
  updated_at: string;
};

export type ProjectSubject = {
  id: number;
  project_id: number;
  subject_name: string;
  subject_type: 'company' | 'government' | 'institution' | 'individual' | 'other';
  registration_code: string;
  country_code: string;
  region: string;
  is_primary: boolean;
  verification_status: 'unverified' | 'verified' | 'mismatch';
  source: string;
  verified_at?: string;
  evidence_summary: string;
};

export type ProjectDomain = {
  id: number;
  project_id: number;
  asset_id: number;
  domain: string;
  subject_id?: number;
  is_primary: boolean;
  ownership_status: 'unverified' | 'verified' | 'mismatch';
  source: string;
  evidence_summary: string;
};

export type ICPFiling = {
  id: number;
  project_id: number;
  subject_id: number;
  filing_no: string;
  filing_type: 'filing' | 'license';
  website_name: string;
  status: 'unverified' | 'valid' | 'invalid' | 'cancelled';
  approved_at?: string;
  source: string;
  verified_at?: string;
  evidence_summary: string;
  domain_profile_ids: number[];
};

export type OnboardingStatus = {
  owner_configured: boolean;
  primary_subject_configured: boolean;
  primary_domain_configured: boolean;
  valid_scope_configured: boolean;
  ready_to_activate: boolean;
  missing: string[];
};

export type ProjectCapabilities = {
  role: string;
  permissions: string[];
  can_activate: boolean;
  onboarding_missing: string[];
};

export type CreateProjectInput = Pick<Project, 'project_code' | 'name' | 'business_unit' | 'criticality' | 'description'> & {
  owner_user_id?: string;
};

export function listProjects(pageNumber = 1, pageSize = 100) {
  return getJSON<PageData<Project>>('/projects', { page_number: pageNumber, page_size: pageSize });
}

export function createProject(input: CreateProjectInput) {
  return postJSON<Project>('/projects', input);
}

export function getProject(projectId: number) {
  return getJSON<Project>(`/projects/${projectId}`);
}

export function updateProject(projectId: number, input: Partial<CreateProjectInput>) {
  return patchJSON<Project>(`/projects/${projectId}`, input);
}

export function transitionProject(projectId: number, status: Exclude<ProjectStatus, 'draft'>, reason = '') {
  return postJSON<Project>(`/projects/${projectId}/transitions`, { status, reason });
}

export function getOnboardingStatus(projectId: number) {
  return getJSON<OnboardingStatus>(`/projects/${projectId}/onboarding-status`);
}

export function getProjectCapabilities(projectId: number) {
  return getJSON<ProjectCapabilities>(`/projects/${projectId}/capabilities`);
}

export function listProjectSubjects(projectId: number) {
  return getJSON<{ items: ProjectSubject[] }>(`/projects/${projectId}/subjects`);
}

export function createProjectSubject(projectId: number, input: Omit<ProjectSubject, 'id' | 'project_id'>) {
  return postJSON<ProjectSubject>(`/projects/${projectId}/subjects`, input);
}

export function listProjectDomains(projectId: number) {
  return getJSON<{ items: ProjectDomain[] }>(`/projects/${projectId}/domains`);
}

export function createProjectDomain(projectId: number, input: Omit<ProjectDomain, 'id' | 'project_id' | 'asset_id'>) {
  return postJSON<ProjectDomain>(`/projects/${projectId}/domains`, input);
}

export function listICPFilings(projectId: number) {
  return getJSON<{ items: ICPFiling[] }>(`/projects/${projectId}/icp-filings`);
}

export function createICPFiling(projectId: number, input: Omit<ICPFiling, 'id' | 'project_id'>) {
  return postJSON<ICPFiling>(`/projects/${projectId}/icp-filings`, input);
}
