import { getJSON, patchJSON, postJSON, putJSON } from './http';
import type { Role } from '../auth/permissions';
import type { PageData } from './assets';

export type PlatformUserStatus = 'active' | 'disabled';
export type PlatformRole = Extract<Role, 'system_admin' | 'security_admin'>;

export type PlatformUser = {
  id: number;
  username: string;
  name: string;
  email: string;
  phone?: string;
  department?: string;
  role: PlatformRole | null;
  project_count: number;
  status: PlatformUserStatus;
  last_login_at?: string;
  must_change_password: boolean;
  created_at: string;
  updated_at: string;
};

export type PlatformUserInput = {
  username: string;
  name: string;
  email: string;
  phone?: string;
  department?: string;
  role: PlatformRole | null;
  status: PlatformUserStatus;
  password: string;
};

export type AdminRole = {
  value: Role;
  label: string;
  scope: 'tenant' | 'project';
  permissions: string[];
};

export type PlatformUserTransitionInput = {
  status: PlatformUserStatus;
  reason: string;
};

export type TenantRoleUpdateInput = {
  role: PlatformRole | null;
};

export type PlatformUserUpdate = Partial<Pick<PlatformUserInput, 'name' | 'email' | 'phone' | 'department'>>;

export type PlatformUserProject = {
  id: number;
  project_code: string;
  name: string;
  role: Exclude<Role, PlatformRole>;
  status: string;
  updated_at: string;
};

export function listPlatformUsers(
  pageNumber = 1,
  pageSize = 20,
  filters: { q?: string; status?: PlatformUserStatus; role?: PlatformRole | 'none' } = {}
) {
  return getJSON<PageData<PlatformUser>>('/admin/users', {
    page_number: pageNumber,
    page_size: pageSize,
    ...(filters.q ? { q: filters.q } : {}),
    ...(filters.status ? { status: filters.status } : {}),
    ...(filters.role ? { role: filters.role } : {})
  });
}

export function listAdminRoles() {
  return getJSON<AdminRole[]>('/admin/roles');
}

export function createPlatformUser(input: PlatformUserInput) {
  return postJSON<PlatformUser>('/admin/users', input);
}

export function updatePlatformUser(userId: number, input: PlatformUserUpdate) {
  return patchJSON<PlatformUser>(`/admin/users/${userId}`, input);
}

export function transitionPlatformUserStatus(userId: number, input: PlatformUserTransitionInput) {
  return postJSON<PlatformUser>(`/admin/users/${userId}/transitions`, input);
}

export function resetPlatformUserCredential(userId: number, temporaryPassword: string) {
  return postJSON<{ user_id: number; must_change_password: true }>(`/admin/users/${userId}/password-reset`, {
    temporary_password: temporaryPassword
  });
}

export function updatePlatformUserTenantRole(userId: number, input: TenantRoleUpdateInput) {
  return putJSON<{ user_id: number; role: PlatformRole | null }>(`/admin/users/${userId}/tenant-role`, input);
}

export function listPlatformUserProjects(userId: number) {
  return getJSON<{ items: PlatformUserProject[] }>(`/admin/users/${userId}/projects`);
}
