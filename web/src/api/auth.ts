import { getJSON, postJSON } from './http';
import { Permission, Role } from '../auth/permissions';

export type LoginResponse = {
  access_token: string;
  refresh_token: string;
  user: {
    id: string;
    name?: string;
    username: string;
    display_name?: string;
    role: Role;
    project_id: number;
    permissions?: Permission[];
    must_change_password: boolean;
  };
};

export type MeResponse = {
  id: string;
  username: string;
  display_name: string;
  tenant_id: string;
  org_id: string;
  must_change_password: boolean;
};

export function loginRequest(username: string, password: string) {
  return postJSON<LoginResponse>('/auth/login', { username, password });
}

export function refreshRequest(refreshToken: string) {
  return postJSON<{ access_token: string }>('/auth/refresh', { refresh_token: refreshToken });
}

export function permissionsRequest() {
  return getJSON<{ permissions: Permission[] }>('/auth/permissions');
}

export function meRequest() {
  return getJSON<MeResponse>('/auth/me');
}

export function changePasswordRequest(currentPassword: string, newPassword: string) {
  return postJSON<{ must_change_password: false }>('/auth/password/change', {
    current_password: currentPassword,
    new_password: newPassword
  });
}
