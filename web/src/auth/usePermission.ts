import { useAuth } from './AuthProvider';
import { Permission, hasPermission } from './permissions';
import { useProjectWorkspaceOptional } from '../projects/ProjectContext';

export function usePermission() {
  const { permissions } = useAuth();
  const workspace = useProjectWorkspaceOptional();
  const inProject = Boolean(workspace?.projectId);
  const effectivePermissions = inProject
    ? (workspace?.capabilities?.permissions as Permission[] | undefined) ?? []
    : permissions;
  return {
    permissions: effectivePermissions,
    loading: inProject ? Boolean(workspace?.loading) : false,
    // error is surfaced so callers can tell "the capability fetch failed" apart
    // from "this user genuinely lacks the permission". Both previously collapsed
    // into an empty permission set, which read as a denial.
    error: inProject ? workspace?.error ?? '' : '',
    retry: workspace?.refresh,
    can: (permission: Permission) => hasPermission(effectivePermissions, permission)
  };
}
