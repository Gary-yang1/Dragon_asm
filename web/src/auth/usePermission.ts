import { useAuth } from './AuthProvider';
import { Permission, hasPermission } from './permissions';
import { useProjectWorkspaceOptional } from '../projects/ProjectContext';

export function usePermission() {
  const { permissions } = useAuth();
  const workspace = useProjectWorkspaceOptional();
  const effectivePermissions = workspace?.projectId
    ? (workspace.capabilities?.permissions as Permission[] | undefined) ?? []
    : permissions;
  return {
    permissions: effectivePermissions,
    loading: workspace?.projectId ? workspace.loading : false,
    can: (permission: Permission) => hasPermission(effectivePermissions, permission)
  };
}
