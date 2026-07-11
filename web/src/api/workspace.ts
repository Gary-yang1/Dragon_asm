import { getJSON } from './http';
import type { Project } from './projects';

export type WorkspaceProject = Pick<
  Project,
  'id' | 'project_code' | 'name' | 'owner_user_id' | 'business_unit' | 'criticality' | 'status' | 'updated_at'
>;

export type WorkspaceSummary = {
  projects: {
    total: number;
    active: number;
    draft: number;
    suspended: number;
  };
  assets: { total: number };
  risks: {
    open: number;
    critical_high: number;
    overdue: number;
  };
  tickets: {
    open: number;
    overdue: number;
  };
  recent_projects: WorkspaceProject[];
};

export function getWorkspaceSummary() {
  return getJSON<WorkspaceSummary>('/workspace/summary');
}
