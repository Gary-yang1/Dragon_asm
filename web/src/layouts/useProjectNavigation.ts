import { useCallback, useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';

import { getProjectCapabilities } from '../api/projects';
import { useAuth } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { useProjectWorkspace } from '../projects/ProjectContext';

const pagePermissions: Record<string, Permission> = {
  overview: Permission.ReportRead,
  profile: Permission.ProjectRead,
  assets: Permission.AssetRead,
  discovery: Permission.DiscoveryRead,
  risks: Permission.RiskRead,
  tickets: Permission.TicketRead,
  reports: Permission.ReportRead,
  settings: Permission.AdminManage
};

type ProjectLocation = { projectId: number; page: string; path: string };

function parseProjectLocation(path: string): ProjectLocation | null {
  const match = path.match(/^\/projects\/([1-9]\d*)\/(overview|profile|assets|discovery|risks|tickets|reports|settings)(?:\?[^#]*)?$/);
  if (!match || !Number.isSafeInteger(Number(match[1]))) return null;
  return { projectId: Number(match[1]), page: match[2], path };
}

function readLocation(key: string): ProjectLocation | null {
  try { return parseProjectLocation(sessionStorage.getItem(key) ?? ''); } catch { return null; }
}

/** Navigation memory never supplies a project's data scope or route authorization. */
export function useProjectNavigation() {
  const location = useLocation();
  const { user } = useAuth();
  const workspace = useProjectWorkspace();
  const storageKey = `asm.projectNavigation:${user?.id ?? ''}`;
  const [saved, setSaved] = useState(() => ({ key: storageKey, value: readLocation(storageKey) }));
  const remembered = saved.key === storageKey ? saved.value : null;
  const current = parseProjectLocation(`${location.pathname}${location.search}`);
  const inPlatform = location.pathname === '/platform' || location.pathname.startsWith('/platform/');
  const auxiliaryPage = inPlatform || location.pathname === '/403';
  const projectId = current?.projectId ?? (auxiliaryPage ? remembered?.projectId ?? 0 : 0);
  const [verified, setVerified] = useState<{ projectId: number; permissions: string[] } | null>(null);
  const [error, setError] = useState('');
  const [retryKey, setRetryKey] = useState(0);

  useEffect(() => {
    if (saved.key !== storageKey) setSaved({ key: storageKey, value: readLocation(storageKey) });
  }, [saved.key, storageKey]);

  const currentPath = current?.path;
  const currentPage = current?.page;
  const permissions = workspace.capabilities?.permissions;
  useEffect(() => {
    if (!currentPath || !currentPage || workspace.loading || !permissions?.includes(pagePermissions[currentPage])) return;
    const value = parseProjectLocation(currentPath);
    setSaved({ key: storageKey, value });
    try { sessionStorage.setItem(storageKey, currentPath); } catch { /* Memory still works when storage is unavailable. */ }
  }, [currentPage, currentPath, permissions, storageKey, workspace.loading]);

  useEffect(() => {
    if (!auxiliaryPage || !projectId) { setVerified(null); setError(''); return; }
    let active = true;
    setVerified(null);
    setError('');
    void getProjectCapabilities(projectId).then((capabilities) => {
      if (active) setVerified({ projectId, permissions: capabilities.permissions });
    }).catch(() => { if (active) setError('项目菜单暂时无法加载，可重试或返回全局工作台。'); });
    return () => { active = false; };
  }, [auxiliaryPage, projectId, retryKey]);

  const clear = useCallback(() => {
    setSaved({ key: storageKey, value: null });
    try { sessionStorage.removeItem(storageKey); } catch { /* No persisted state to clear. */ }
  }, [storageKey]);
  const retry = useCallback(() => setRetryKey((value) => value + 1), []);
  const navigationPermissions = current
    ? permissions
    : verified?.projectId === projectId ? verified.permissions : undefined;
  const returnPage = remembered && navigationPermissions?.includes(pagePermissions[remembered.page])
    ? remembered.path
    : Object.entries(pagePermissions).find(([, permission]) => navigationPermissions?.includes(permission))?.[0];
  const returnPath = returnPage?.startsWith('/') ? returnPage : returnPage ? `/projects/${projectId}/${returnPage}` : undefined;

  return {
    projectId,
    inPlatform,
    permissions: navigationPermissions,
    loading: projectId > 0 && navigationPermissions === undefined,
    error: auxiliaryPage ? error : '',
    returnPath,
    clear,
    retry
  };
}
