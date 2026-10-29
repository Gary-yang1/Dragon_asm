import { Alert, Button, Spin } from 'antd';
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Navigate, useLocation, useParams } from 'react-router-dom';

import { getProjectCapabilities, listProjects, type ProjectCapabilities, type ProjectStatus } from '../api/projects';
import { useAuth } from '../auth/AuthProvider';
import { sessionRefreshedEvent } from '../api/http';

type ProjectWorkspaceState = {
  projectId: number;
  capabilities: ProjectCapabilities | null;
  projectStatus: ProjectStatus | null;
  loading: boolean;
  error: string;
  refresh: () => Promise<void>;
};

const ProjectWorkspaceContext = createContext<ProjectWorkspaceState | null>(null);

export function ProjectWorkspaceProvider({ children }: { children: ReactNode }) {
  const location = useLocation();
  const projectMatch = location.pathname.match(/^\/projects\/(\d+)(?:\/|$)/);
  const projectId = projectMatch ? Number(projectMatch[1]) : 0;
  const [capabilities, setCapabilities] = useState<ProjectCapabilities | null>(null);
  const [capabilityProjectId, setCapabilityProjectId] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const loadedProject = useRef(0);
  const requestSequence = useRef(0);

  const refresh = useCallback(async () => {
    const sequence = ++requestSequence.current;
    if (!projectId) {
      loadedProject.current = 0;
      setCapabilities(null);
      setCapabilityProjectId(0);
      setError('');
      setLoading(false);
      return;
    }
    if (loadedProject.current !== projectId) setLoading(true);
    setError('');
    try {
      const next = await getProjectCapabilities(projectId);
      if (sequence !== requestSequence.current) return;
      loadedProject.current = projectId;
      setCapabilities(next);
      setCapabilityProjectId(projectId);
      localStorage.setItem('asm.lastProject', String(projectId));
    } catch (err) {
      if (sequence !== requestSequence.current) return;
      loadedProject.current = 0;
      setCapabilities(null);
      setCapabilityProjectId(projectId);
      setError(err instanceof Error ? err.message : '项目权限加载失败');
    } finally {
      if (sequence === requestSequence.current) setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    void refresh();
    const refreshSessionPermissions = () => { void refresh(); };
    globalThis.addEventListener(sessionRefreshedEvent, refreshSessionPermissions);
    return () => {
      requestSequence.current += 1;
      globalThis.removeEventListener(sessionRefreshedEvent, refreshSessionPermissions);
    };
  }, [refresh]);

  const value = useMemo(() => {
    const current = capabilityProjectId === projectId;
    return {
      projectId,
      capabilities: current ? capabilities : null,
      projectStatus: current ? capabilities?.project_status ?? null : null,
      loading: projectId > 0 && (!current || loading),
      error: current ? error : '',
      refresh
    };
  }, [capabilities, capabilityProjectId, error, loading, projectId, refresh]);
  return <ProjectWorkspaceContext.Provider value={value}>{children}</ProjectWorkspaceContext.Provider>;
}

export function useProjectWorkspace() {
  const context = useContext(ProjectWorkspaceContext);
  if (!context) throw new Error('useProjectWorkspace must be used inside ProjectWorkspaceProvider');
  return context;
}

export function useProjectWorkspaceOptional() {
  return useContext(ProjectWorkspaceContext);
}

export function useProjectId() {
  const { projectId } = useParams<{ projectId: string }>();
  const parsed = Number(projectId);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error('invalid project route');
  }
  return parsed;
}

export function LegacyProjectRedirect({ page }: { page: string }) {
  const { user } = useAuth();
  const defaultProjectId = user?.projectId ?? 0;
  if (!defaultProjectId) return <Navigate to="/projects" replace />;
  return <Navigate to={`/projects/${defaultProjectId}/${page}`} replace />;
}

export function LandingRedirect() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [target, setTarget] = useState('');

  const resolve = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const page = await listProjects(1, 100);
      const lastProject = Number(localStorage.getItem('asm.lastProject'));
      const lastIsVisible = Number.isSafeInteger(lastProject) && page.items.some((project) => project.id === lastProject);
      if (lastIsVisible) {
        setTarget(`/projects/${lastProject}/overview`);
      } else if (page.items.length === 1) {
        setTarget(`/projects/${page.items[0].id}/overview`);
      } else if (page.items.length > 1) {
        setTarget('/workspace');
      } else {
        setTarget('/projects');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : '项目列表加载失败');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void resolve();
  }, [resolve]);

  if (loading) return <div className="route-loading"><Spin size="large" /></div>;
  if (error) return <div className="route-error"><Alert type="error" showIcon message={error} action={<Button onClick={() => void resolve()}>重试</Button>} /></div>;
  return <Navigate to={target || '/projects'} replace />;
}
