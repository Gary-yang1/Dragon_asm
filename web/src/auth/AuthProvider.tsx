import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

import { changePasswordRequest, loginRequest, meRequest, permissionsRequest, refreshRequest } from '../api/auth';
import { Permission, Role } from './permissions';
import { sanitizeDisplayName } from '../utils/text';

type User = {
  id: string;
  username: string;
  displayName: string;
  role: Role;
  projectId: number;
  mustChangePassword: boolean;
};

type AuthState = {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  permissions: Permission[];
  loading: boolean;
  ready: boolean;
  login: (username: string, password: string) => Promise<User>;
  logout: () => void;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  refresh: () => Promise<void>;
  refreshPermissions: () => Promise<void>;
  can: (permission: Permission) => boolean;
};

const AuthContext = createContext<AuthState | null>(null);

const storageKey = 'asm.auth';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [snapshot, setSnapshot] = useState(() => readSnapshot());
  const [loading, setLoading] = useState(false);
  const [ready, setReady] = useState(snapshot === null);

  const persistSnapshot = useCallback((next: StoredSnapshot | null) => {
    if (next) {
      localStorage.setItem(storageKey, JSON.stringify(next));
    } else {
      localStorage.removeItem(storageKey);
    }
    setSnapshot(next);
  }, []);

  const logout = useCallback(() => {
    persistSnapshot(null);
    setReady(true);
  }, [persistSnapshot]);

  const login = useCallback(async (username: string, password: string) => {
    setLoading(true);
    try {
      const data = await loginRequest(username, password);
      const next = normalizeAuthPayload(data);
      persistSnapshot(next);
      setReady(true);
      return next.user;
    } finally {
      setLoading(false);
    }
  }, [persistSnapshot]);

  const changePassword = useCallback(async (currentPassword: string, newPassword: string) => {
    setLoading(true);
    try {
      await changePasswordRequest(currentPassword, newPassword);
      persistSnapshot(null);
      setReady(true);
    } finally {
      setLoading(false);
    }
  }, [persistSnapshot]);

  const refresh = useCallback(async () => {
    if (!snapshot?.refreshToken) return;
    const data = await refreshRequest(snapshot.refreshToken);
    const next = { ...snapshot, accessToken: data.access_token };
    persistSnapshot(next);
  }, [persistSnapshot, snapshot]);

  const refreshPermissions = useCallback(async () => {
    if (!snapshot?.accessToken) return;
    const data = await permissionsRequest();
    const next = { ...snapshot, permissions: data.permissions };
    persistSnapshot(next);
  }, [persistSnapshot, snapshot]);

  useEffect(() => {
    const handleUnauthorized = () => {
      persistSnapshot(null);
      setReady(true);
    };
    globalThis.addEventListener('asm:unauthorized', handleUnauthorized);
    return () => globalThis.removeEventListener('asm:unauthorized', handleUnauthorized);
  }, [persistSnapshot]);

  const accessToken = snapshot?.accessToken;

  useEffect(() => {
    if (!accessToken) {
      setReady(true);
      return;
    }
    let active = true;
    setReady(false);
    void Promise.all([permissionsRequest(), meRequest()])
      .then(([permissionData, me]) => {
        if (!active) return;
        setSnapshot((current) => {
          if (!current || current.accessToken !== accessToken) return current;
          const next = {
            ...current,
            user: {
              ...current.user,
              username: sanitizeDisplayName(me.username),
              displayName: sanitizeDisplayName(me.display_name || me.username),
              mustChangePassword: me.must_change_password
            },
            permissions: permissionData.permissions
          };
          localStorage.setItem(storageKey, JSON.stringify(next));
          return next;
        });
      })
      .catch(() => {
        if (!active || !localStorage.getItem(storageKey)) return;
        setSnapshot((current) => {
          if (!current || current.accessToken !== accessToken) return current;
          const next = { ...current, permissions: [] };
          localStorage.setItem(storageKey, JSON.stringify(next));
          return next;
        });
      })
      .finally(() => {
        if (active) setReady(true);
      });
    return () => {
      active = false;
    };
  }, [accessToken]);

  const permissions = useMemo(() => snapshot?.permissions ?? [], [snapshot?.permissions]);
  const value = useMemo<AuthState>(
    () => ({
      user: snapshot?.user ?? null,
      accessToken: snapshot?.accessToken ?? null,
      refreshToken: snapshot?.refreshToken ?? null,
      permissions,
      loading,
      ready,
      login,
      logout,
      changePassword,
      refresh,
      refreshPermissions,
      can: (permission) => hasStoredPermission(permissions, permission)
    }),
    [changePassword, loading, login, logout, permissions, ready, refresh, refreshPermissions, snapshot]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used inside AuthProvider');
  }
  return ctx;
}

type StoredSnapshot = {
  user: User;
  accessToken: string;
  refreshToken: string;
  permissions: Permission[];
};

function readSnapshot(): StoredSnapshot | null {
  const raw = localStorage.getItem(storageKey);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<StoredSnapshot> & {
      user?: Partial<User> & { name?: string; display_name?: string; project_id?: number; must_change_password?: boolean };
    };
    if (!parsed.user || !parsed.accessToken || !parsed.refreshToken) {
      localStorage.removeItem(storageKey);
      return null;
    }
    const username = sanitizeDisplayName(parsed.user.username ?? '');
    const projectId = parsed.user.projectId ?? parsed.user.project_id ?? 0;
    const role = parsed.user.role;
    const snapshot = {
      user: {
        id: parsed.user.id ?? '',
        username,
        displayName: sanitizeDisplayName(
          parsed.user.displayName ?? parsed.user.display_name ?? parsed.user.name ?? username
        ),
        role: role as Role,
        projectId,
        mustChangePassword: parsed.user.mustChangePassword ?? parsed.user.must_change_password ?? false
      },
      accessToken: parsed.accessToken,
      refreshToken: parsed.refreshToken,
      permissions: parsed.permissions ?? []
    };
    if (snapshot.user.username !== parsed.user.username || snapshot.user.displayName !== parsed.user.displayName) {
      localStorage.setItem(storageKey, JSON.stringify(snapshot));
    }
    return snapshot;
  } catch {
    localStorage.removeItem(storageKey);
    return null;
  }
}

type AuthPayload = {
  access_token: string;
  refresh_token: string;
  user: {
    id: string;
    name?: string;
    username: string;
    display_name?: string;
    displayName?: string;
    role: Role;
    project_id: number;
    permissions?: Permission[];
    must_change_password: boolean;
  };
};

function normalizeAuthPayload(data: AuthPayload): StoredSnapshot {
  const role = data.user.role;
  const username = data.user.username;
  return {
    user: {
      id: data.user.id,
      username: sanitizeDisplayName(username),
      displayName: sanitizeDisplayName(
        data.user.displayName ?? data.user.display_name ?? data.user.name ?? username
      ),
      role,
      projectId: data.user.project_id,
      mustChangePassword: data.user.must_change_password
    },
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    permissions: data.user.permissions ?? []
  };
}

function hasStoredPermission(permissions: Permission[], permission: Permission) {
  return permissions.includes(permission);
}
