import axios, { AxiosError } from 'axios';

export type ApiEnvelope<T> = {
  request_id: string;
  data: T;
};

export type ApiErrorEnvelope = {
  request_id: string;
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
};

export class ApiError extends Error {
  code: string;
  status: number;
  requestId?: string;
  details?: unknown;

  constructor(message: string, code: string, status: number, requestId?: string, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.requestId = requestId;
    this.details = details;
  }
}

export const http = axios.create({
  baseURL: '/api/v1',
  timeout: 15000
});

const storageKey = 'asm.auth';
const refreshPath = '/auth/refresh';

/** sessionRefreshedEvent lets AuthProvider re-read the snapshot after a silent refresh. */
export const sessionRefreshedEvent = 'asm:session-refreshed';

type TokenSnapshot = { accessToken?: string; refreshToken?: string };

function readTokens(): TokenSnapshot | null {
  const raw = localStorage.getItem(storageKey);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as TokenSnapshot;
  } catch {
    localStorage.removeItem(storageKey);
    return null;
  }
}

function persistTokens(accessToken: string, refreshToken?: string) {
  const raw = localStorage.getItem(storageKey);
  if (!raw) return;
  try {
    const snapshot = JSON.parse(raw) as Record<string, unknown>;
    snapshot.accessToken = accessToken;
    if (refreshToken) {
      snapshot.refreshToken = refreshToken;
    }
    localStorage.setItem(storageKey, JSON.stringify(snapshot));
  } catch {
    localStorage.removeItem(storageKey);
  }
}

function clearSession() {
  localStorage.removeItem(storageKey);
  globalThis.dispatchEvent(new Event('asm:unauthorized'));
}

// A single in-flight refresh is shared by every request that hit 401 at once, so
// a burst of parallel calls produces one refresh rather than N competing ones.
let refreshInFlight: Promise<string | null> | null = null;

async function refreshAccessToken(): Promise<string | null> {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      const tokens = readTokens();
      if (!tokens?.refreshToken) return null;
      try {
        // A bare axios call: going through `http` would recurse into this very
        // interceptor when the refresh itself is rejected.
        const response = await axios.post<ApiEnvelope<{ access_token: string; refresh_token?: string }>>(
          `/api/v1${refreshPath}`,
          { refresh_token: tokens.refreshToken },
          { timeout: 15000 }
        );
        const payload = response.data?.data;
        if (!payload?.access_token) return null;
        // The server rotates both tokens; storing only the access token would
        // leave the old refresh token behind and break once rotation is enforced.
        persistTokens(payload.access_token, payload.refresh_token);
        globalThis.dispatchEvent(new Event(sessionRefreshedEvent));
        return payload.access_token;
      } catch {
        return null;
      }
    })().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

http.interceptors.request.use((config) => {
  const tokens = readTokens();
  if (tokens?.accessToken) {
    config.headers.Authorization = `Bearer ${tokens.accessToken}`;
  }
  return config;
});

http.interceptors.response.use(
  (response) => {
    const body = response.data as ApiEnvelope<unknown>;
    if (body && typeof body === 'object' && 'data' in body) {
      return body.data;
    }
    return response.data;
  },
  async (error: AxiosError<ApiErrorEnvelope>) => {
    const status = error.response?.status ?? 0;
    const body = error.response?.data;
    const config = error.config as (typeof error.config & { _retriedAfterRefresh?: boolean }) | undefined;

    // An expired access token is recoverable: refresh once and replay the request,
    // so an operator mid-form is not thrown back to the login page. The refresh
    // call itself, and an already-replayed request, must not loop.
    if (
      status === 401 &&
      config &&
      !config._retriedAfterRefresh &&
      !(config.url ?? '').includes(refreshPath)
    ) {
      const token = await refreshAccessToken();
      if (token) {
        config._retriedAfterRefresh = true;
        config.headers = { ...config.headers, Authorization: `Bearer ${token}` } as typeof config.headers;
        return http.request(config);
      }
    }

    if (status === 401) {
      clearSession();
    }
    if (body?.error) {
      throw new ApiError(body.error.message, body.error.code, status, body.request_id, body.error.details);
    }
    throw new ApiError(error.message, 'NETWORK_ERROR', status);
  }
);

export async function getJSON<T>(url: string, params?: Record<string, unknown>, signal?: globalThis.AbortSignal) {
  return http.get<unknown, T>(url, { params, signal });
}

export async function postJSON<T>(url: string, data?: unknown) {
  return http.post<unknown, T>(url, data);
}

export async function putJSON<T>(url: string, data?: unknown) {
  return http.put<unknown, T>(url, data);
}

export async function patchJSON<T>(url: string, data?: unknown) {
  return http.patch<unknown, T>(url, data);
}

export async function deleteJSON<T>(url: string, data?: unknown) {
  return http.delete<unknown, T>(url, { data });
}
