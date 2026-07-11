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

http.interceptors.request.use((config) => {
  const raw = localStorage.getItem('asm.auth');
  if (raw) {
    try {
      const snapshot = JSON.parse(raw) as { accessToken?: string };
      if (snapshot.accessToken) {
        config.headers.Authorization = `Bearer ${snapshot.accessToken}`;
      }
    } catch {
      localStorage.removeItem('asm.auth');
    }
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
  (error: AxiosError<ApiErrorEnvelope>) => {
    const status = error.response?.status ?? 0;
    const body = error.response?.data;
    if (status === 401) {
      localStorage.removeItem('asm.auth');
      window.dispatchEvent(new Event('asm:unauthorized'));
    }
    if (body?.error) {
      throw new ApiError(body.error.message, body.error.code, status, body.request_id, body.error.details);
    }
    throw new ApiError(error.message, 'NETWORK_ERROR', status);
  }
);

export async function getJSON<T>(url: string, params?: Record<string, unknown>) {
  return http.get<unknown, T>(url, { params });
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
