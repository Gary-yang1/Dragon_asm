import { ApiError } from './http';

export function errorMessage(error: unknown, fallback = '请求失败') {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return fallback;
}
