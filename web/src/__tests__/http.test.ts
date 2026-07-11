import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import { ApiError, getJSON } from '../api/http';
import { server } from '../test/server';

describe('http client', () => {
  it('unwraps standard success envelopes', async () => {
    server.use(http.get('/api/v1/projects/1/ping', () => HttpResponse.json({ request_id: 'req-1', data: { ok: true } })));
    await expect(getJSON<{ ok: boolean }>('/projects/1/ping')).resolves.toEqual({ ok: true });
  });

  it('throws ApiError from standard error envelopes', async () => {
    server.use(
      http.get('/api/v1/projects/1/forbidden', () =>
        HttpResponse.json(
          { request_id: 'req-2', error: { code: 'FORBIDDEN', message: 'permission denied' } },
          { status: 403 }
        )
      )
    );
    await expect(getJSON('/projects/1/forbidden')).rejects.toMatchObject({
      code: 'FORBIDDEN',
      status: 403,
      requestId: 'req-2'
    } satisfies Partial<ApiError>);
  });
});
