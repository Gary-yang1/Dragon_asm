import { http as httpServer, HttpResponse } from 'msw';
import { beforeEach, describe, expect, it } from 'vitest';

import { getJSON } from '../api/http';
import { server } from '../test/server';

const storageKey = 'asm.auth';

function seedSession(accessToken: string, refreshToken = 'refresh-1') {
  localStorage.setItem(
    storageKey,
    JSON.stringify({
      user: { id: 'u1', username: 'alice', displayName: 'Alice', role: 'project_owner', projectId: 1 },
      accessToken,
      refreshToken,
      permissions: []
    })
  );
}

function storedTokens() {
  const raw = localStorage.getItem(storageKey);
  return raw ? (JSON.parse(raw) as { accessToken?: string; refreshToken?: string }) : null;
}

describe('http 401 handling', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('refreshes the access token once and replays the failed request', async () => {
    seedSession('expired-token');
    let refreshCalls = 0;
    const seenAuth: string[] = [];

    server.use(
      httpServer.post('/api/v1/auth/refresh', async ({ request }) => {
        refreshCalls += 1;
        const body = (await request.json()) as { refresh_token: string };
        expect(body.refresh_token).toBe('refresh-1');
        return HttpResponse.json({
          request_id: 'r',
          data: { access_token: 'fresh-token', refresh_token: 'refresh-2' }
        });
      }),
      httpServer.get('/api/v1/projects/1/assets', ({ request }) => {
        const auth = request.headers.get('Authorization') ?? '';
        seenAuth.push(auth);
        if (auth === 'Bearer expired-token') {
          return HttpResponse.json(
            { request_id: 'r', error: { code: 'UNAUTHORIZED', message: 'authentication required' } },
            { status: 401 }
          );
        }
        return HttpResponse.json({ request_id: 'r', data: { items: [], total: 0, page_size: 20, page_number: 1 } });
      })
    );

    const page = await getJSON<{ total: number }>('/projects/1/assets');

    expect(page.total).toBe(0);
    expect(refreshCalls).toBe(1);
    expect(seenAuth).toEqual(['Bearer expired-token', 'Bearer fresh-token']);
    // The rotated refresh token must be adopted, not discarded.
    expect(storedTokens()).toMatchObject({ accessToken: 'fresh-token', refreshToken: 'refresh-2' });
  });

  it('refreshes only once for a burst of concurrent 401s', async () => {
    seedSession('expired-token');
    let refreshCalls = 0;

    server.use(
      httpServer.post('/api/v1/auth/refresh', () => {
        refreshCalls += 1;
        return HttpResponse.json({ request_id: 'r', data: { access_token: 'fresh-token', refresh_token: 'refresh-2' } });
      }),
      httpServer.get('/api/v1/projects/1/*', ({ request }) => {
        if ((request.headers.get('Authorization') ?? '') === 'Bearer expired-token') {
          return HttpResponse.json(
            { request_id: 'r', error: { code: 'UNAUTHORIZED', message: 'authentication required' } },
            { status: 401 }
          );
        }
        return HttpResponse.json({ request_id: 'r', data: { ok: true } });
      })
    );

    const results = await Promise.all([
      getJSON<{ ok: boolean }>('/projects/1/assets'),
      getJSON<{ ok: boolean }>('/projects/1/risks'),
      getJSON<{ ok: boolean }>('/projects/1/tickets')
    ]);

    expect(results.every((r) => r.ok)).toBe(true);
    expect(refreshCalls).toBe(1);
  });

  it('clears the session when the refresh token is also rejected', async () => {
    seedSession('expired-token');
    let unauthorizedEvents = 0;
    const onUnauthorized = () => {
      unauthorizedEvents += 1;
    };
    globalThis.addEventListener('asm:unauthorized', onUnauthorized);

    server.use(
      httpServer.post('/api/v1/auth/refresh', () =>
        HttpResponse.json(
          { request_id: 'r', error: { code: 'UNAUTHORIZED', message: 'refresh token expired' } },
          { status: 401 }
        )
      ),
      httpServer.get('/api/v1/projects/1/assets', () =>
        HttpResponse.json(
          { request_id: 'r', error: { code: 'UNAUTHORIZED', message: 'authentication required' } },
          { status: 401 }
        )
      )
    );

    await expect(getJSON('/projects/1/assets')).rejects.toMatchObject({ status: 401 });
    expect(storedTokens()).toBeNull();
    expect(unauthorizedEvents).toBe(1);

    globalThis.removeEventListener('asm:unauthorized', onUnauthorized);
  });

  it('does not attempt a refresh when no refresh token is stored', async () => {
    localStorage.clear();
    let refreshCalls = 0;
    server.use(
      httpServer.post('/api/v1/auth/refresh', () => {
        refreshCalls += 1;
        return HttpResponse.json({ request_id: 'r', data: { access_token: 'x' } });
      }),
      httpServer.get('/api/v1/projects/1/assets', () =>
        HttpResponse.json(
          { request_id: 'r', error: { code: 'UNAUTHORIZED', message: 'authentication required' } },
          { status: 401 }
        )
      )
    );

    await expect(getJSON('/projects/1/assets')).rejects.toMatchObject({ status: 401 });
    expect(refreshCalls).toBe(0);
  });
});
