import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

function renderDiscovery() {
  localStorage.setItem(
    'asm.auth',
    JSON.stringify({
      user: { id: 'u1', name: 'Alice', role: 'project_owner', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [
        Permission.AssetRead,
        Permission.ScopeRead,
        Permission.ScopeWrite,
        Permission.DiscoveryRead,
        Permission.DiscoveryRun,
        Permission.ExposureRead,
        Permission.ReportRead
      ]
    })
  );
  return render(
    <MemoryRouter initialEntries={['/discovery']}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('DiscoveryPage', () => {
  beforeEach(() => {
    server.use(
      http.get('/api/v1/projects/1/discovery/scopes', () =>
        HttpResponse.json({
          request_id: 'req-scopes',
          data: {
            items: [
              {
                id: 1,
                project_id: 1,
                name: 'Public perimeter',
                status: 'active',
                authorized_by: 'CISO',
                valid_from: '2026-07-01T00:00:00Z',
                valid_until: '2026-08-01T00:00:00Z',
                targets: [{ id: 1, target_type: 'domain', match_type: 'include', value: 'example.com' }]
              }
            ],
            total: 1,
            page_size: 50,
            page_number: 1
          }
        })
      ),
      http.post('/api/v1/projects/1/discovery/scopes', async ({ request }) => {
        const body = (await request.json()) as { name: string; target_value?: string };
        return HttpResponse.json({
          request_id: 'req-create-scope',
          data: {
            id: 2,
            project_id: 1,
            name: body.name,
            status: 'active',
            authorized_by: 'CISO',
            valid_from: '2026-07-08T00:00:00Z',
            valid_until: '2026-08-08T00:00:00Z',
            targets: []
          }
        });
      }),
      http.get('/api/v1/projects/1/discovery/templates', () =>
        HttpResponse.json({
          request_id: 'req-templates',
          data: {
            items: [
              {
                id: 11,
                project_id: 1,
                name: 'Daily web discovery',
                task_type: 'web',
                scope_id: 1,
                schedule: '0 2 * * *',
                enabled: true,
                rate_limit_per_minute: 60,
                concurrency: 4
              }
            ],
            total: 1,
            page_size: 50,
            page_number: 1
          }
        })
      ),
      http.post('/api/v1/projects/1/discovery/templates/11/runs', () =>
        HttpResponse.json({
          request_id: 'req-trigger',
          data: { id: 91, project_id: 1, template_id: 11, scope_id: 1, task_type: 'web', status: 'pending', progress: 0 }
        })
      ),
      http.get('/api/v1/projects/1/discovery/runs', () =>
        HttpResponse.json({
          request_id: 'req-runs',
          data: {
            items: [
              { id: 91, project_id: 1, template_id: 11, scope_id: 1, task_type: 'web', status: 'running', progress: 35 },
              { id: 90, project_id: 1, template_id: 11, scope_id: 1, task_type: 'port', status: 'failed', progress: 100, error_summary: 'timeout' }
            ],
            total: 2,
            page_size: 20,
            page_number: 1
          }
        })
      ),
      http.post('/api/v1/projects/1/discovery/runs/91/cancel', () =>
        HttpResponse.json({
          request_id: 'req-cancel',
          data: { id: 91, project_id: 1, template_id: 11, scope_id: 1, task_type: 'web', status: 'cancelled', progress: 35 }
        })
      ),
      http.get('/api/v1/projects/1/exposures', () =>
        HttpResponse.json({
          request_id: 'req-exposures',
          data: {
            items: [
              { id: 1, project_id: 1, asset_id: 1, exposure_type: 'port', title: '443/tcp', endpoint: 'example.com:443', severity: 'info', last_seen: '2026-07-08T00:00:00Z' },
              { id: 2, project_id: 1, asset_id: 1, exposure_type: 'certificate', title: 'Certificate expiring', endpoint: 'example.com', severity: 'high', last_seen: '2026-07-08T00:00:00Z' }
            ],
            total: 2,
            page_size: 20,
            page_number: 1
          }
        })
      ),
      http.get('/api/v1/projects/1/change-events', ({ request }) => {
        const url = new URL(request.url);
        const severity = url.searchParams.get('severity') ?? 'high';
        return HttpResponse.json({
          request_id: 'req-events',
          data: {
            items: [
              {
                id: 7,
                project_id: 1,
                entity_type: url.searchParams.get('entity_type') ?? 'certificate',
                change_type: 'risk',
                severity,
                title: '证书即将过期',
                detected_at: '2026-07-08T00:00:00Z'
              }
            ],
            total: 1,
            page_size: 20,
            page_number: 1
          }
        });
      })
    );
  });

  it('renders scopes and creates a scope with validation', async () => {
    renderDiscovery();
    expect(await screen.findByText('Public perimeter')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '新建 Scope' }));
    await userEvent.type(screen.getByLabelText('名称'), 'Partner range');
    await userEvent.type(screen.getByLabelText('授权人'), 'CISO');
    await userEvent.type(screen.getByLabelText('生效时间'), '2026-07-08T00:00:00Z');
    await userEvent.type(screen.getByLabelText('失效时间'), '2026-08-08T00:00:00Z');
    await userEvent.type(screen.getByPlaceholderText('example.com'), 'partner.example.com');
    await userEvent.click(screen.getByRole('button', { name: /保\s*存/ }));

    await waitFor(() => expect(screen.queryByRole('dialog', { name: '新建 Scope' })).not.toBeInTheDocument());
  });

  it('triggers and cancels discovery runs', async () => {
    renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务' }));
    expect(screen.getByText('Daily web discovery')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '触发 Daily web discovery' }));
    await userEvent.click(await screen.findByRole('button', { name: '取消 run 91' }));

    await waitFor(() => expect(screen.getByText('timeout')).toBeInTheDocument());
  });

  it('shows exposure cards and filters change timeline', async () => {
    renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '暴露面' }));
    expect(screen.getByText('Certificate expiring')).toBeInTheDocument();
    expect(screen.getByText('certificate')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('tab', { name: '变化监控' }));
    expect(await screen.findByText('证书即将过期')).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText('事件等级'), 'critical');

    await waitFor(() => expect(screen.getAllByText('critical').length).toBeGreaterThan(1));
  });
});
