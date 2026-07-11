import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

vi.mock('echarts', () => ({
  init: vi.fn(() => ({
    setOption: vi.fn(),
    dispose: vi.fn()
  }))
}));

function renderRoute(path: string) {
  localStorage.setItem(
    'asm.auth',
    JSON.stringify({
      user: { id: 'u1', name: 'Alice', role: 'system_admin', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: Object.values(Permission)
    })
  );
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('operations pages', () => {
  beforeEach(() => {
    server.use(
      http.get('/api/v1/projects/1/tickets', () =>
        HttpResponse.json({
          request_id: 'req-tickets',
          data: {
            items: [{ id: 501, title: 'Fix admin panel', status: 'open', assignee: 'bob', risk_count: 2, sla_due_at: '2026-07-10T00:00:00Z', available_actions: ['start_fixing'] }],
            total: 1,
            page_size: 20,
            page_number: 1
          }
        })
      ),
      http.get('/api/v1/projects/1/tickets/501', () =>
        HttpResponse.json({
          request_id: 'req-ticket',
          data: {
            id: 501,
            title: 'Fix admin panel',
            status: 'open',
            assignee: 'bob',
            risk_count: 2,
            available_actions: ['start_fixing'],
            risks: [{ id: 101, title: 'Public admin panel', severity: 'critical' }],
            comments: [{ id: 1, actor: 'alice', content: 'created', created_at: '2026-07-08T00:00:00Z' }]
          }
        })
      ),
      http.post('/api/v1/projects/1/tickets/501/status-transitions', async ({ request }) => {
        const body = (await request.json()) as { action: string };
        const status = body.action === 'submit_retest' ? 'pending_retest' : 'in_progress';
        return HttpResponse.json({
          request_id: body.action === 'submit_retest' ? 'req-retest' : 'req-ticket-transition',
          data: {
            id: 501,
            title: 'Fix admin panel',
            status,
            assignee: 'bob',
            risk_count: 2,
            available_actions: body.action === 'submit_retest' ? ['resolve'] : ['submit_retest'],
            risks: [{ id: 101, title: 'Public admin panel', severity: 'critical' }],
            comments: [{ id: 2, actor: 'alice', content: body.action, created_at: '2026-07-08T01:00:00Z' }]
          }
        });
      }),
      http.get('/api/v1/projects/1/reports/dashboard', () =>
        HttpResponse.json({
          request_id: 'req-report',
          data: {
            risk_total: 18,
            mttr_hours: 42,
            sla_rate: 91,
            recurrence_rate: 6,
            trend: [{ date: '2026-07-08', risks: 18, fixed: 4 }]
          }
        })
      ),
      http.get('/api/v1/projects/1/reports/exports', () =>
        HttpResponse.json({
          request_id: 'req-exports',
          data: { items: [{ id: 1, report_type: 'risk_summary', status: 'success', file_name: 'risk.csv', created_at: '2026-07-08T00:00:00Z' }], total: 1, page_size: 20, page_number: 1 }
        })
      ),
      http.post('/api/v1/projects/1/reports/exports', () =>
        HttpResponse.json({ request_id: 'req-export-create', data: { id: 2, report_type: 'sla_efficiency', status: 'pending', created_at: '2026-07-08T01:00:00Z' } })
      ),
      http.get('/api/v1/projects/1/sla-policies', () =>
        HttpResponse.json({
          request_id: 'req-sla',
          data: [{ id: 1, severity: 'critical', business_unit: 'platform', response_hours: 4, resolution_hours: 24, enabled: true }]
        })
      ),
      http.put('/api/v1/projects/1/sla-policies', async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        expect(body).toMatchObject({ severity: 'high', business_unit: 'default', response_hours: 24, resolution_hours: 72 });
        return HttpResponse.json({ request_id: 'req-sla-save', data: { updated: true } });
      }),
      http.get('/api/v1/projects/1/notification-rules', () =>
        HttpResponse.json({
          request_id: 'req-rules',
          data: [{ id: 1, name: 'Critical risk', trigger: 'risk.created', channel: 'email', recipients: ['sec@example.com'], throttle_window: 3600, enabled: true }]
        })
      ),
      http.post('/api/v1/projects/1/notification-rules', async ({ request }) => {
        const body = (await request.json()) as { name: string; recipients: string[]; throttle_window: number };
        expect(body.recipients).toEqual(['ops@example.com']);
        expect(body.throttle_window).toBe(3600);
        return HttpResponse.json({ request_id: 'req-rule-save', data: { id: 2, enabled: true, ...body } });
      })
    );
  });

  it('updates ticket state and submits retest', async () => {
    renderRoute('/tickets');
    await userEvent.click(await screen.findByText('Fix admin panel'));

    expect(await screen.findByText('Public admin panel')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'start_fixing' }));
    expect(await screen.findByText('in_progress')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '提交复测' }));
    expect(await screen.findByText('pending_retest')).toBeInTheDocument();
  });

  it('renders report dashboard and creates export task', async () => {
    renderRoute('/reports');
    expect(
      await screen.findByText('风险总量', { selector: '.page-summary-stat .ant-typography-secondary' })
    ).toBeInTheDocument();
    expect(screen.getByTestId('report-chart')).toBeInTheDocument();
    expect(await screen.findByText('risk.csv')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '异步导出' }));
    await waitFor(() => expect(screen.getByText('risk.csv')).toBeInTheDocument());
  });

  it('saves SLA and notification settings', async () => {
    renderRoute('/settings');
    expect(await screen.findByText('platform')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '保存 SLA' }));

    await userEvent.click(screen.getByRole('tab', { name: '通知规则' }));
    expect(await screen.findByText('Critical risk')).toBeInTheDocument();
    const panel = screen.getByRole('tabpanel', { name: '通知规则' });
    await userEvent.type(within(panel).getByLabelText('名称'), 'SLA due soon');
    await userEvent.type(within(panel).getByLabelText('收件人'), 'ops@example.com');
    await userEvent.click(screen.getByRole('button', { name: '保存通知' }));

    await waitFor(() => expect(screen.getByText('Critical risk')).toBeInTheDocument());
  });
});
