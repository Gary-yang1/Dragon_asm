import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

const risk = {
  id: 101,
  project_id: 1,
  risk_key: 'risk:exposure:101',
  title: 'Public admin panel',
  severity: 'critical',
  status: 'new',
  owner: 'alice',
  business_unit: 'platform',
  score: 96,
  sla_due_at: '2026-07-10T00:00:00Z',
  available_actions: ['confirm', 'false_positive'],
  created_at: '2026-07-08T00:00:00Z'
};

function renderRisks() {
  localStorage.setItem(
    'asm.auth',
    JSON.stringify({
      user: { id: 'u1', name: 'Alice', role: 'project_owner', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [
        Permission.AssetRead,
        Permission.RiskRead,
        Permission.RiskWrite,
        Permission.RiskAccept,
        Permission.RiskSuppress,
        Permission.TicketRead,
        Permission.ReportRead
      ]
    })
  );
  return render(
    <MemoryRouter initialEntries={['/risks']}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('RisksPage', () => {
  beforeEach(() => {
    server.use(
      http.get('/api/v1/projects/1/risks', () =>
        HttpResponse.json({
          request_id: 'req-risks',
          data: { items: [risk], total: 1, page_size: 20, page_number: 1 }
        })
      ),
      http.get('/api/v1/projects/1/risks/101', () =>
        HttpResponse.json({
          request_id: 'req-risk',
          data: {
            ...risk,
            evidence: [{ label: 'Endpoint', value: 'https://admin.example.com' }],
            score_factors: [{ name: 'internet_exposed', value: 25, reason: 'Public endpoint' }],
            timeline: [{ id: 1, action: 'created', actor: 'system', at: '2026-07-08T00:00:00Z' }],
            tickets: [{ id: 501, title: 'Fix admin panel', status: 'open' }]
          }
        })
      ),
      http.post('/api/v1/projects/1/risks/101/status-transitions', async ({ request }) => {
        const body = (await request.json()) as { action: string };
        return HttpResponse.json({
          request_id: 'req-transition',
          data: {
            ...risk,
            status: body.action === 'confirm' ? 'confirmed' : 'false_positive',
            available_actions: ['assign'],
            evidence: [{ label: 'Endpoint', value: 'https://admin.example.com' }],
            score_factors: [{ name: 'internet_exposed', value: 25, reason: 'Public endpoint' }],
            timeline: [
              { id: 1, action: 'created', actor: 'system', at: '2026-07-08T00:00:00Z' },
              { id: 2, action: body.action, actor: 'alice', at: '2026-07-08T01:00:00Z' }
            ],
            tickets: []
          }
        });
      }),
      http.post('/api/v1/projects/1/risks/manual', async ({ request }) => {
        const body = (await request.json()) as { title: string; severity: string; owner: string };
        return HttpResponse.json({
          request_id: 'req-manual',
          data: { ...risk, id: 102, title: body.title, severity: body.severity, owner: body.owner }
        });
      }),
      http.post('/api/v1/projects/1/risks/batch-assign', () =>
        HttpResponse.json({ request_id: 'req-assign', data: { updated: 1 } })
      ),
      http.get('/api/v1/projects/1/risk-suppressions', () =>
        HttpResponse.json({
          request_id: 'req-suppressions',
          data: { items: [{ id: 1, name: 'Accepted lab', pattern: 'lab-*', expires_at: '2026-08-01T00:00:00Z', enabled: true }], total: 1, page_size: 50, page_number: 1 }
        })
      ),
      http.post('/api/v1/projects/1/risk-suppressions', async ({ request }) => {
        const body = (await request.json()) as { name: string; pattern: string; expires_at: string };
        return HttpResponse.json({ request_id: 'req-suppression-create', data: { id: 2, enabled: true, ...body } });
      })
    );
  });

  it('opens risk detail and renders backend transition actions', async () => {
    renderRisks();
    await userEvent.click(await screen.findByText('Public admin panel'));

    expect(await screen.findByText('https://admin.example.com')).toBeInTheDocument();
    expect(screen.getByText('internet_exposed=25')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'confirm' }));

    expect(await screen.findByText('confirmed')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'assign' })).toBeInTheDocument();
  });

  it('supports batch assign', async () => {
    renderRisks();
    expect(await screen.findByText('Public admin panel')).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole('checkbox')[1]);
    await userEvent.click(screen.getByRole('button', { name: '批量分派' }));
    const assignDialog = await screen.findByRole('dialog', { name: '批量分派' });
    await userEvent.type(requiredField(assignDialog, 'owner'), 'bob');
    await userEvent.click(within(assignDialog).getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '批量分派' })).not.toBeInTheDocument());
  });

  it('supports manual risk creation', async () => {
    renderRisks();
    expect(await screen.findByText('Public admin panel')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '人工录入' }));
    const manualDialog = await screen.findByRole('dialog', { name: '人工录入风险' });
    await userEvent.type(requiredField(manualDialog, 'title'), 'Manual exposed admin');
    await userEvent.type(requiredField(manualDialog, 'owner'), 'carol');
    await userEvent.type(requiredField(manualDialog, 'evidence'), 'operator report');
    await userEvent.click(within(manualDialog).getByRole('button', { name: /保\s*存/ }));

    await waitFor(() => expect(screen.queryByRole('dialog', { name: '人工录入风险' })).not.toBeInTheDocument());
  });

  it('loads and creates suppression rules', async () => {
    renderRisks();
    expect(await screen.findByText('Public admin panel')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '抑制规则' }));
    expect(await screen.findByText(/Accepted lab/)).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText('名称'), 'Temporary vendor');
    await userEvent.type(screen.getByLabelText('匹配模式'), 'vendor-*');
    await userEvent.type(screen.getByLabelText('过期时间'), '2026-08-08T00:00:00Z');
    await userEvent.click(screen.getByRole('button', { name: '新增规则' }));

    await waitFor(() => expect(screen.getByText(/Temporary vendor/)).toBeInTheDocument());
  });
});

function requiredField(container: HTMLElement, id: string) {
  const field = container.querySelector(`#${id}`);
  if (!field) throw new Error(`missing field ${id}`);
  return field as HTMLElement;
}
