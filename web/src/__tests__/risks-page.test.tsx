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

// Shaped like the Go response DTO in internal/risk/handler.go: evidence is a
// summary string, and score_factors is an object keyed by factor name.
const riskDetailFields = {
  risk_type: 'exposure',
  source: 'discovery',
  rule_id: 'RULE-ADMIN-PANEL',
  evidence_summary: 'https://admin.example.com',
  evidence_ref: 'run-7/seq-3',
  score_level: 'critical',
  score_model_version: 'v1',
  score_factors: { internet_exposed: 25 },
  first_seen: '2026-07-08T00:00:00Z',
  last_seen: '2026-07-08T01:00:00Z'
};

function renderRisks(path = '/risks') {
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
    <MemoryRouter initialEntries={[path]}>
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
          data: { ...risk, ...riskDetailFields }
        })
      ),
      http.post('/api/v1/projects/1/risks/101/status-transitions', async ({ request }) => {
        const body = (await request.json()) as { action: string };
        return HttpResponse.json({
          request_id: 'req-transition',
          data: {
            ...risk,
            ...riskDetailFields,
            status: body.action === 'confirm' ? 'confirmed' : 'false_positive',
            available_actions: ['assign']
          }
        });
      }),
      http.get('/api/v1/projects/1/risk-suppressions', () =>
        HttpResponse.json({
          request_id: 'req-suppressions',
          data: {
            items: [{
              id: 1, project_id: 1, name: 'Accepted lab', risk_type: 'high_risk_port',
              rule_id: 'RULE-0001', reason: 'lab environment', expires_at: '2026-08-01T00:00:00Z', enabled: true
            }],
            total: 1, page_size: 50, page_number: 1
          }
        })
      ),
      http.post('/api/v1/projects/1/risk-suppressions', async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          request_id: 'req-suppression-create',
          data: { id: 2, project_id: 1, enabled: true, risk_type: '', rule_id: '', reason: '', expires_at: '', ...body }
        });
      })
    );
  });

  it('opens a risk linked from an asset and filters by that asset', async () => {
    const assetIds: string[] = [];
    server.use(http.get('/api/v1/projects/1/risks', ({ request }) => {
      assetIds.push(new URL(request.url).searchParams.get('asset_id') ?? '');
      return HttpResponse.json({ data: { items: [risk], total: 1, page_size: 20, page_number: 1 } });
    }));
    renderRisks('/projects/1/risks?asset_id=9&risk_id=101');
    const drawer = await screen.findByRole('dialog');
    expect(await within(drawer).findByText('https://admin.example.com')).toBeInTheDocument();
    await waitFor(() => expect(assetIds.at(-1)).toBe('9'));
    await userEvent.click(screen.getByRole('button', { name: '关闭' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    const filter = screen.getByLabelText('已应用的风险筛选');
    expect(filter).toHaveTextContent('仅看资产 #9 的风险');
    const close = filter.querySelector('.ant-tag-close-icon');
    if (!close) throw new Error('asset filter tag is not closable');
    await userEvent.click(close);
    await waitFor(() => expect(assetIds.at(-1)).toBe(''));
  });

  it('opens risk detail and renders backend transition actions', async () => {
    renderRisks();
    await userEvent.click(await screen.findByText('Public admin panel'));

    expect(await screen.findByText('https://admin.example.com')).toBeInTheDocument();
    expect(screen.getByText('internet_exposed')).toBeInTheDocument();
    expect(screen.getByText('25')).toBeInTheDocument();
    // A transition now opens a form so the operator supplies the reason that lands
    // in the status history, instead of the page sending a hardcoded literal.
    await userEvent.click(screen.getByRole('button', { name: /确\s*认/ }));
    const dialog = await findTransitionDialog();
    await userEvent.type(requiredField(dialog, 'reason'), 'triaged by analyst');
    await userEvent.click(within(dialog).getByRole('button', { name: /提\s*交/ }));

    expect(await screen.findByText('已确认')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^分\s*派$/ })).toBeInTheDocument();
  });

  it('sends the operator-supplied reason rather than a hardcoded one', async () => {
    const bodies: Array<Record<string, unknown>> = [];
    server.use(
      http.post('/api/v1/projects/1/risks/101/status-transitions', async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        bodies.push(body);
        return HttpResponse.json({
          request_id: 'req-transition',
          data: { ...risk, ...riskDetailFields, status: 'confirmed', available_actions: ['assign'] }
        });
      })
    );

    renderRisks();
    await userEvent.click(await screen.findByText('Public admin panel'));
    await userEvent.click(await screen.findByRole('button', { name: /确\s*认/ }));
    const dialog = await findTransitionDialog();
    await userEvent.type(requiredField(dialog, 'reason'), 'triaged by analyst');
    await userEvent.click(within(dialog).getByRole('button', { name: /提\s*交/ }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({ action: 'confirm', reason: 'triaged by analyst' });
    expect(bodies[0].reason).not.toBe('operator action');
  });



  it('loads and creates suppression rules', async () => {
    renderRisks();
    expect(await screen.findByText('Public admin panel')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '抑制规则' }));
    expect(await screen.findByText(/Accepted lab/)).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText('名称'), 'Temporary vendor');
    // Suppression matches on rule_id / risk_type and requires an audited reason —
    // there is no free-form "pattern" field.
    await userEvent.type(screen.getByLabelText('规则编号'), 'RULE-0002');
    await userEvent.type(screen.getByLabelText('抑制原因'), '第三方待整改');
    await userEvent.click(screen.getByRole('button', { name: '新增规则' }));

    await waitFor(() => expect(screen.getByText(/Temporary vendor/)).toBeInTheDocument());
  });
});

// The drawer and the modal are both role="dialog" and the test setup stubs id
// generation, so both share aria-labelledby="test-id" and an accessible-name query
// cannot tell them apart. Anchor on the modal's title text instead.
async function findTransitionDialog() {
  const title = await screen.findByText(/风险状态流转/);
  const dialog = title.closest('.ant-modal');
  if (!dialog) throw new Error('transition modal not found');
  return dialog as HTMLElement;
}

function requiredField(container: HTMLElement, id: string) {
  const field = container.querySelector(`#${id}`);
  if (!field) throw new Error(`missing field ${id}`);
  return field as HTMLElement;
}
