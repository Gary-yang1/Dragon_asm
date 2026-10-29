import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import type { ChangeEvent } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App as AntApp } from 'antd';

type MockDatePickerProps = {
  'aria-label'?: string;
  id?: string;
  value?: string | { toISOString?: () => string };
  onChange?: (value: string) => void;
  placeholder?: string;
};

vi.mock('antd', async (importOriginal) => {
  const original = await importOriginal<typeof import('antd')>();
  return {
    ...original,
    DatePicker: (props: MockDatePickerProps) => {
      const value = typeof props.value === 'string' ? props.value : props.value?.toISOString?.() ?? '';
      return (
        <input
          aria-label={props['aria-label']}
          id={props.id}
          value={value}
          onChange={(event: ChangeEvent<HTMLInputElement>) => props.onChange?.(event.target.value)}
          placeholder={props.placeholder}
        />
      );
    },
  };
});

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

function ProjectSwitchControl() {
  const navigate = useNavigate();
  return <button onClick={() => navigate('/projects/2/discovery')}>切换测试项目</button>;
}

async function renderDiscovery(initialEntry = '/discovery', includeProjectSwitch = false) {
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
  const view = render(
    <AntApp>
      <MemoryRouter initialEntries={[initialEntry]}>
        {includeProjectSwitch && <ProjectSwitchControl />}
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </AntApp>
  );
  if (!vi.isFakeTimers()) await userEvent.click(await screen.findByRole('tab', { name: '授权范围' }));
  return view;
}

type TestRequestPayload = {
  scope_id?: unknown;
  name?: unknown;
  task_type?: unknown;
  schedule?: unknown;
  rate_limit?: unknown;
  concurrency?: unknown;
  retry_limit?: unknown;
  config?: {
    options?: {
      max_results?: unknown;
      sources?: unknown[];
      ports?: unknown;
      node_id?: unknown;
    };
    targets?: unknown[];
  };
};

let deleteCalled = false;
let editRequest: TestRequestPayload | null = null;
let createRequest: TestRequestPayload | null = null;
let createScopeRequest: Record<string, unknown> | null = null;
let scopeStatusRequest: Record<string, unknown> | null = null;
let editScopeRequest: Record<string, unknown> | null = null;
let templateEnabledRequest: Record<string, unknown> | null = null;
let triggerRequestCount = 0;
let cancelRequestCount = 0;

const DAY_MS = 24 * 60 * 60 * 1000;
const activeScopeValidFrom = new Date(Date.now() - DAY_MS).toISOString();
const activeScopeValidUntil = new Date(Date.now() + 180 * DAY_MS).toISOString();

describe('DiscoveryPage', () => {
  beforeEach(() => {
    server.use(http.get('/api/v1/projects/:projectId/discovery/runs/:runId/activity', () => HttpResponse.json({data:{status:'partial_success',stages:[],recent:[],asset_count:0,subdomain_count:0,ip_count:0,received_batches:0,processed_batches:0,failed_batches:0,truncated:false}})));
    deleteCalled = false;
    editRequest = null;
    createRequest = null;
    createScopeRequest = null;
    scopeStatusRequest = null;
    editScopeRequest = null;
    templateEnabledRequest = null;
    triggerRequestCount = 0;
    cancelRequestCount = 0;
    server.use(
      http.get('/api/v1/projects/1/discovery/runs/:id', ({ params }) => HttpResponse.json({ data: { id: Number(params.id), project_id: 1, template_id: 11, scope_id: 1, task_type: 'dns', status: 'pending', progress: 0 } })),
      http.get('/api/v1/projects/1/subjects', () =>
        HttpResponse.json({
          request_id: 'req-scope-subject-candidates',
          data: {
            items: [{
              id: 21,
              project_id: 1,
              subject_name: '示例科技有限公司',
              subject_type: 'company',
              registration_code: '91310000TEST',
              country_code: 'CN',
              region: '上海',
              is_primary: true,
              verification_status: 'verified',
              source: 'manual',
              evidence_summary: ''
            }]
          }
        })
      ),
      http.get('/api/v1/projects/1/domains', () =>
        HttpResponse.json({
          request_id: 'req-scope-domain-candidates',
          data: {
            items: [{
              id: 31,
              project_id: 1,
              asset_id: 131,
              domain: 'example.com',
              subject_id: 21,
              is_primary: true,
              ownership_status: 'verified',
              source: 'manual',
              evidence_summary: ''
            }]
          }
        })
      ),
      http.get('/api/v1/projects/1/assets', ({ request }) => {
        const category = new URL(request.url).searchParams.get('category');
        const assets = category === 'domains'
          ? [{
              id: 141,
              project_id: 1,
              asset_type: 'subdomain',
              asset_key: 'subdomain:portal.example.com',
              display_name: 'portal.example.com',
              value: 'portal.example.com',
              source: 'discovery',
              owner: '',
              business_unit: '',
              confidence: 90,
              miss_count: 0,
              status: 'active',
              first_seen: '2026-07-01T00:00:00Z',
              last_seen: '2026-07-08T00:00:00Z',
              created_at: '2026-07-01T00:00:00Z',
              updated_at: '2026-07-08T00:00:00Z',
              created_by: 'engine',
              updated_by: 'engine'
            }]
          : category === 'ips'
            ? [{
                id: 142,
                project_id: 1,
                asset_type: 'ip',
                asset_key: 'ip:8.8.8.8',
                display_name: '8.8.8.8',
                value: '8.8.8.8',
                source: 'discovery',
                owner: '',
                business_unit: '',
                confidence: 90,
                miss_count: 0,
                status: 'active',
                first_seen: '2026-07-01T00:00:00Z',
                last_seen: '2026-07-08T00:00:00Z',
                created_at: '2026-07-01T00:00:00Z',
                updated_at: '2026-07-08T00:00:00Z',
                created_by: 'engine',
                updated_by: 'engine'
              }]
            : category === 'web'
              ? [{
                  id: 143,
                  project_id: 1,
                  asset_type: 'web',
                  asset_key: 'web:https://portal.example.com',
                  display_name: 'Portal',
                  value: 'https://portal.example.com',
                  source: 'discovery',
                  owner: '',
                  business_unit: '',
                  confidence: 90,
                  miss_count: 0,
                  status: 'active',
                  first_seen: '2026-07-01T00:00:00Z',
                  last_seen: '2026-07-08T00:00:00Z',
                  created_at: '2026-07-01T00:00:00Z',
                  updated_at: '2026-07-08T00:00:00Z',
                  created_by: 'engine',
                  updated_by: 'engine'
                }]
              : [];
        return HttpResponse.json({
          request_id: 'req-scope-asset-candidates',
          data: {
            items: assets,
            total: assets.length,
            page_size: 50,
            page_number: 1
          }
        });
      }),
      http.get('/api/v1/projects/1/scopes', () =>
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
                valid_from: activeScopeValidFrom,
                valid_until: activeScopeValidUntil,
                targets: [
                  { id: 1, target_type: 'domain', match_mode: 'include', value: 'example.com' },
                  { id: 3, target_type: 'domain', match_mode: 'exclude', value: 'internal.example.com' }
                ]
              },
              {
                id: 2,
                project_id: 1,
                name: 'Staged perimeter',
                status: 'inactive',
                authorized_by: 'CISO',
                valid_from: '2026-07-01T00:00:00Z',
                valid_until: '2099-08-01T00:00:00Z',
                targets: [{ id: 2, target_type: 'domain', match_mode: 'include', value: 'staged.example.com' }]
              }
            ],
            total: 2,
            page_size: 50,
            page_number: 1
          }
        })
      ),
      http.post('/api/v1/projects/1/scopes', async ({ request }) => {
        const body = (await request.json()) as { name: string; status: string; targets: unknown[] };
        createScopeRequest = body;
        return HttpResponse.json({
          request_id: 'req-create-scope',
          data: {
            id: 3,
            project_id: 1,
            name: body.name,
            status: body.status,
            authorized_by: 'CISO',
            valid_from: '2026-07-08T00:00:00Z',
            valid_until: '2099-08-08T00:00:00Z',
            targets: body.targets
          }
        });
      }),
      http.patch('/api/v1/projects/1/scopes/1', async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        editScopeRequest = body;
        return HttpResponse.json({
          request_id: 'req-edit-scope',
          data: { id: 1, project_id: 1, ...body }
        });
      }),
      http.patch('/api/v1/projects/1/scopes/2', async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        scopeStatusRequest = body;
        return HttpResponse.json({
          request_id: 'req-enable-scope',
          data: {
            id: 2,
            project_id: 1,
            name: 'Staged perimeter',
            status: body.status,
            authorized_by: 'CISO',
            valid_from: activeScopeValidFrom,
            valid_until: activeScopeValidUntil,
            targets: [{ id: 2, target_type: 'domain', match_mode: 'include', value: 'staged.example.com' }]
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
                name: 'Daily DNS discovery',
                task_type: 'dns',
                scope_id: 1,
                config: { targets: [{ type: 'domain', value: 'example.com' }], options: { profile: 'resolve', record_types: ['A'], max_results: 1000 } },
                schedule: '0 2 * * *',
                enabled: true,
                rate_limit: 60,
                concurrency: 4,
                timeout_seconds: 1800,
                retry_limit: 3
              }
            ],
            total: 1,
            page_size: 50,
            page_number: 1
          }
        })
      ),
      http.post('/api/v1/projects/1/discovery/templates', async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        createRequest = body;
        return HttpResponse.json({
          request_id: 'req-create-template',
          data: { ...body, id: 12, project_id: 1 }
        });
      }),
      http.patch('/api/v1/projects/1/discovery/templates/11', async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        editRequest = body;
        return HttpResponse.json({
          request_id: 'req-update-template',
          data: {
            id: 11,
            project_id: 1,
            name: body.name,
            task_type: 'dns',
            scope_id: 1,
            config: body.config,
            schedule: body.schedule,
            enabled: true,
            rate_limit: body.rate_limit,
            concurrency: body.concurrency,
            timeout_seconds: body.timeout_seconds,
            retry_limit: body.retry_limit
          }
        });
      }),
      http.patch('/api/v1/projects/1/discovery/templates/11/enabled', async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        templateEnabledRequest = body;
        return HttpResponse.json({
          request_id: 'req-toggle-template',
          data: {
            id: 11,
            project_id: 1,
            name: 'Daily DNS discovery',
            task_type: 'dns',
            scope_id: 1,
            config: { targets: [{ type: 'domain', value: 'example.com' }], options: { profile: 'resolve', record_types: ['A'], max_results: 1000 } },
            schedule: '0 2 * * *',
            enabled: body.enabled,
            rate_limit: 60,
            concurrency: 4,
            timeout_seconds: 1800,
            retry_limit: 3
          }
        });
      }),
      http.delete('/api/v1/projects/1/discovery/templates/11', () => {
        deleteCalled = true;
        return new HttpResponse(null, { status: 204 });
      }),
      http.post('/api/v1/projects/1/discovery/templates/11/runs', () => {
        triggerRequestCount += 1;
        return HttpResponse.json({
          request_id: 'req-trigger',
          data: { id: 91, project_id: 1, template_id: 11, scope_id: 1, task_type: 'dns', status: 'pending', progress: 0 }
        });
      }),
      http.get('/api/v1/projects/1/discovery/runs', () =>
        HttpResponse.json({
          request_id: 'req-runs',
          data: {
            items: [
              { id: 91, project_id: 1, template_id: 11, scope_id: 1, task_type: 'dns', status: 'running', progress: 35, engine_job_id: 'j-1' },
              { id: 90, project_id: 1, template_id: 11, scope_id: 1, task_type: 'dns', status: 'failed', progress: 100, error_summary: 'timeout' }
            ],
            total: 2,
            page_size: 20,
            page_number: 1
          }
        })
      ),
      http.post('/api/v1/projects/1/discovery/runs/91/cancel', () => {
        cancelRequestCount += 1;
        return HttpResponse.json({
          request_id: 'req-cancel',
          data: { id: 91, project_id: 1, template_id: 11, scope_id: 1, task_type: 'dns', status: 'cancelled', progress: 35 }
        });
      }),
      http.get('/api/v1/projects/1/exposures', () =>
        HttpResponse.json({
          request_id: 'req-exposures',
          data: {
            items: [
              { id: 1, project_id: 1, asset_id: 1, exposure_type: 'port', name: '443/tcp', value: '', protocol: 'tcp', port: 443, url: 'example.com:443', source: 'shodan', confidence: 90, last_seen: '2026-07-08T00:00:00Z' }
            ],
            total: 1,
            page_size: 20,
            page_number: 1
          }
        })
      )
    );
  });

  it('renders scopes and creates a scope with validation', async () => {
    await renderDiscovery();
    expect(await screen.findByText('Public perimeter')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '新建授权范围' }));
    await userEvent.type(screen.getByLabelText('名称'), 'Partner range');
    await userEvent.type(screen.getByLabelText('授权人'), 'CISO');
    await userEvent.type(screen.getByLabelText('生效时间'), '2026-07-08T00:00:00Z');
    await userEvent.type(screen.getByLabelText('失效时间'), '2026-08-08T00:00:00Z');
    await userEvent.type(screen.getByPlaceholderText('example.com'), 'partner.example.com');
    await userEvent.click(screen.getByRole('button', { name: /保\s*存/ }));

    await waitFor(() => expect(screen.queryByRole('dialog', { name: '新建授权范围' })).not.toBeInTheDocument());
    expect(createScopeRequest).toMatchObject({
      status: 'inactive',
      is_default: false,
      targets: [{
        target_type: 'domain',
        match_mode: 'include',
        coverage_mode: 'exact',
        value: 'partner.example.com'
      }]
    });
  });

  it('blocks scope windows longer than 365 days before submitting', async () => {
    await renderDiscovery();
    expect(await screen.findByText('Public perimeter')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '新建授权范围' }));
    await userEvent.type(screen.getByLabelText('名称'), 'Long-lived authorization');
    await userEvent.type(screen.getByLabelText('授权人'), 'CISO');
    await userEvent.type(screen.getByLabelText('生效时间'), '2026-07-31T00:00:00Z');
    await userEvent.type(screen.getByLabelText('失效时间'), '2028-08-31T00:00:00Z');
    await userEvent.type(screen.getByPlaceholderText('example.com'), 'example.com');
    await userEvent.click(screen.getByRole('button', { name: /保\s*存/ }));

    expect(await screen.findByText('授权有效期最长 365 天，请缩短失效时间')).toBeInTheDocument();
    expect(createScopeRequest).toBeNull();
    expect(screen.getByRole('dialog', { name: '新建授权范围' })).toBeInTheDocument();
  });

  it('creates a default domain scope that explicitly covers subdomains', async () => {
    await renderDiscovery();
    expect(await screen.findByText('Public perimeter')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '新建授权范围' }));
    await userEvent.type(screen.getByLabelText('名称'), 'Automatic handoff');
    await userEvent.type(screen.getByLabelText('授权人'), 'CISO');
    await userEvent.click(screen.getByLabelText('创建状态'));
    await userEvent.click(await screen.findByText('创建后立即启用'));
    await userEvent.click(screen.getByRole('switch', { name: '项目默认 Scope' }));
    await userEvent.type(screen.getByLabelText('生效时间'), '2026-07-08T00:00:00Z');
    await userEvent.type(screen.getByLabelText('失效时间'), '2026-08-08T00:00:00Z');
    await userEvent.click(screen.getByRole('combobox', { name: '覆盖范围 1' }));
    await userEvent.click(await screen.findByText('包含子域名'));
    await userEvent.type(screen.getByLabelText('目标值 1'), 'example.com');
    await userEvent.click(screen.getByRole('button', { name: /保\s*存/ }));

    await waitFor(() => expect(createScopeRequest).toBeTruthy());
    expect(createScopeRequest).toMatchObject({
      status: 'active',
      is_default: true,
      targets: [{
        target_type: 'domain',
        match_mode: 'include',
        coverage_mode: 'subdomains',
        value: 'example.com'
      }]
    });
  });

  it('builds an inactive scope draft from project sources without enabling it', async () => {
    await renderDiscovery();
    expect(await screen.findByText('Public perimeter')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '新建授权范围' }));
    const dialog = await screen.findByRole('dialog', { name: '新建授权范围' });

    await userEvent.click(within(dialog).getByRole('combobox', { name: '目标类型 1' }));
    expect(await screen.findByRole('option', { name: '企业主体' })).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(within(dialog).getByText(/当前主动引擎只支持单 IP/)).toBeInTheDocument();

    const sourceSelect = within(dialog).getByRole('combobox', { name: 'Scope 来源候选' });
    await waitFor(() => expect(within(dialog).queryByText('正在加载候选…')).not.toBeInTheDocument());
    await userEvent.click(sourceSelect);
    await userEvent.click(await screen.findByText('示例科技有限公司 · 主主体'));
    await userEvent.click(await screen.findByText('example.com · 主域名'));
    await userEvent.keyboard('{Escape}');

    expect(createScopeRequest).toBeNull();
    await userEvent.click(within(dialog).getByRole('button', { name: '添加到 Scope 草稿' }));
    expect(within(dialog).getByLabelText('目标值 1')).toHaveValue('示例科技有限公司');
    expect(within(dialog).getByLabelText('目标值 2')).toHaveValue('example.com');

    await userEvent.type(within(dialog).getByLabelText('名称'), 'Project boundary draft');
    await userEvent.type(within(dialog).getByLabelText('授权人'), 'CISO');
    await userEvent.type(within(dialog).getByLabelText('生效时间'), '2026-07-08T00:00:00Z');
    await userEvent.type(within(dialog).getByLabelText('失效时间'), '2026-08-08T00:00:00Z');
    await userEvent.click(within(dialog).getByRole('button', { name: /保\s*存/ }));

    await waitFor(() => expect(createScopeRequest).toBeTruthy());
    expect(createScopeRequest).toMatchObject({
      status: 'inactive',
      is_default: false,
      targets: [
        {
          target_type: 'company',
          match_mode: 'include',
          coverage_mode: 'exact',
          value: '示例科技有限公司'
        },
        {
          target_type: 'domain',
          match_mode: 'include',
          coverage_mode: 'subdomains',
          value: 'example.com'
        }
      ]
    });
    expect(scopeStatusRequest).toBeNull();
  });

  it('rejects dangerous scope targets before submitting', async () => {
    server.use(
      http.get('/api/v1/projects/1/scopes', () => HttpResponse.json({
        request_id: 'req-ip-scope',
        data: {
          items: [{
            id: 1,
            project_id: 1,
            name: 'Public IP range',
            status: 'active',
            authorized_by: 'CISO',
            valid_from: activeScopeValidFrom,
            valid_until: activeScopeValidUntil,
            targets: [{ id: 1, target_type: 'ip', match_mode: 'include', value: '8.8.8.8' }]
          }],
          total: 1,
          page_size: 20,
          page_number: 1
        }
      }))
    );
    await renderDiscovery();
    await userEvent.click(await screen.findByRole('button', { name: '编辑 Public IP range' }));
    await userEvent.clear(screen.getByLabelText('目标值 1'));
    await userEvent.type(screen.getByLabelText('目标值 1'), '127.0.0.1');
    await userEvent.click(screen.getByRole('button', { name: /保\s*存/ }));

    expect((await screen.findAllByText('禁止使用内网、回环或保留地址')).length).toBeGreaterThan(0);
    expect(editScopeRequest).toBeNull();
  });

  it('locks scope creation while the request is in flight', async () => {
    let requestCount = 0;
    let releaseRequest: (() => void) | undefined;
    server.use(
      http.post('/api/v1/projects/1/scopes', async ({ request }) => {
        requestCount += 1;
        const body = (await request.json()) as Record<string, unknown>;
        await new Promise<void>((resolve) => {
          releaseRequest = resolve;
        });
        return HttpResponse.json({
          request_id: 'req-create-scope-delayed',
          data: { ...body, id: 3, project_id: 1 }
        });
      })
    );
    await renderDiscovery();
    expect(await screen.findByText('Public perimeter')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '新建授权范围' }));
    await userEvent.type(screen.getByLabelText('名称'), 'Delayed range');
    await userEvent.type(screen.getByLabelText('授权人'), 'CISO');
    await userEvent.type(screen.getByLabelText('生效时间'), '2026-07-08T00:00:00Z');
    await userEvent.type(screen.getByLabelText('失效时间'), '2026-08-08T00:00:00Z');
    await userEvent.type(screen.getByLabelText('目标值 1'), 'delayed.example.com');
    const saveButton = screen.getByRole('button', { name: /保\s*存/ });
    await userEvent.click(saveButton);

    await waitFor(() => expect(requestCount).toBe(1));
    expect(saveButton).toBeDisabled();
    await userEvent.click(saveButton);
    expect(requestCount).toBe(1);
    await act(async () => releaseRequest?.());
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '新建授权范围' })).not.toBeInTheDocument());
  });

  it('activates an inactive scope explicitly', async () => {
    await renderDiscovery();
    expect(await screen.findByText('Staged perimeter')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '启用 Staged perimeter' }));
    await userEvent.click(await screen.findByRole('button', { name: /确.*定/ }));

    await waitFor(() => expect(scopeStatusRequest).toEqual({ status: 'active' }));
    expect(screen.getByRole('button', { name: '停用 Staged perimeter' })).toBeInTheDocument();
  });

  it('edits scope metadata without dropping existing targets', async () => {
    await renderDiscovery();
    expect(await screen.findByText('Public perimeter')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '编辑 Public perimeter' }));
    expect(await screen.findByRole('dialog', { name: '编辑 Scope' })).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText('授权人'));
    await userEvent.type(screen.getByLabelText('授权人'), 'Security Team');
    await userEvent.clear(screen.getByLabelText('目标值 2'));
    await userEvent.type(screen.getByLabelText('目标值 2'), 'private.example.com');
    await userEvent.click(screen.getByRole('button', { name: /保\s*存/ }));

    await waitFor(() => expect(editScopeRequest).toBeTruthy());
    expect(editScopeRequest).toMatchObject({
      authorized_by: 'Security Team',
      targets: [
        { target_type: 'domain', match_mode: 'include', value: 'example.com' },
        { target_type: 'domain', match_mode: 'exclude', value: 'private.example.com' }
      ]
    });
    expect(await screen.findByText('Security Team')).toBeInTheDocument();
    expect(screen.getByText('排除：private.example.com')).toBeInTheDocument();
  });

  it('shows 403 permission denied state for scopes', async () => {
    server.use(
      http.get('/api/v1/projects/1/scopes', () => HttpResponse.json({
        request_id: 'req-forbidden',
        error: { code: 'FORBIDDEN', message: 'permission denied' }
      }, { status: 403 }))
    );
    await renderDiscovery();
    expect(await screen.findByText('无权限访问')).toBeInTheDocument();
  });

  it('does not let a slow response from the previous project overwrite the current project', async () => {
    let projectOneRequests = 0;
    let releaseProjectOne: (() => void) | undefined;
    server.use(
      http.get('/api/v1/projects/1/scopes', async () => {
        projectOneRequests += 1;
        await new Promise<void>((resolve) => {
          releaseProjectOne = resolve;
        });
        return HttpResponse.json({
          request_id: 'req-project-one-scopes',
          data: {
            items: [{ id: 101, project_id: 1, name: 'Project one stale scope', status: 'active', authorized_by: 'CISO', valid_from: '2026-07-01T00:00:00Z', valid_until: '2099-08-01T00:00:00Z', targets: [{ id: 101, target_type: 'domain', match_mode: 'include', value: 'one.example.com' }] }],
            total: 1,
            page_size: 20,
            page_number: 1
          }
        });
      }),
      http.get('/api/v1/projects/2/scopes', () => HttpResponse.json({
        request_id: 'req-project-two-scopes',
        data: {
          items: [{ id: 201, project_id: 2, name: 'Project two scope', status: 'active', authorized_by: 'CISO', valid_from: '2026-07-01T00:00:00Z', valid_until: '2099-08-01T00:00:00Z', targets: [{ id: 201, target_type: 'domain', match_mode: 'include', value: 'two.example.com' }] }],
          total: 1,
          page_size: 20,
          page_number: 1
        }
      })),
      http.get('/api/v1/projects/2/discovery/templates', () => HttpResponse.json({ request_id: 'req-project-two-templates', data: { items: [], total: 0, page_size: 20, page_number: 1 } })),
      http.get('/api/v1/projects/2/discovery/runs', () => HttpResponse.json({ request_id: 'req-project-two-runs', data: { items: [], total: 0, page_size: 20, page_number: 1 } })),
      http.get('/api/v1/projects/2/exposures', () => HttpResponse.json({ request_id: 'req-project-two-exposures', data: { items: [], total: 0, page_size: 20, page_number: 1 } }))
    );

    await renderDiscovery('/projects/1/discovery', true);
    await waitFor(() => expect(projectOneRequests).toBeGreaterThan(0));
    await userEvent.click(screen.getByRole('button', { name: '切换测试项目' }));
    await userEvent.click(await screen.findByRole('tab', { name: '授权范围' }));
    expect(await screen.findByText('Project two scope')).toBeInTheDocument();

    await act(async () => releaseProjectOne?.());
    await waitFor(() => expect(screen.queryByText('Project one stale scope')).not.toBeInTheDocument());
    expect(screen.getByText('Project two scope')).toBeInTheDocument();
  });

  it('triggers and cancels discovery runs', async () => {
    await renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));
    expect(screen.getByText('Daily DNS discovery')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '触发 Daily DNS discovery' }));
    expect(triggerRequestCount).toBe(0);
    await userEvent.click(await screen.findByRole('button', { name: /开始运行/ }));
    await waitFor(() => expect(triggerRequestCount).toBe(1));
    await userEvent.click(await screen.findByRole('button', { name: '关闭' }));
    await userEvent.click(await screen.findByRole('button', { name: '取消 run 91' }));
    await userEvent.click(await screen.findByRole('button', { name: /确.*定/ }));

    await waitFor(() => expect(cancelRequestCount).toBe(1));
    expect(await screen.findByText('已取消')).toBeInTheDocument();
  });

  it('blocks task triggering when the project is not active', async () => {
    server.use(
      http.get('/api/v1/projects/1/capabilities', () => HttpResponse.json({
        request_id: 'draft-project-capabilities',
        data: {
          role: 'project_owner',
          permissions: [
            Permission.AssetRead,
            Permission.ScopeRead,
            Permission.ScopeWrite,
            Permission.DiscoveryRead,
            Permission.DiscoveryRun,
            Permission.ExposureRead,
            Permission.ReportRead
          ],
          project_status: 'draft',
          can_activate: false,
          onboarding_missing: ['valid_scope']
        }
      }))
    );

    await renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));

    expect(await screen.findByRole('button', { name: /项目尚未激活，激活后才能触发任务 Daily DNS discovery/ })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '触发 Daily DNS discovery' })).not.toBeInTheDocument();
    expect(triggerRequestCount).toBe(0);
  });

  it('locks the trigger action while its request is in flight', async () => {
    let releaseRequest: (() => void) | undefined;
    server.use(
      http.post('/api/v1/projects/1/discovery/templates/11/runs', async () => {
        triggerRequestCount += 1;
        await new Promise<void>((resolve) => {
          releaseRequest = resolve;
        });
        return HttpResponse.json({
          request_id: 'req-trigger-delayed',
          data: { id: 92, project_id: 1, template_id: 11, scope_id: 1, task_type: 'dns', status: 'pending', progress: 0 }
        });
      })
    );
    await renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));
    const triggerButton = await screen.findByRole('button', { name: '触发 Daily DNS discovery' });

    await userEvent.click(triggerButton);
    await userEvent.click(await screen.findByRole('button', { name: /开始运行/ }));
    await waitFor(() => expect(triggerButton).toBeDisabled());
    await userEvent.click(screen.getByRole('button', { name: /开始运行/ }));
    expect(triggerRequestCount).toBe(1);

    await act(async () => releaseRequest?.());
    await waitFor(() => expect(screen.queryByRole('button', { name: /开始运行/ })).not.toBeInTheDocument());
    expect(await screen.findByText('执行详情 · #92')).toBeInTheDocument();
  });

  it('deletes a template', async () => {
    await renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));
    expect(await screen.findByText('Daily DNS discovery')).toBeInTheDocument();

    // Ant Design's Popconfirm triggers on first click, then we need to click OK
    await userEvent.click(screen.getByRole('button', { name: '删除 Daily DNS discovery' }));
    const okBtn = await screen.findByRole('button', { name: /确.*定/ });
    await userEvent.click(okBtn);

    await waitFor(() => expect(deleteCalled).toBe(true));
    expect(screen.queryByText('Daily DNS discovery')).not.toBeInTheDocument();
  });

  it('edits a template', async () => {
    await renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));
    expect(await screen.findByText('Daily DNS discovery')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '编辑 Daily DNS discovery' }));

    await screen.findByText('编辑模板');
    expect(screen.getByText(/原配置：0 2/)).toBeInTheDocument();
    expect(screen.queryByLabelText('调度周期（可选）')).not.toBeInTheDocument();
    expect(screen.getByLabelText('重试次数')).toHaveValue('3');
    await userEvent.clear(screen.getByLabelText('任务名称'));
    await userEvent.type(screen.getByLabelText('任务名称'), 'Edited template');

    await userEvent.click(screen.getByRole('button', { name: '保存模板' }));

    await waitFor(() => expect(editRequest).toBeTruthy());
    expect(editRequest!.scope_id).toBeUndefined();
    expect(editRequest!.name).toBe('Edited template');
    expect(editRequest!.schedule).toBe('0 2 * * *');
    expect(editRequest!.retry_limit).toBe(3);
    expect(editRequest!.config!.options!.max_results).toBe(1000);
    expect(editRequest!.config!.targets).toEqual([{ type: 'domain', value: 'example.com' }]);
    expect(await screen.findByText('Edited template')).toBeInTheDocument();
  });

  it('toggles a template and updates its actions immediately', async () => {
    await renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));
    expect(await screen.findByText('Daily DNS discovery')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '禁用 Daily DNS discovery' }));
    await userEvent.click(await screen.findByRole('button', { name: /确.*定/ }));

    await waitFor(() => expect(templateEnabledRequest).toEqual({ enabled: false }));
    expect(screen.getByRole('button', { name: '启用 Daily DNS discovery' })).toBeInTheDocument();
  });

  it('blocks triggering and enabling a template whose scope is inactive', async () => {
    server.use(
      http.get('/api/v1/projects/1/discovery/templates', () => HttpResponse.json({
        request_id: 'req-invalid-scope-template',
        data: {
          items: [{
            id: 12,
            project_id: 1,
            name: 'Inactive scope template',
            task_type: 'dns',
            scope_id: 2,
            config: { targets: [{ type: 'domain', value: 'staged.example.com' }], options: { profile: 'resolve', record_types: ['A'], max_results: 1000 } },
            schedule: '',
            enabled: false,
            rate_limit: 60,
            concurrency: 4,
            timeout_seconds: 1800,
            retry_limit: 3
          }],
          total: 1,
          page_size: 50,
          page_number: 1
        }
      }))
    );
    await renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));

    expect(await screen.findByRole('button', { name: '触发 Inactive scope template' })).toBeDisabled();
    expect(screen.getByRole('button', { name: '启用 Inactive scope template' })).toBeDisabled();
  });

  it('prevents editing backend task types unsupported by the current form', async () => {
    server.use(
      http.get('/api/v1/projects/1/discovery/templates', () => HttpResponse.json({
        request_id: 'req-unsupported-template',
        data: {
          items: [{
            id: 13,
            project_id: 1,
            name: 'Legacy CT template',
            task_type: 'ct_log',
            scope_id: 1,
            config: { targets: [{ type: 'domain', value: 'example.com' }], options: {} },
            schedule: '',
            enabled: false,
            rate_limit: 60,
            concurrency: 4,
            timeout_seconds: 1800,
            retry_limit: 3
          }],
          total: 1,
          page_size: 50,
          page_number: 1
        }
      }))
    );
    await renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));

    expect(await screen.findByRole('button', { name: '编辑 Legacy CT template' })).toBeDisabled();
  });

  it('shows created scenario templates immediately even across token refresh and a failed list refresh', async () => {
    let completed=false, attempts=0;
    const bp={key:'domain_asset_inventory',version:'1.0.0',name:'Domain inventory',description:'domain inventory',risk_level:'passive',required_target_types:['domain'],
      steps:[{key:'passive_intel',name:'Passive discovery',description:'passive',task_type:'passive_intel',engine_route:'passive',required_target_types:['domain'],depends_on:[],defaults:{timeout_seconds:1800,rate_limit:200,concurrency:10,retry_limit:3}}]};
    const made={id:123,project_id:1,scope_id:1,name:'Created from scenario',task_type:'passive_intel',config:{targets:[{type:'domain',value:'example.com'}],options:{}},enabled:true,schedule:'',concurrency:10,rate_limit:200,timeout_seconds:1800,retry_limit:3};
    server.use(
      http.get('/api/v1/projects/1/discovery/blueprints',()=>HttpResponse.json({data:{items:[bp],total:1}})),
      http.post('/api/v1/projects/1/discovery/blueprints/domain_asset_inventory/preview',()=>HttpResponse.json({data:{blueprint:bp,scope:{id:1,name:'Public perimeter',target_types:['domain']},scope_selection:'only_compatible',ready:true,issues:[],steps:[{step:bp.steps[0],ready:true,issues:[]}]}})),
      http.post('/api/v1/projects/1/discovery/blueprints/domain_asset_inventory/templates',async()=>{
        attempts++;
        if(attempts===1)return HttpResponse.json({error:{code:'UNAUTHORIZED',message:'expired'}},{status:401});
        await delay(80);
        completed=true;
        return HttpResponse.json({data:{execution_mode:'templates_only',created_count:1,existing_count:0,templates:[{step_key:'passive_intel',created:true,template:made}]}});
      }),
      http.get('/api/v1/projects/1/discovery/templates',()=>{
        if(completed)return HttpResponse.json({error:{code:'TEMPORARY',message:'list refresh unavailable'}},{status:503});
        return HttpResponse.json({data:{items:[],total:0,page_number:1,page_size:20}});
      })
    );
    await renderDiscovery();
    await userEvent.click(screen.getByRole('tab',{name:'场景方案'}));
    await userEvent.click(await screen.findByRole('button',{name:'预检 Domain inventory'}));
    await userEvent.click(await screen.findByRole('button',{name:'创建任务模板'}));
    expect(await screen.findByText('已创建 1 个任务模板，复用 0 个已有模板。可在下方确认并运行。')).toBeInTheDocument();
    expect(screen.getByRole('tab',{name:'任务模板'})).toHaveAttribute('aria-selected','true');
    expect(await screen.findByText('列表刷新失败，已保留当前模板')).toBeInTheDocument();
    expect(screen.getByText('Created from scenario')).toBeInTheDocument();
    expect(attempts).toBe(2);
  });

  it('creates template', async () => {
    await renderDiscovery();
    await screen.findByText('Public perimeter');
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));

    await userEvent.click(await screen.findByRole('button', { name: '新建模板' }));
    await userEvent.clear(screen.getByLabelText('任务名称'));
    await userEvent.type(screen.getByLabelText('任务名称'), 'Weekly passive');

    expect(screen.getAllByText('发现子域名').length).toBeGreaterThan(0);

    await userEvent.click(screen.getByLabelText('数据来源'));
    expect((await screen.findAllByText('FOFA')).length).toBeGreaterThan(0);
    expect(screen.queryByText('quake')).not.toBeInTheDocument();
    await userEvent.keyboard('{Escape}');

    // Provide a scope by clicking
    const scopeSelect = screen.getByRole('combobox', { name: '授权范围' });
    await userEvent.click(scopeSelect);
    const inactiveScopeOption = await screen.findByTitle('Staged perimeter（未启用）');
    expect(inactiveScopeOption.closest('.ant-select-item-option')).toHaveClass('ant-select-item-option-disabled');
    const scopeOptions = await screen.findAllByText('Public perimeter');
    await userEvent.click(scopeOptions[scopeOptions.length - 1]);

    expect(screen.getByText('定时执行尚未接入，当前无需填写调度表达式。')).toBeInTheDocument();

    const saveButton = screen.getByRole('button', { name: '保存模板' });
    await userEvent.click(saveButton);

    await waitFor(() => expect(createRequest).toBeTruthy());
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '新建发现模板' })).not.toBeInTheDocument());
    expect(createRequest!.scope_id).toBe(1);
    expect(createRequest!.config!.targets).toEqual([{ type: 'domain', value: 'example.com' }]);
    expect(createRequest!.config!.options!.sources).toContain('auto');
    expect(createRequest!.schedule).toBe('');
    expect(createRequest!.retry_limit).toBe(3);
  });

  it('runs and edits a resolved Web template under a wildcard-only scope without losing its targets', async () => {
    server.use(
      http.get('/api/v1/projects/1/scopes',()=>HttpResponse.json({data:{items:[{
        id:1,project_id:1,name:'Web wildcard',status:'active',is_default:false,authorized_by:'owner',valid_from:activeScopeValidFrom,valid_until:activeScopeValidUntil,
        targets:[{target_type:'url',value:'http://example.com',match_mode:'include',coverage_mode:'exact',url_rule:{protocol:'http',include_root:false,include_subdomains:true,ports:[]}}]
      }],total:1}})),
      http.get('/api/v1/projects/1/discovery/templates',()=>HttpResponse.json({data:{items:[{
        id:11,project_id:1,scope_id:1,name:'Resolved Web',task_type:'web_probe',enabled:true,concurrency:10,rate_limit:50,timeout_seconds:1800,retry_limit:3,schedule:'',
        config:{targets:[{type:'url',value:'http://api.example.com:80'}],options:{blueprint_key:'web_exposure_baseline'}}
      }],total:1}}))
    );
    await renderDiscovery();
    await userEvent.click(screen.getByRole('tab',{name:'任务模板'}));
    expect(await screen.findByRole('button',{name:'触发 Resolved Web'})).toBeEnabled();
    await userEvent.click(screen.getByRole('button',{name:'编辑 Resolved Web'}));
    await userEvent.click(await screen.findByRole('button',{name:'保存模板'}));
    await waitFor(()=>expect(editRequest).not.toBeNull());
    expect(editRequest!.config).toMatchObject({targets:[{type:'url',value:'http://api.example.com:80'}],options:{blueprint_key:'web_exposure_baseline'}});
  });

  it('creates an active port template from authorized IP targets', async () => {
    server.use(
      http.get('/api/v1/projects/1/scopes', () => HttpResponse.json({
        request_id: 'req-active-scopes',
        data: {
          items: [{
            id: 3,
            project_id: 1,
            name: 'Authorized active targets',
            status: 'active',
            authorized_by: 'CISO',
            valid_from: '2026-07-01T00:00:00Z',
            valid_until: '2099-08-01T00:00:00Z',
            targets: [
              { id: 31, target_type: 'ip', match_mode: 'include', value: '8.8.8.8' },
              { id: 32, target_type: 'url', match_mode: 'include', value: 'https://example.com' },
              { id: 33, target_type: 'domain', match_mode: 'include', value: 'example.com' }
            ]
          }],
          total: 1,
          page_size: 50,
          page_number: 1
        }
      }))
    );

    await renderDiscovery();
    await screen.findByText('Authorized active targets');
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));
    await userEvent.click(await screen.findByRole('button', { name: '新建模板' }));
    await userEvent.type(screen.getByLabelText('任务名称'), 'Authorized port scan');

    await userEvent.click(screen.getByLabelText('发现目的'));
    await userEvent.click(await screen.findByText('发现开放端口'));

    await userEvent.click(screen.getByRole('combobox', { name: '授权范围' }));
    const matchingScopes = await screen.findAllByText('Authorized active targets');
    await userEvent.click(matchingScopes[matchingScopes.length - 1]);
    expect(screen.getByLabelText('端口范围')).toHaveValue('80,443');
    expect(screen.getByLabelText('执行节点（可选）')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '保存模板' }));
    await waitFor(() => expect(createRequest).toBeTruthy());

    expect(createRequest).toMatchObject({
      task_type: 'port_probe',
      scope_id: 3,
      rate_limit: 100,
      concurrency: 10,
      config: {
        targets: [{ type: 'ip', value: '8.8.8.8' }],
        options: { ports: '80,443' }
      }
    });
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '新建发现模板' })).not.toBeInTheDocument());
  });

  it('disables cancellation after an active task has reached the engine', async () => {
    server.use(
      http.get('/api/v1/projects/1/discovery/runs', () => HttpResponse.json({
        request_id: 'req-active-run',
        data: {
          items: [{
            id: 101,
            project_id: 1,
            template_id: 13,
            scope_id: 3,
            task_type: 'port_probe',
            status: 'running',
            progress: 30,
            engine_job_id: 'active-job-101'
          }],
          total: 1,
          page_size: 20,
          page_number: 1
        }
      }))
    );

    await renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '发现任务' }));
    const cancelButton = await screen.findByRole('button', { name: '取消 run 101' });
    expect(cancelButton).toBeDisabled();
    expect(cancelRequestCount).toBe(0);
  });

  it('uses server-side pagination for exposure results', async () => {
    const requestedPages: number[] = [];
    server.use(
      http.get('/api/v1/projects/1/exposures', ({ request }) => {
        const pageNumber = Number(new URL(request.url).searchParams.get('page_number') ?? '1');
        requestedPages.push(pageNumber);
        return HttpResponse.json({
          request_id: `req-exposure-page-${pageNumber}`,
          data: {
            items: [{ id: pageNumber, project_id: 1, asset_id: pageNumber, exposure_type: 'port', name: `Exposure page ${pageNumber}`, value: '', protocol: 'tcp', port: 443, url: `page-${pageNumber}.example.com:443`, source: 'fofa', confidence: 90, last_seen: '2026-07-08T00:00:00Z' }],
            total: 45,
            page_size: 20,
            page_number: pageNumber
          }
        });
      })
    );

    await renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '暴露结果' }));
    expect(await screen.findByText('Exposure page 1')).toBeInTheDocument();
    await userEvent.click(screen.getByTitle('2'));

    expect(await screen.findByText('Exposure page 2')).toBeInTheDocument();
    expect(requestedPages).toContain(2);
  });

  it('shows placeholder in changes monitor', async () => {
    await renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '变化监控' }));
    expect(await screen.findByText('变化事件查询接口待接入')).toBeInTheDocument();
  });

  it('retries run polling after a transient failure and continues at an idle cadence', async () => {
    vi.useFakeTimers();
    let runRequests = 0;
    server.use(
      http.get('/api/v1/projects/1/discovery/runs', () => {
        runRequests += 1;
        if (runRequests === 1) {
          return HttpResponse.json({
            request_id: 'req-runs-temporary-error',
            error: { code: 'TEMPORARY_ERROR', message: 'temporary failure' }
          }, { status: 503 });
        }
        return HttpResponse.json({
          request_id: 'req-runs-terminal',
          data: {
            items: [{ id: 91, project_id: 1, template_id: 11, scope_id: 1, task_type: 'dns', status: 'success', progress: 100 }],
            total: 1,
            page_size: 20,
            page_number: 1
          }
        });
      })
    );

    const view = await renderDiscovery();
    try {
      await act(async () => vi.advanceTimersByTimeAsync(100));
      expect(runRequests).toBe(1);
      await act(async () => vi.advanceTimersByTimeAsync(8000));
      expect(runRequests).toBe(2);
      await act(async () => vi.advanceTimersByTimeAsync(29999));
      expect(runRequests).toBe(2);
      await act(async () => vi.advanceTimersByTimeAsync(1));
      expect(runRequests).toBe(3);
    } finally {
      view.unmount();
      vi.useRealTimers();
    }
  });

  it('stops run polling after a permission denial', async () => {
    vi.useFakeTimers();
    let runRequests = 0;
    server.use(
      http.get('/api/v1/projects/1/discovery/runs', () => {
        runRequests += 1;
        return HttpResponse.json({
          request_id: 'req-runs-forbidden',
          error: { code: 'FORBIDDEN', message: 'permission denied' }
        }, { status: 403 });
      })
    );

    const view = await renderDiscovery();
    try {
      await act(async () => vi.advanceTimersByTimeAsync(100));
      expect(runRequests).toBe(1);
      await act(async () => vi.advanceTimersByTimeAsync(16000));
      expect(runRequests).toBe(1);
    } finally {
      view.unmount();
      vi.useRealTimers();
    }
  });
  it('auto-fills a compatible scope and creates then runs only after explicit confirmation', async () => {
    let starts = 0;
    server.use(http.post('/api/v1/projects/1/discovery/templates/12/runs', () => {
      starts += 1;
      return HttpResponse.json({ data: { id: 120, project_id: 1, template_id: 12, scope_id: 1, task_type: 'passive_intel', status: 'pending', progress: 0 } });
    }));
    await renderDiscovery();
    await userEvent.click(screen.getByRole('button', { name: '新建发现任务' }));
    const dialog = await screen.findByRole('dialog', { name: '新建发现任务' });
    await waitFor(() => expect(within(dialog).getByLabelText('任务名称')).toHaveValue('发现子域名 · Public perimeter'));
    expect(within(dialog).getAllByText('Public perimeter').length).toBeGreaterThan(0);
    expect(createRequest).toBeNull();
    await userEvent.click(within(dialog).getByRole('button', { name: '下一步：确认执行' }));
    const confirmation = await screen.findByRole('dialog', { name: '确认发现任务' });
    expect(within(confirmation).getAllByText('example.com').length).toBeGreaterThan(0);
    expect(createRequest).toBeNull();
    expect(starts).toBe(0);
    await userEvent.click(within(confirmation).getByRole('button', { name: '创建并运行' }));
    await waitFor(() => expect(starts).toBe(1));
    expect(createRequest).toMatchObject({ scope_id: 1, schedule: '', task_type: 'passive_intel' });
    expect(await screen.findByRole('dialog', { name: '执行详情 · #120' })).toBeInTheDocument();
  });

  it('keeps form usable after validation failure and does not create a task', async () => {
    await renderDiscovery();
    await userEvent.click(screen.getByRole('button', { name: '新建发现任务' }));
    const dialog = await screen.findByRole('dialog', { name: '新建发现任务' });
    await userEvent.clear(within(dialog).getByLabelText('任务名称'));
    await userEvent.click(within(dialog).getByRole('button', { name: '下一步：确认执行' }));
    expect(await screen.findByText('请输入 1–64 个字符的任务名称')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: '下一步：确认执行' })).toBeEnabled();
    expect(createRequest).toBeNull();
    await userEvent.click(within(dialog).getByRole('button', { name: /取\s*消/ }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '新建发现任务' })).not.toBeInTheDocument());
  });

  it('preserves a created configuration when dispatch fails instead of recreating or retrying automatically', async () => {
    let creates = 0;
    let starts = 0;
    server.use(
      http.post('/api/v1/projects/1/discovery/templates', async ({ request }) => {
        creates += 1;
        const body = await request.json() as Record<string, unknown>;
        return HttpResponse.json({ data: { ...body, id: 12, project_id: 1 } });
      }),
      http.post('/api/v1/projects/1/discovery/templates/12/runs', () => {
        starts += 1;
        return HttpResponse.json({ error: { code: 'ENGINE_UNAVAILABLE', message: '引擎未就绪' } }, { status: 503 });
      })
    );
    await renderDiscovery();
    await userEvent.click(screen.getByRole('button', { name: '新建发现任务' }));
    await userEvent.click(await screen.findByRole('button', { name: '下一步：确认执行' }));
    await userEvent.click(await screen.findByRole('button', { name: '创建并运行' }));
    expect(await screen.findByText(/配置已保存为.*但未能确认任务启动/)).toBeInTheDocument();
    expect(creates).toBe(1);
    expect(starts).toBe(1);
    expect(await screen.findByRole('button', { name: '触发 发现子域名 · Public perimeter' })).toBeInTheDocument();
  });

  it('explains partial success and links to project-wide results without implying run-level filtering', async () => {
    server.use(http.get('/api/v1/projects/1/discovery/runs/90', () => HttpResponse.json({ data: {
      id: 90, project_id: 1, template_id: 11, scope_id: 1, task_type: 'passive_intel', status: 'partial_success', progress: 100, result_count: 3692
    } })));
    await renderDiscovery();
    await userEvent.click(screen.getByRole('tab', { name: '发现任务' }));
    await userEvent.click(await screen.findByRole('button', { name: '查看任务 90' }));
    const detail = await screen.findByRole('dialog', { name: '执行详情 · #90' });
    expect(await within(detail).findByText('本次任务仅部分完成')).toBeInTheDocument();
    expect(within(detail).getByText(/下方查看来源和 DNS 阶段的状态/)).toBeInTheDocument();
    expect(within(detail).getByText(/上方展示本次运行已返回的资产/)).toBeInTheDocument();
    expect(within(detail).getByRole('link', { name: '查看项目资产' })).toHaveAttribute('href', '/projects/1/assets');
  });

  it('preserves task input while the user goes to repair missing authorization', async () => {
    await renderDiscovery();
    await userEvent.click(screen.getByRole('button', { name: '新建发现任务' }));
    let dialog = await screen.findByRole('dialog', { name: '新建发现任务' });
    await userEvent.click(within(dialog).getByRole('combobox', { name: '发现目的' }));
    await userEvent.click(await screen.findByText('发现开放端口'));
    await userEvent.clear(within(dialog).getByLabelText('任务名称'));
    await userEvent.type(within(dialog).getByLabelText('任务名称'), '上线检查');
    await userEvent.click(within(dialog).getByRole('button', { name: '管理授权范围' }));
    expect(await screen.findByText('任务配置已暂存')).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '新建发现任务' })).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: '继续配置任务' }));
    dialog = await screen.findByRole('dialog', { name: '新建发现任务' });
    expect(within(dialog).getByLabelText('任务名称')).toHaveValue('上线检查');
    expect(within(dialog).getByText('发现开放端口')).toBeInTheDocument();
    expect(createRequest).toBeNull();
  });

  it('saves explicit URL rules converted from a pasted wildcard without losing the rule fields', async () => {
    await renderDiscovery();
    await userEvent.click(await screen.findByRole('button', {name:'编辑 Public perimeter'}));
    await userEvent.click(screen.getByRole('combobox', {name:'目标类型 1'}));
    await userEvent.click(await screen.findByText('URL', {exact:true}));
    await userEvent.clear(screen.getByLabelText('目标值 1'));
    await userEvent.type(screen.getByLabelText('目标值 1'), 'https://*.example.com:8443');
    await userEvent.tab();
    await waitFor(() => expect(screen.getByRole('checkbox', {name:'包含当前主机'})).not.toBeChecked());
    expect(screen.getByRole('checkbox', {name:'包含其子域名'})).toBeChecked();
    expect(screen.getByLabelText('URL 允许端口')).toHaveValue('8443');
    await userEvent.click(screen.getByRole('button', {name:/保\s*存/}));
    await waitFor(() => expect(editScopeRequest).not.toBeNull());
    expect(editScopeRequest!.targets).toEqual(expect.arrayContaining([expect.objectContaining({
      target_type:'url', value:'https://example.com',
      url_rule:{protocol:'https',include_root:false,include_subdomains:true,ports:[8443]}
    })]));
  });

  it('clears previously loaded run details when a refresh is denied', async () => {
    let reads = 0;
    server.use(http.get('/api/v1/projects/1/discovery/runs/90', () => {
      reads += 1;
      if (reads > 1) return HttpResponse.json({ error: { code: 'FORBIDDEN', message: '没有查看权限' } }, { status: 403 });
      return HttpResponse.json({ data: { id: 90, project_id: 1, template_id: 11, scope_id: 1, task_type: 'dns', status: 'success', progress: 100, engine_job_id: 'private-job-reference' } });
    }));
    await renderDiscovery();
    await userEvent.click(screen.getByRole('tab', { name: '发现任务' }));
    await userEvent.click(await screen.findByRole('button', { name: '查看任务 90' }));
    const detail = await screen.findByRole('dialog', { name: '执行详情 · #90' });
    expect(await within(detail).findByText('private-job-reference')).toBeInTheDocument();
    await userEvent.click(within(detail).getByRole('button', { name: '刷新详情' }));
    expect(await within(detail).findByText('无法加载执行详情')).toBeInTheDocument();
    expect(within(detail).queryByText('private-job-reference')).not.toBeInTheDocument();
  });

  it('prepares full Web targets without validating hidden name fields', async () => {
    const step={key:'web_probe',name:'识别全部网站',task_type:'web_probe',engine_route:'active',required_target_types:['url'],depends_on:[],defaults:{timeout_seconds:1800,rate_limit:50,concurrency:10,retry_limit:3}};
    const bp={key:'web_exposure_baseline',version:'1.0.0',name:'Web 暴露面基线',risk_level:'active',required_target_types:['url'],steps:[step]};
    let previewed=false;
    server.use(
      http.get('/api/v1/projects/1/discovery/blueprints',()=>HttpResponse.json({data:{items:[bp],total:1}})),
      http.post('/api/v1/projects/1/discovery/blueprints/web_exposure_baseline/preview',()=>{previewed=true;return HttpResponse.json({data:{blueprint:bp,scope:{id:1,name:'Public perimeter',target_types:['domain']},scope_selection:'explicit',ready:true,issues:[],steps:[{step,ready:true,issues:[],target_count:202,batch_count:1}]}})})
    );
    await renderDiscovery();
    await userEvent.click(screen.getByRole('button',{name:'新建发现任务'}));
    await userEvent.clear(screen.getByLabelText('任务名称'));
    await userEvent.click(screen.getByLabelText('发现目的'));
    await userEvent.click(await screen.findByText('识别网站',{exact:true}));
    await userEvent.click(screen.getByRole('button',{name:'预览全部网站目标'}));
    expect(await screen.findByText('已解析 202 个具体网址')).toBeInTheDocument();
    expect(previewed).toBe(true);expect(triggerRequestCount).toBe(0);
  });

});
