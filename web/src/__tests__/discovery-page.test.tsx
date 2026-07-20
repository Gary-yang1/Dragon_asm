import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
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

function renderDiscovery(initialEntry = '/discovery', includeProjectSwitch = false) {
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
    <AntApp>
      <MemoryRouter initialEntries={[initialEntry]}>
        {includeProjectSwitch && <ProjectSwitchControl />}
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </AntApp>
  );
}

type TestRequestPayload = {
  scope_id?: unknown;
  name?: unknown;
  schedule?: unknown;
  retry_limit?: unknown;
  config?: {
    options?: { max_results?: unknown; sources?: unknown[] };
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

describe('DiscoveryPage', () => {
  beforeEach(() => {
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
                valid_from: '2026-07-01T00:00:00Z',
                valid_until: '2026-08-01T00:00:00Z',
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
                valid_until: '2026-08-01T00:00:00Z',
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
            valid_until: '2026-08-08T00:00:00Z',
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
            valid_from: '2026-07-01T00:00:00Z',
            valid_until: '2026-08-01T00:00:00Z',
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
    expect(createScopeRequest).toMatchObject({
      status: 'inactive',
      targets: [{ target_type: 'domain', match_mode: 'include', value: 'partner.example.com' }]
    });
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
            valid_from: '2026-07-01T00:00:00Z',
            valid_until: '2026-08-01T00:00:00Z',
            targets: [{ id: 1, target_type: 'ip', match_mode: 'include', value: '8.8.8.8' }]
          }],
          total: 1,
          page_size: 20,
          page_number: 1
        }
      }))
    );
    renderDiscovery();
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
    renderDiscovery();
    expect(await screen.findByText('Public perimeter')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '新建 Scope' }));
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
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '新建 Scope' })).not.toBeInTheDocument());
  });

  it('activates an inactive scope explicitly', async () => {
    renderDiscovery();
    expect(await screen.findByText('Staged perimeter')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '启用 Staged perimeter' }));
    await userEvent.click(await screen.findByRole('button', { name: /确.*定/ }));

    await waitFor(() => expect(scopeStatusRequest).toEqual({ status: 'active' }));
    expect(screen.getByRole('button', { name: '停用 Staged perimeter' })).toBeInTheDocument();
  });

  it('edits scope metadata without dropping existing targets', async () => {
    renderDiscovery();
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
    expect(screen.getByText('exclude:private.example.com')).toBeInTheDocument();
  });

  it('shows 403 permission denied state for scopes', async () => {
    server.use(
      http.get('/api/v1/projects/1/scopes', () => HttpResponse.json({
        request_id: 'req-forbidden',
        error: { code: 'FORBIDDEN', message: 'permission denied' }
      }, { status: 403 }))
    );
    renderDiscovery();
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
            items: [{ id: 101, project_id: 1, name: 'Project one stale scope', status: 'active', authorized_by: 'CISO', valid_from: '2026-07-01T00:00:00Z', valid_until: '2026-08-01T00:00:00Z', targets: [{ id: 101, target_type: 'domain', match_mode: 'include', value: 'one.example.com' }] }],
            total: 1,
            page_size: 20,
            page_number: 1
          }
        });
      }),
      http.get('/api/v1/projects/2/scopes', () => HttpResponse.json({
        request_id: 'req-project-two-scopes',
        data: {
          items: [{ id: 201, project_id: 2, name: 'Project two scope', status: 'active', authorized_by: 'CISO', valid_from: '2026-07-01T00:00:00Z', valid_until: '2026-08-01T00:00:00Z', targets: [{ id: 201, target_type: 'domain', match_mode: 'include', value: 'two.example.com' }] }],
          total: 1,
          page_size: 20,
          page_number: 1
        }
      })),
      http.get('/api/v1/projects/2/discovery/templates', () => HttpResponse.json({ request_id: 'req-project-two-templates', data: { items: [], total: 0, page_size: 20, page_number: 1 } })),
      http.get('/api/v1/projects/2/discovery/runs', () => HttpResponse.json({ request_id: 'req-project-two-runs', data: { items: [], total: 0, page_size: 20, page_number: 1 } })),
      http.get('/api/v1/projects/2/exposures', () => HttpResponse.json({ request_id: 'req-project-two-exposures', data: { items: [], total: 0, page_size: 20, page_number: 1 } }))
    );

    renderDiscovery('/projects/1/discovery', true);
    await waitFor(() => expect(projectOneRequests).toBeGreaterThan(0));
    await userEvent.click(screen.getByRole('button', { name: '切换测试项目' }));
    expect(await screen.findByText('Project two scope')).toBeInTheDocument();

    await act(async () => releaseProjectOne?.());
    await waitFor(() => expect(screen.queryByText('Project one stale scope')).not.toBeInTheDocument());
    expect(screen.getByText('Project two scope')).toBeInTheDocument();
  });

  it('triggers and cancels discovery runs', async () => {
    renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));
    expect(screen.getByText('Daily DNS discovery')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '触发 Daily DNS discovery' }));
    await waitFor(() => expect(triggerRequestCount).toBe(1));
    await userEvent.click(await screen.findByRole('button', { name: '取消 run 91' }));
    await userEvent.click(await screen.findByRole('button', { name: /确.*定/ }));

    await waitFor(() => expect(cancelRequestCount).toBe(1));
    expect(await screen.findByText('cancelled')).toBeInTheDocument();
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
    renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));
    const triggerButton = await screen.findByRole('button', { name: '触发 Daily DNS discovery' });

    await userEvent.click(triggerButton);
    await waitFor(() => expect(triggerButton).toBeDisabled());
    await userEvent.click(triggerButton);
    expect(triggerRequestCount).toBe(1);

    await act(async () => releaseRequest?.());
    await waitFor(() => expect(triggerButton).not.toBeDisabled());
  });

  it('deletes a template', async () => {
    renderDiscovery();
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
    renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));
    expect(await screen.findByText('Daily DNS discovery')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '编辑 Daily DNS discovery' }));

    await screen.findByText('编辑模板');
    expect(screen.getByLabelText('调度周期（可选）')).toHaveValue('0 2 * * *');
    expect(screen.getByLabelText('重试次数')).toHaveValue('3');
    await userEvent.clear(screen.getByLabelText('模板名称'));
    await userEvent.type(screen.getByLabelText('模板名称'), 'Edited template');

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
    renderDiscovery();
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
    renderDiscovery();
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
    renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));

    expect(await screen.findByRole('button', { name: '编辑 Legacy CT template' })).toBeDisabled();
  });

  it('creates template', async () => {
    renderDiscovery();
    await screen.findByText('Public perimeter');
    await userEvent.click(await screen.findByRole('tab', { name: '任务模板' }));

    await userEvent.click(await screen.findByRole('button', { name: '新建模板' }));
    await userEvent.type(screen.getByLabelText('模板名称'), 'Weekly passive');

    const taskTypeSelect = screen.getByLabelText('任务类型');
    await userEvent.click(taskTypeSelect);
    const option = await screen.findByText('被动子域发现');
    await userEvent.click(option);

    await userEvent.click(screen.getByLabelText('数据源 (sources)'));
    expect((await screen.findAllByText('FOFA')).length).toBeGreaterThan(0);
    expect(screen.queryByText('quake')).not.toBeInTheDocument();
    await userEvent.keyboard('{Escape}');

    // Provide a scope by clicking
    const scopeSelect = screen.getByLabelText('授权 Scope');
    await userEvent.click(scopeSelect);
    const inactiveScopeOption = await screen.findByTitle('Staged perimeter（未启用）');
    expect(inactiveScopeOption.closest('.ant-select-item-option')).toHaveClass('ant-select-item-option-disabled');
    const scopeOptions = await screen.findAllByText('Public perimeter');
    await userEvent.click(scopeOptions[scopeOptions.length - 1]);

    await userEvent.type(screen.getByLabelText('调度周期（可选）'), '@every 30m');

    const saveButton = screen.getByRole('button', { name: '保存模板' });
    await userEvent.click(saveButton);

    await waitFor(() => expect(createRequest).toBeTruthy());
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '新建发现模板' })).not.toBeInTheDocument());
    expect(createRequest!.scope_id).toBe(1);
    expect(createRequest!.config!.targets).toEqual([{ type: 'domain', value: 'example.com' }]);
    expect(createRequest!.config!.options!.sources).toContain('fofa');
    expect(createRequest!.schedule).toBe('@every 30m');
    expect(createRequest!.retry_limit).toBe(3);
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

    renderDiscovery();
    await userEvent.click(await screen.findByRole('tab', { name: '暴露结果' }));
    expect(await screen.findByText('Exposure page 1')).toBeInTheDocument();
    await userEvent.click(screen.getByTitle('2'));

    expect(await screen.findByText('Exposure page 2')).toBeInTheDocument();
    expect(requestedPages).toContain(2);
  });

  it('shows placeholder in changes monitor', async () => {
    renderDiscovery();
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

    const view = renderDiscovery();
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

    const view = renderDiscovery();
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
});
