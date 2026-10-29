import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ConfigProvider } from 'antd';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { App } from '../App';
import type { EngineManagementOverview, EngineSummary } from '../api/engineManagement';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { EngineManagementPage } from '../pages/admin/EngineManagementPage';
import { server } from '../test/server';

const passiveEngine: EngineSummary = {
  route: 'passive',
  key: 'baiyan',
  name: 'Baiyan',
  configured: true,
  ready: true,
  health: 'healthy',
  base_url: 'http://baiyan-engine:8090',
  capabilities: ['passive_intel', 'dns', 'org_intel'],
  credentials: [
    { key: 'token', label: 'Engine Token', configured: true, masked_value: '••••••••T0K1' }
  ],
  providers: [
    {
      key: 'fofa',
      name: 'FOFA',
      configured: true,
      credentials: [
        { key: 'email', label: 'FOFA Email', configured: true, masked_value: 't********r@example.invalid' },
        { key: 'key', label: 'FOFA Key', configured: true, masked_value: '••••••••F0F4' }
      ]
    }
  ],
  last_checked_at: '2026-08-03T01:00:00Z',
  latency_ms: 12
};

const activeEngine: EngineSummary = {
  route: 'active',
  key: 'rinnegan',
  name: '主动扫描引擎',
  configured: true,
  ready: true,
  health: 'degraded',
  base_url: 'http://active-engine:8080',
  capabilities: ['portscan', 'webscan', 'fingerprint'],
  credentials: [
    { key: 'ak', label: 'Access Key', configured: true, masked_value: 'ak_t••••E5T1' },
    { key: 'sk', label: 'Secret Key', configured: true, masked_value: '••••••••S3K9' }
  ],
  nodes: [
    { node_id: 'worker-cn-01', capabilities: ['portscan', 'webscan'] }
  ],
  last_checked_at: '2026-08-03T01:01:00Z',
  latency_ms: 18,
  error_summary: 'fingerprint capability is temporarily unavailable'
};

const overview: EngineManagementOverview = {
  items: [passiveEngine, activeEngine],
  active_policy: {
    enabled: true,
    require_approval: false,
    require_ownership: true
  },
  worker: {
    status: 'online',
    last_seen_at: '2026-08-03T01:02:00Z',
    config_matches: true
  }
};

function renderPage() {
  return render(
    <ConfigProvider>
      <EngineManagementPage />
    </ConfigProvider>
  );
}

function renderApp(path: string, permissions: Permission[]) {
  localStorage.setItem('asm.auth', JSON.stringify({
    user: {
      id: 'u1',
      username: 'admin',
      displayName: 'Admin',
      role: 'system_admin',
      projectId: 1
    },
    accessToken: 'token',
    refreshToken: 'refresh',
    permissions
  }));

  return render(
    <ConfigProvider>
      <MemoryRouter initialEntries={[path]}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </ConfigProvider>
  );
}

describe('engine management page', () => {
  it('registers the platform route, renders masked credentials, and updates only the checked engine', async () => {
    let checkRequests = 0;
    let releaseCheck: (() => void) | undefined;
    const checkGate = new Promise<void>((resolve) => {
      releaseCheck = resolve;
    });
    server.use(
      http.get('/api/v1/platform/discovery-engines', () => HttpResponse.json({
        request_id: 'engines',
        data: overview
      })),
      http.post('/api/v1/platform/discovery-engines/active/check', async () => {
        checkRequests += 1;
        await checkGate;
        return HttpResponse.json({
          request_id: 'active-check',
          data: { ...activeEngine, health: 'healthy', latency_ms: 31, error_summary: undefined }
        });
      })
    );

    renderApp('/platform/engines', [Permission.AdminManage]);

    expect(await screen.findByRole('heading', { name: '引擎管理' })).toBeInTheDocument();
    expect(await screen.findByText('系统设置')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '配置管理' })).toBeInTheDocument();
    expect(screen.getByText('Baiyan')).toBeInTheDocument();
    for (const name of ['Baiyan', '主动扫描引擎']) {
      const row = screen.getByText(name, { exact: true }).closest('tr');
      if (!row) throw new Error('missing engine row');
      await userEvent.click(within(row).getByRole('button', { name: /Expand row|展开行/ }));
    }
    expect(screen.getByText('FOFA')).toBeInTheDocument();
    expect(screen.getByText('••••••••S3K9')).toBeInTheDocument();
    expect(screen.getByText('t********r@example.invalid')).toBeInTheDocument();
    expect(screen.getByText('worker-cn-01')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /(显示原文|复制凭据)/ })).not.toBeInTheDocument();

    const checkButton = screen.getByRole('button', { name: '测试 主动扫描引擎 连接' });
    await userEvent.click(checkButton);
    await waitFor(() => expect(checkButton).toBeDisabled());
    await userEvent.click(checkButton);
    expect(checkRequests).toBe(1);

    releaseCheck?.();
    expect(await screen.findByText('31 ms')).toBeInTheDocument();
    expect(screen.getByText('••••••••S3K9')).toBeInTheDocument();
    expect(screen.getByText('主动扫描引擎连接测试完成')).toBeInTheDocument();
  });

  it('keeps the last known card when a connection test fails', async () => {
    server.use(
      http.get('/api/v1/platform/discovery-engines', () => HttpResponse.json({ request_id: 'engines', data: overview })),
      http.post('/api/v1/platform/discovery-engines/passive/check', () => HttpResponse.json({
        request_id: 'check-failed',
        error: { code: 'ENGINE_UNREACHABLE', message: 'Baiyan 暂时不可达' }
      }, { status: 502 }))
    );
    renderPage();

    await screen.findByText('12 ms');
    await userEvent.click(screen.getByRole('button', { name: '测试 Baiyan 连接' }));

    expect(await screen.findByText(/Baiyan 暂时不可达/)).toBeInTheDocument();
    expect(screen.getByText('12 ms')).toBeInTheDocument();
    const row = screen.getByText('Baiyan', { exact: true }).closest('tr');
    if (!row) throw new Error('missing engine row');
    await userEvent.click(within(row).getByRole('button', { name: /Expand row|展开行/ }));
    expect(screen.getByText('••••••••T0K1')).toBeInTheDocument();
  });

  it('shows a retryable error and recovers after a normal load failure', async () => {
    let requests = 0;
    server.use(
      http.get('/api/v1/platform/discovery-engines', () => {
        requests += 1;
        if (requests === 1) {
          return HttpResponse.json({
            request_id: 'temporary-error',
            error: { code: 'TEMPORARY', message: '引擎状态暂时不可用' }
          }, { status: 503 });
        }
        return HttpResponse.json({ request_id: 'engines', data: overview });
      })
    );
    renderPage();

    expect(await screen.findByText('引擎状态暂时不可用')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /重\s*试/ }));
    expect(await screen.findByText('Baiyan')).toBeInTheDocument();
    expect(requests).toBe(2);
  });

  it('distinguishes an API 403 from a load failure and still allows retry', async () => {
    server.use(
      http.get('/api/v1/platform/discovery-engines', () => HttpResponse.json({
        request_id: 'forbidden',
        error: { code: 'FORBIDDEN', message: 'forbidden' }
      }, { status: 403 }))
    );
    renderPage();

    expect(await screen.findByText('无权查看引擎管理')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /重\s*试/ })).toBeEnabled();
  });

  it('renders the empty state when no engine has been registered', async () => {
    server.use(
      http.get('/api/v1/platform/discovery-engines', () => HttpResponse.json({
        request_id: 'empty-engines',
        data: { ...overview, items: [] }
      }))
    );
    renderPage();

    expect(await screen.findByText('暂无已注册引擎')).toBeInTheDocument();
  });

  it('blocks the route and hides the menu entry without admin:manage', async () => {
    let engineRequests = 0;
    server.use(
      http.get('/api/v1/platform/discovery-engines', () => {
        engineRequests += 1;
        return HttpResponse.json({ request_id: 'engines', data: overview });
      })
    );
    renderApp('/platform/engines', [Permission.UserRead]);

    expect(await screen.findByText('无权限访问')).toBeInTheDocument();
    expect(screen.queryByText('引擎管理')).not.toBeInTheDocument();
    expect(engineRequests).toBe(0);
  });
  it('edits configuration without echoing or replacing an unchanged secret', async () => {
    let submitted: { version: number; values: Record<string, string>; reason: string } | undefined;
    server.use(
      http.get('/api/v1/platform/discovery-engines', () => HttpResponse.json({ data: { ...overview, configuration_version: 1, editable: true } })),
      http.get('/api/v1/platform/discovery-engines/configuration', () => HttpResponse.json({ data: { version: 1, values: { passive_url: 'https://before.example.com' }, secrets: { passive_token: { configured: true, masked_value: '••••••••1234' } }, providers_managed: true } })),
      http.put('/api/v1/platform/discovery-engines/configuration', async ({ request }) => {
        submitted = await request.json() as typeof submitted;
        return HttpResponse.json({ data: { version: 2 } });
      })
    );
    renderPage();
    await waitFor(() => expect(screen.getByRole('button', { name: '编辑配置' })).toBeEnabled());
    await userEvent.click(screen.getByRole('button', { name: '编辑配置' }));
    const url = await screen.findByLabelText('Baiyan 服务地址');
    expect(screen.getByLabelText('连接 Token')).toHaveValue('');
    await userEvent.clear(url);
    await userEvent.type(url, 'https://after.example.com');
    await userEvent.type(screen.getByLabelText('变更原因'), '更换连接地址');
    await userEvent.click(screen.getByRole('button', { name: '保存配置' }));
    await waitFor(() => expect(submitted?.values).toEqual({ passive_url: 'https://after.example.com' }));
    expect(submitted?.version).toBe(1);
    expect(JSON.stringify(submitted)).not.toContain('••••');
  });

  it('keeps the configuration form open on a revision conflict', async () => {
    server.use(
      http.get('/api/v1/platform/discovery-engines', () => HttpResponse.json({ data: { ...overview, configuration_version: 1, editable: true } })),
      http.get('/api/v1/platform/discovery-engines/configuration', () => HttpResponse.json({ data: { version: 1, values: { passive_url: 'https://before.example.com' }, secrets: {}, providers_managed: true } })),
      http.put('/api/v1/platform/discovery-engines/configuration', () => HttpResponse.json({ error: { code: 'ENGINE_SETTINGS_CONFLICT', message: '配置已被其他管理员修改，请重新加载' } }, { status: 409 }))
    );
    renderPage();
    await waitFor(() => expect(screen.getByRole('button', { name: '编辑配置' })).toBeEnabled());
    await userEvent.click(screen.getByRole('button', { name: '编辑配置' }));
    await userEvent.type(await screen.findByLabelText('Baiyan 服务地址'), '/new');
    await userEvent.type(screen.getByLabelText('变更原因'), '调整地址');
    await userEvent.click(screen.getByRole('button', { name: '保存配置' }));
    expect(await screen.findByText('配置已被其他管理员修改，请重新加载')).toBeInTheDocument();
    expect(screen.getByLabelText('变更原因')).toHaveValue('调整地址');
  });

});
