import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ConfigProvider } from 'antd';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

function renderApp(initialPath: string, snapshot?: unknown) {
  if (snapshot) {
    localStorage.setItem('asm.auth', JSON.stringify(snapshot));
  }
  return render(
    <ConfigProvider>
      <MemoryRouter initialEntries={[initialPath]}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </ConfigProvider>
  );
}

describe('auth routing', () => {
  it('redirects unauthenticated users to login', () => {
    renderApp('/dashboard');
    expect(screen.getByRole('heading', { name: '欢迎使用' })).toBeInTheDocument();
  });

  it('logs in and renders viewer menu without export button', async () => {
    renderApp('/login');
    await userEvent.type(screen.getByLabelText('账号'), 'alice');
    await userEvent.type(screen.getByLabelText('密码'), 'password');
    await userEvent.click(screen.getByRole('button', { name: '登录' }));
    expect(await screen.findByText('暴露面工作台')).toBeInTheDocument();
    expect(screen.getByText('Alice')).toBeInTheDocument();
    expect(screen.queryByLabelText('下载')).not.toBeInTheDocument();
  });

  it('shows export button when permission exists', async () => {
    renderApp('/dashboard', {
      user: { id: 'u1', name: 'Alice', role: 'security_admin', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [Permission.ReportRead, Permission.ReportExport]
    });
    expect(await screen.findByText('暴露面工作台')).toBeInTheDocument();
    expect(screen.getByLabelText('下载')).toBeInTheDocument();
  });

  it('normalizes legacy display name and strips control characters', async () => {
    renderApp('/dashboard', {
      user: {
        id: 'u1',
        username: 'alice',
        display_name: 'A\u200B\u0007lice',
        role: 'viewer',
        projectId: 1
      },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [Permission.ReportRead]
    });
    expect(await screen.findByText('Alice')).toBeInTheDocument();
  });

  it('blocks routes without required permission', async () => {
    renderApp('/settings', {
      user: { id: 'u1', name: 'Alice', role: 'viewer', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [Permission.ReportRead]
    });
    expect(await screen.findByText('无权限访问')).toBeInTheDocument();
  });

  it('uses refreshed backend permissions instead of stale cached permissions', async () => {
    server.use(
      http.get('/api/v1/auth/permissions', () =>
        HttpResponse.json({ request_id: 'permissions', data: { permissions: [Permission.ProjectRead] } })
      )
    );
    renderApp('/projects', {
      user: { id: 'u1', username: 'alice', displayName: 'Alice', role: 'security_admin', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [Permission.ProjectRead, Permission.ProjectCreate]
    });

    const createButton = await screen.findByRole('button', { name: '创建项目' });
    expect(createButton).toBeDisabled();
    expect(screen.getByText(/项目只读视图/)).toBeInTheDocument();
  });

  it('fails closed when permission refresh is rejected', async () => {
    server.use(
      http.get('/api/v1/auth/permissions', () =>
        HttpResponse.json({ request_id: 'permissions', error: { code: 'FORBIDDEN', message: 'forbidden' } }, { status: 403 })
      )
    );
    renderApp('/projects/new', {
      user: { id: 'u1', username: 'alice', displayName: 'Alice', role: 'security_admin', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [Permission.ProjectCreate]
    });

    expect(await screen.findByText('无权限访问')).toBeInTheDocument();
  });

  it('uses project capabilities instead of global permissions on project routes', async () => {
    server.use(
      http.get('/api/v1/projects/1/capabilities', () => HttpResponse.json({
        request_id: 'capabilities',
        data: { role: 'viewer', permissions: [], can_activate: false, onboarding_missing: [] }
      }))
    );
    renderApp('/projects/1/overview', {
      user: { id: 'u1', username: 'alice', displayName: 'Alice', role: 'viewer', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [Permission.ReportRead]
    });

    expect(await screen.findByText('无权限访问')).toBeInTheDocument();
  });

  it('accepts a project permission even when it is absent from the global permission list', async () => {
    server.use(
      http.get('/api/v1/projects/1/capabilities', () => HttpResponse.json({
        request_id: 'capabilities',
        data: { role: 'viewer', permissions: [Permission.ReportRead], can_activate: false, onboarding_missing: [] }
      }))
    );
    renderApp('/projects/1/overview', {
      user: { id: 'u1', username: 'alice', displayName: 'Alice', role: 'viewer', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: []
    });

    expect(await screen.findByText('暴露面工作台')).toBeInTheDocument();
  });

  it('forces temporary-password users onto the password change route', async () => {
    renderApp('/projects', {
      user: {
        id: 'u1', username: 'alice', displayName: 'Alice', role: 'viewer', projectId: 1,
        mustChangePassword: true
      },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [Permission.ProjectRead]
    });

    expect(await screen.findByRole('heading', { name: '修改初始密码' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: '项目管理' })).not.toBeInTheDocument();
  });

  it('keeps global platform navigation visible inside a project workspace', async () => {
    server.use(
      http.get('/api/v1/projects/1/capabilities', () => HttpResponse.json({
        request_id: 'capabilities',
        data: { role: 'viewer', permissions: [Permission.ReportRead], can_activate: false, onboarding_missing: [] }
      }))
    );
    renderApp('/projects/1/overview', {
      user: { id: 'u1', username: 'alice', displayName: 'Alice', role: 'viewer', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [Permission.ReportRead, Permission.UserRead]
    });

    expect(await screen.findByText('暴露面工作台')).toBeInTheDocument();
    expect(screen.getByText('平台管理')).toBeInTheDocument();
  });
});
