import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

function RouteProbe() {
  const location = useLocation();
  return <output data-testid="settings-route">{location.pathname}</output>;
}
function renderSettings(path: string, permissions: Permission[]) {
  localStorage.setItem('asm.auth', JSON.stringify({
    user: { id: 'u1', username: 'alice', displayName: 'Alice', role: 'viewer', projectId: 1 },
    accessToken: 'token', refreshToken: 'refresh', permissions
  }));
  return render(<MemoryRouter initialEntries={[path]}><AuthProvider><App /><RouteProbe /></AuthProvider></MemoryRouter>);
}

describe('system settings entry', () => {
  it('opens platform settings from a project and preserves the project return path', async () => {
    server.use(http.get('/api/v1/projects/1/capabilities', () => HttpResponse.json({ data: {
      role: 'viewer', permissions: [Permission.AssetRead], project_status: 'active', can_activate: false, onboarding_missing: []
    } })));
    renderSettings('/projects/1/assets', [Permission.AdminManage, Permission.UserRead]);
    await screen.findByRole('heading', { name: '资产中心' });
    await userEvent.click(screen.getByRole('button', { name: '系统设置' }));
    expect(await screen.findByRole('heading', { name: '系统设置' })).toBeInTheDocument();
    expect(screen.getByTestId('settings-route')).toHaveTextContent('/platform/settings');
    expect(screen.getByRole('link', { name: /配置管理/ })).toHaveAttribute('href', '/platform/engines');
    expect(screen.getByRole('link', { name: /^用户管理/ })).toHaveAttribute('href', '/platform/users');
    await userEvent.click(screen.getByRole('link', { name: /^权限管理/ }));
    expect(await screen.findByRole('heading', { name: '角色权限' })).toBeInTheDocument();
    expect(screen.getByTestId('settings-route')).toHaveTextContent('/platform/roles');
    await waitFor(() => expect(screen.getByRole('button', { name: '返回项目工作区' })).toBeEnabled());
    await userEvent.click(screen.getByRole('button', { name: '返回项目工作区' }));
    expect(screen.getByTestId('settings-route')).toHaveTextContent('/projects/1/assets');
  });

  it('uses global permissions to expose only available settings', async () => {
    renderSettings('/platform/settings', [Permission.AdminManage]);
    await screen.findByRole('heading', { name: '系统设置' });
    expect(screen.getByRole('link', { name: /配置管理/ })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /^用户管理/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /^权限管理/ })).not.toBeInTheDocument();
  });

  it('explains missing platform permissions without exposing management actions', async () => {
    renderSettings('/platform/settings', [Permission.ProjectRead]);
    expect(await screen.findByText('当前账号没有平台管理权限，请联系系统管理员。')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /配置管理/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /^权限管理/ })).not.toBeInTheDocument();
  });
});
