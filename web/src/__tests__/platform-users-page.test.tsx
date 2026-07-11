import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

function renderRoute(path: string, permissions: Permission[]) {
  localStorage.setItem(
    'asm.auth',
    JSON.stringify({
      user: { id: 'u1', username: 'alice', displayName: 'Alice', role: 'security_admin', projectId: 0 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions
    })
  );
  server.use(
    http.get('/api/v1/auth/permissions', () =>
      HttpResponse.json({ request_id: 'permissions', data: { permissions } })
    )
  );
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('platform users page', () => {
  it('renders platform user list with management actions', async () => {
    renderRoute('/platform/users', [Permission.UserRead, Permission.UserWrite, Permission.UserCredentialReset, Permission.UserRoleWrite]);
    expect(await screen.findByRole('heading', { name: '平台用户管理' })).toBeInTheDocument();
    expect(await screen.findByText('alice')).toBeInTheDocument();
    expect(await screen.findByText('bob')).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: '新建用户' })).toBeInTheDocument();
  });

  it('supports creating a new user', async () => {
    renderRoute('/platform/users', [Permission.UserRead, Permission.UserWrite, Permission.UserRoleWrite]);
    await userEvent.click(await screen.findByRole('button', { name: '新建用户' }));
    const editorDialog = await screen.findByRole('dialog', { name: '新建用户' });
    const queryById = (id: string) => {
      const element = editorDialog.querySelector(`#${id}`);
      expect(element).toBeInstanceOf(HTMLInputElement);
      return element as HTMLInputElement;
    };

    await userEvent.type(queryById('username'), 'claire');
    await userEvent.type(queryById('name'), 'Claire');
    await userEvent.type(queryById('email'), 'claire@example.com');
    await userEvent.type(queryById('department'), '安全');
    await userEvent.type(queryById('password'), 'Temporary-123');

    await userEvent.click(within(editorDialog).getByRole('button', { name: /创\s*建/ }));
    expect(await screen.findByText('claire')).toBeInTheDocument();
  });

  it('keeps profile editing separate from platform-role changes', async () => {
    let roleRequests = 0;
    server.use(
      http.put('/api/v1/admin/users/:userId/tenant-role', () => {
        roleRequests += 1;
        return HttpResponse.json({ request_id: 'role', data: { user_id: 1, role: 'system_admin' } });
      })
    );
    renderRoute('/platform/users', [Permission.UserRead, Permission.UserWrite, Permission.UserRoleWrite]);

    await userEvent.click(await screen.findByRole('button', { name: '编辑alice' }));
    const editDialog = await screen.findByRole('dialog', { name: '编辑用户' });
    expect(within(editDialog).queryByLabelText('平台角色')).not.toBeInTheDocument();
    await userEvent.click(within(editDialog).getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '编辑用户' })).not.toBeInTheDocument());
    expect(roleRequests).toBe(0);

    await userEvent.click(await screen.findByRole('button', { name: '设置alice平台角色' }));
    const roleDialog = await screen.findByRole('dialog', { name: '设置平台角色' });
    await userEvent.click(within(roleDialog).getByRole('button', { name: /保存角色/ }));
    await waitFor(() => expect(roleRequests).toBe(1));
  });

  it('resets a password only after matching temporary-password confirmation', async () => {
    renderRoute('/platform/users', [Permission.UserRead, Permission.UserCredentialReset]);
    await screen.findByText('bob');
    const resetButtons = await screen.findAllByRole('button', { name: '重置密码' });
    await userEvent.click(resetButtons[0]);

    const dialog = await screen.findByRole('dialog', { name: '重置临时密码' });
    const passwordInputs = within(dialog).getAllByLabelText(/临时密码/);
    await userEvent.type(passwordInputs[0], 'Replacement-123');
    await userEvent.type(passwordInputs[1], 'Replacement-123');
    await userEvent.click(within(dialog).getByRole('button', { name: '确认重置' }));

    expect(await screen.findByText('临时密码已设置，用户现有会话已失效')).toBeInTheDocument();
  });

  it('shows project authorization without exposing project-role editing', async () => {
    renderRoute('/platform/users', [Permission.UserRead]);
    await screen.findByText('bob');
    const projectButtons = await screen.findAllByRole('button', { name: '项目授权' });
    await userEvent.click(projectButtons[0]);

    const dialog = await screen.findByRole('dialog', { name: /的项目授权/ });
    expect(await within(dialog).findByText('Default Project')).toBeInTheDocument();
    expect(within(dialog).getByText('只读用户')).toBeInTheDocument();
    expect(within(dialog).queryByRole('button', { name: /编辑/ })).not.toBeInTheDocument();
  });

  it('supports compatibility route /settings/users', async () => {
    renderRoute('/settings/users', [Permission.UserRead]);
    expect(await screen.findByRole('heading', { name: '平台用户管理' })).toBeInTheDocument();
  });

  it('supports compatibility route /settings/roles', async () => {
    renderRoute('/settings/roles', [Permission.UserRead]);
    expect(await screen.findByRole('heading', { name: '角色权限' })).toBeInTheDocument();
  });

  it('renders the fixed role matrix as read-only', async () => {
    renderRoute('/platform/roles', [Permission.UserRead]);
    expect(await screen.findByRole('heading', { name: '角色权限' })).toBeInTheDocument();
    expect(await screen.findByText('系统管理员')).toBeInTheDocument();
    expect(await screen.findByText('项目负责人')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /新增角色|编辑权限/ })).not.toBeInTheDocument();
  });

  it('blocks access without user read permission', async () => {
    renderRoute('/platform/users', [Permission.ReportRead]);
    expect(await screen.findByText('无权限访问')).toBeInTheDocument();
  });

  it('security admin has no platform user page access by default', async () => {
    renderRoute('/platform/users', [Permission.ReportRead, Permission.ReportExport]);
    expect(await screen.findByText('无权限访问')).toBeInTheDocument();
  });
});
