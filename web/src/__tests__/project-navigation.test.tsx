import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { beforeEach, describe, expect, it } from 'vitest';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';

import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { usePermission } from '../auth/usePermission';
import { AppLayout } from '../layouts/AppLayout';
import { ProjectWorkspaceProvider, useProjectWorkspace } from '../projects/ProjectContext';
import { server } from '../test/server';

function Probe() {
  const location = useLocation();
  const navigate = useNavigate();
  const { projectId } = useProjectWorkspace();
  const { can } = usePermission();
  return <>
    <output data-testid="route">{location.pathname}{location.search}</output>
    <output data-testid="data-scope">{projectId}</output>
    <output data-testid="global-access">{String(can(Permission.UserRead))}</output>
    <button onClick={() => navigate(-1)}>浏览器返回</button>
  </>;
}

function renderShell(path: string, userId = 'nav-user') {
  localStorage.setItem('asm.auth', JSON.stringify({
    user: { id: userId, username: 'alice', displayName: 'Alice', role: 'system_admin', projectId: 0 },
    accessToken: 'token', refreshToken: 'refresh', permissions: Object.values(Permission)
  }));
  return render(<MemoryRouter initialEntries={[path]}><AuthProvider><Routes>
    <Route element={<ProjectWorkspaceProvider><AppLayout /></ProjectWorkspaceProvider>}>
      <Route path="*" element={<Probe />} />
    </Route>
    <Route path="/login" element={<p>已退出</p>} />
  </Routes></AuthProvider></MemoryRouter>);
}

beforeEach(() => {
  sessionStorage.clear();
  server.use(
    http.get('/api/v1/projects', () => HttpResponse.json({ data: { items: [{ id: 1, name: 'Alpha' }, { id: 2, name: 'Beta' }], total: 2 } })),
    http.get('/api/v1/projects/:id/capabilities', ({ params }) => HttpResponse.json({ data: {
      role: 'viewer', project_status: 'active', can_activate: false, onboarding_missing: [],
      permissions: params.id === '1' ? [Permission.AssetRead, Permission.RiskRead, Permission.ReportRead] : [Permission.ReportRead, Permission.TicketRead]
    } }))
  );
});

describe('persistent project navigation', () => {
  it('keeps project menus across pages and platform management without changing the platform data scope', async () => {
    renderShell('/projects/1/assets?q=needle');
    await userEvent.click(await screen.findByRole('button', { name: '风险管理' }));
    await waitFor(() => expect(screen.getByTestId('route')).toHaveTextContent('/projects/1/risks'));
    expect(screen.getByRole('button', { name: '资产管理' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '工作台' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '浏览器返回' }));
    await waitFor(() => expect(screen.getByTestId('route')).toHaveTextContent('/projects/1/assets?q=needle'));
    await userEvent.click(screen.getByText('系统设置', { exact: true }));
    await userEvent.click(await screen.findByRole('button', { name: '用户管理' }));
    await waitFor(() => expect(screen.getByTestId('route')).toHaveTextContent('/platform/users'));
    expect(screen.getByRole('button', { name: '资产管理' })).toBeInTheDocument();
    expect(screen.getByTestId('data-scope')).toHaveTextContent('0');
    expect(screen.getByTestId('global-access')).toHaveTextContent('true');
    await waitFor(() => expect(screen.getByRole('button', { name: '返回项目工作区' })).toBeEnabled());
    await userEvent.click(screen.getByRole('button', { name: '返回项目工作区' }));
    expect(screen.getByTestId('route')).toHaveTextContent('/projects/1/assets?q=needle');
  });

  it('restores the project on platform refresh and clears it on explicit exit', async () => {
    const view = renderShell('/projects/1/assets?q=retained');
    await waitFor(() => expect(sessionStorage.getItem('asm.projectNavigation:nav-user')).toBe('/projects/1/assets?q=retained'));
    view.unmount();
    renderShell('/platform/users');
    await waitFor(() => expect(screen.getByRole('button', { name: '返回项目工作区' })).toBeEnabled());
    await userEvent.click(screen.getByRole('button', { name: '返回全局工作台' }));
    expect(screen.getByTestId('route')).toHaveTextContent('/workspace');
    expect(sessionStorage.getItem('asm.projectNavigation:nav-user')).toBeNull();
    expect(screen.queryByRole('button', { name: '资产管理' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '工作台' })).toBeInTheDocument();
  });

  it('switches the entire menu to the selected project and uses its permissions', async () => {
    renderShell('/projects/1/assets');
    await userEvent.click(await screen.findByRole('button', { name: '切换项目：Alpha' }));
    await userEvent.click(await screen.findByText('Beta', { exact: true }));
    await waitFor(() => expect(screen.getByTestId('route')).toHaveTextContent('/projects/2/overview'));
    await waitFor(() => expect(screen.queryByRole('button', { name: '资产管理' })).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: '工单管理' }));
    expect(screen.getByTestId('route')).toHaveTextContent('/projects/2/tickets');
  });

  it('does not load another users remembered project or unsafe stored routes', async () => {
    sessionStorage.setItem('asm.projectNavigation:other-user', '/projects/1/assets');
    sessionStorage.setItem('asm.projectNavigation:nav-user', 'https://example.com/projects/1/assets');
    renderShell('/platform/users');
    await screen.findByText('系统设置', { exact: true });
    expect(screen.queryByRole('button', { name: '返回项目工作区' })).not.toBeInTheDocument();
    expect(screen.getByTestId('data-scope')).toHaveTextContent('0');
  });

  it('disables remembered project links when capabilities cannot be revalidated', async () => {
    sessionStorage.setItem('asm.projectNavigation:nav-user', '/projects/1/assets');
    server.use(http.get('/api/v1/projects/1/capabilities', () => HttpResponse.json({ error: { message: 'denied' } }, { status: 403 })));
    renderShell('/platform/users');
    expect(await screen.findByText('项目菜单暂时无法加载，可重试或返回全局工作台。')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '资产管理' })).toHaveAttribute('aria-disabled', 'true');
    await userEvent.click(screen.getByRole('button', { name: '资产管理' }));
    expect(screen.getByTestId('route')).toHaveTextContent('/platform/users');
    expect(screen.getByRole('button', { name: '返回项目工作区' })).toBeDisabled();
  });
});
