import { render, screen } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

const projects = [
  { id: 1, project_code: 'alpha', name: 'Alpha', owner_user_id: 'u1', business_unit: 'security', criticality: 'high', status: 'active', description: '', created_at: '2026-07-08T00:00:00Z', updated_at: '2026-07-10T00:00:00Z' },
  { id: 2, project_code: 'beta', name: 'Beta', owner_user_id: 'u2', business_unit: 'platform', criticality: 'medium', status: 'draft', description: '', created_at: '2026-07-09T00:00:00Z', updated_at: '2026-07-09T00:00:00Z' }
];

function renderRoute(path: string, permissions: Permission[] = [Permission.ProjectRead, Permission.ProjectCreate]) {
  localStorage.setItem('asm.auth', JSON.stringify({
    user: { id: 'u1', username: 'alice', displayName: 'Alice', role: 'security_admin', projectId: 0 },
    accessToken: 'token',
    refreshToken: 'refresh',
    permissions
  }));
  return render(<MemoryRouter initialEntries={[path]}><AuthProvider><App /></AuthProvider></MemoryRouter>);
}

describe('workspace routing', () => {
  it('lands on the global workspace when multiple projects are visible and no recent project exists', async () => {
    server.use(
      http.get('/api/v1/projects', () => HttpResponse.json({
        request_id: 'projects',
        data: { items: projects, total: 2, page_size: 100, page_number: 1 }
      }))
    );

    renderRoute('/');
    expect(await screen.findByRole('heading', { name: '全局工作台' })).toBeInTheDocument();
    expect(screen.getByText('工作台')).toBeInTheDocument();
    expect(screen.getByText('我的待办')).toBeInTheDocument();
  });

  it('lands on the empty project list when no project is visible', async () => {
    server.use(
      http.get('/api/v1/projects', () => HttpResponse.json({
        request_id: 'projects-empty',
        data: { items: [], total: 0, page_size: 100, page_number: 1 }
      }))
    );

    renderRoute('/');
    expect(await screen.findByText('还没有项目')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '创建第一个项目' })).toBeInTheDocument();
  });

  it('shows the create call to action in an empty workspace only when permitted', async () => {
    server.use(
      http.get('/api/v1/workspace/summary', () => HttpResponse.json({
        request_id: 'workspace-empty',
        data: {
          projects: { total: 0, active: 0, draft: 0, suspended: 0 },
          assets: { total: 0 },
          risks: { open: 0, critical_high: 0, overdue: 0 },
          tickets: { open: 0, overdue: 0 },
          recent_projects: []
        }
      }))
    );

    renderRoute('/workspace');
    expect(await screen.findByRole('button', { name: '创建第一个项目' })).toBeInTheDocument();
  });

  it('renders aggregate metrics and recent projects', async () => {
    renderRoute('/workspace');
    expect(await screen.findByText('可访问项目')).toBeInTheDocument();
    expect(screen.getByText('资产总量')).toBeInTheDocument();
    expect(screen.getByText('高危风险')).toBeInTheDocument();
    expect(screen.getByText('Default Project')).toBeInTheDocument();
  });
});
