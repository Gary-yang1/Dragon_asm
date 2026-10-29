import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App as AntApp } from 'antd';
import { http, HttpResponse } from 'msw';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

function LocationProbe() {
  const location = useLocation();
  return <output aria-label="current route">{`${location.pathname}${location.search}`}</output>;
}

function projectPayload(status: 'draft' | 'active' | 'archived') {
  return {
    id: 1,
    project_code: 'customer-a',
    name: '客户 A',
    owner_user_id: 'u1',
    business_unit: 'security',
    criticality: 'high',
    status,
    description: '',
    created_at: '2026-07-01T00:00:00Z',
    updated_at: '2026-07-01T00:00:00Z'
  };
}

function installProfileHandlers(initialStatus: 'draft' | 'archived') {
  let status: 'draft' | 'active' | 'archived' = initialStatus;
  server.use(
    http.get('/api/v1/projects/1', () => HttpResponse.json({ request_id: 'project', data: projectPayload(status) })),
    http.get('/api/v1/projects/1/capabilities', () => HttpResponse.json({
      request_id: 'capabilities',
      data: {
        role: 'project_owner',
        permissions: [Permission.ProjectRead, Permission.ProjectWrite, Permission.DiscoveryRead],
        project_status: status,
        can_activate: status === 'draft',
        onboarding_missing: []
      }
    })),
    http.get('/api/v1/projects/1/onboarding-status', () => HttpResponse.json({
      request_id: 'onboarding',
      data: {
        owner_configured: true,
        primary_subject_configured: true,
        primary_domain_configured: true,
        valid_scope_configured: true,
        ready_to_activate: true,
        missing: []
      }
    })),
    http.get('/api/v1/projects/1/subjects', () => HttpResponse.json({ request_id: 'subjects', data: { items: [] } })),
    http.get('/api/v1/projects/1/domains', () => HttpResponse.json({ request_id: 'domains', data: { items: [] } })),
    http.get('/api/v1/projects/1/icp-filings', () => HttpResponse.json({ request_id: 'filings', data: { items: [] } })),
    http.get('/api/v1/projects/1/scopes', () => HttpResponse.json({ request_id: 'scopes', data: { items: [], total: 0, page_size: 20, page_number: 1 } })),
    http.get('/api/v1/projects/1/discovery/templates', () => HttpResponse.json({ request_id: 'templates', data: { items: [], total: 0, page_size: 20, page_number: 1 } })),
    http.get('/api/v1/projects/1/discovery/runs', () => HttpResponse.json({ request_id: 'runs', data: { items: [], total: 0, page_size: 20, page_number: 1 } })),
    http.get('/api/v1/projects/1/exposures', () => HttpResponse.json({ request_id: 'exposures', data: { items: [], total: 0, page_size: 20, page_number: 1 } })),
    http.post('/api/v1/projects/1/transitions', async () => {
      status = 'active';
      return HttpResponse.json({ request_id: 'transition', data: projectPayload(status) });
    })
  );
}

function renderProfile(path: string) {
  localStorage.setItem('asm.auth', JSON.stringify({
    user: { id: 'u1', username: 'alice', displayName: 'Alice', role: 'project_owner', projectId: 1 },
    accessToken: 'token',
    refreshToken: 'refresh',
    permissions: [Permission.ProjectRead, Permission.ProjectWrite, Permission.DiscoveryRead]
  }));
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AntApp>
        <AuthProvider>
          <App />
        </AuthProvider>
      </AntApp>
      <LocationProbe />
    </MemoryRouter>
  );
}

describe('project profile status actions', () => {
  beforeEach(() => localStorage.clear());

  it('activates a ready draft and returns to the originating page', async () => {
    installProfileHandlers('draft');
    renderProfile('/projects/1/profile?focus=activation&returnTo=%2Fprojects%2F1%2Fdiscovery');

    await userEvent.click(await screen.findByRole('button', { name: '激活项目' }));

    await waitFor(() => expect(screen.getByLabelText('current route')).toHaveTextContent('/projects/1/discovery'));
  });

  it('never offers activation for an archived project', async () => {
    installProfileHandlers('archived');
    renderProfile('/projects/1/profile?focus=activation');

    expect(await screen.findByText('归档项目不能重新激活，也不能启动新的发现任务。')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '激活项目' })).not.toBeInTheDocument();
  });
});
