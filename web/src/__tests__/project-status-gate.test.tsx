import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';

import { Permission } from '../auth/permissions';
import { ProjectActiveGate, ProjectStatusBanner } from '../components/ProjectStatusGate';
import { ProjectWorkspaceProvider } from '../projects/ProjectContext';
import { server } from '../test/server';

function LocationProbe() {
  const location = useLocation();
  return <output aria-label="current route">{`${location.pathname}${location.search}`}</output>;
}

function renderGate(path = '/projects/1/discovery') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ProjectWorkspaceProvider>
        <ProjectStatusBanner />
        <ProjectActiveGate actionLabel="触发测试任务">
          <button type="button">触发</button>
        </ProjectActiveGate>
        <LocationProbe />
      </ProjectWorkspaceProvider>
    </MemoryRouter>
  );
}

describe('project status gate', () => {
  beforeEach(() => {
    localStorage.setItem('asm.auth', JSON.stringify({ accessToken: 'token' }));
  });

  it('guides a draft project to activation while keeping the return route', async () => {
    server.use(
      http.get('/api/v1/projects/1/capabilities', () => HttpResponse.json({
        request_id: 'draft-capabilities',
        data: {
          role: 'project_owner',
          permissions: [Permission.ProjectRead, Permission.ProjectWrite, Permission.DiscoveryRun],
          project_status: 'draft',
          can_activate: true,
          onboarding_missing: []
        }
      }))
    );

    renderGate();

    expect(await screen.findByText('项目尚未激活')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '触发' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /激活后才能触发测试任务/ })).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: '前往激活项目' }));
    expect(screen.getByLabelText('current route')).toHaveTextContent(
      '/projects/1/profile?focus=activation&returnTo=%2Fprojects%2F1%2Fdiscovery'
    );
  });

  it('does not offer activation for an archived project', async () => {
    server.use(
      http.get('/api/v1/projects/1/capabilities', () => HttpResponse.json({
        request_id: 'archived-capabilities',
        data: {
          role: 'viewer',
          permissions: [Permission.ProjectRead],
          project_status: 'archived',
          can_activate: false,
          onboarding_missing: []
        }
      }))
    );

    renderGate();

    expect(await screen.findByText('项目已归档')).toBeInTheDocument();
    expect(screen.getByLabelText('项目已归档，不能触发测试任务')).toHaveTextContent('已归档');
    expect(screen.queryByRole('button', { name: /激活项目/ })).not.toBeInTheDocument();
  });
});
