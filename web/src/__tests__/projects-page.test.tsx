import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

function renderProjects() {
  localStorage.setItem('asm.auth', JSON.stringify({
    user: { id: '1', username: 'admin', displayName: 'Admin', role: 'security_admin', projectId: 1 },
    accessToken: 'token',
    refreshToken: 'refresh',
    permissions: [Permission.ProjectRead, Permission.ProjectCreate, Permission.ProjectWrite, Permission.ReportRead]
  }));
  return render(<MemoryRouter initialEntries={['/projects']}><AuthProvider><App /></AuthProvider></MemoryRouter>);
}

function inputFor(container: HTMLElement, label: string) {
  const item = within(container).getByText(label).closest('.ant-form-item');
  const input = item?.querySelector('input');
  if (!input) throw new Error(`missing input for ${label}`);
  return input;
}

describe('ProjectsPage', () => {
  it('creates a project draft with primary subject, root domain and optional ICP filing', async () => {
    const calls: string[] = [];
    server.use(
      http.post('/api/v1/projects', async ({ request }) => {
        calls.push('project');
        const body = await request.json() as Record<string, unknown>;
        expect(body.project_code).toBe('customer-a');
        return HttpResponse.json({ request_id: 'p', data: { id: 9, ...body, owner_user_id: '1', status: 'draft', created_at: '2026-07-10T00:00:00Z', updated_at: '2026-07-10T00:00:00Z' } }, { status: 201 });
      }),
      http.post('/api/v1/projects/9/subjects', async ({ request }) => {
        calls.push('subject');
        const body = await request.json() as Record<string, unknown>;
        return HttpResponse.json({ request_id: 's', data: { id: 21, project_id: 9, ...body } }, { status: 201 });
      }),
      http.post('/api/v1/projects/9/domains', async ({ request }) => {
        calls.push('domain');
        const body = await request.json() as Record<string, unknown>;
        return HttpResponse.json({ request_id: 'd', data: { id: 31, project_id: 9, asset_id: 41, ...body } }, { status: 201 });
      }),
      http.post('/api/v1/projects/9/icp-filings', async ({ request }) => {
        calls.push('icp');
        const body = await request.json() as Record<string, unknown>;
        return HttpResponse.json({ request_id: 'i', data: { id: 51, project_id: 9, ...body } }, { status: 201 });
      }),
      http.get('/api/v1/projects/9', () => HttpResponse.json({ request_id: 'p9', data: { id: 9, project_code: 'customer-a', name: '客户 A', owner_user_id: '1', business_unit: 'security', criticality: 'high', status: 'draft', description: '', created_at: '2026-07-10T00:00:00Z', updated_at: '2026-07-10T00:00:00Z' } })),
      http.get('/api/v1/projects/9/onboarding-status', () => HttpResponse.json({ request_id: 'o', data: { owner_configured: true, primary_subject_configured: true, primary_domain_configured: true, valid_scope_configured: false, ready_to_activate: false, missing: ['valid_scope'] } })),
      http.get('/api/v1/projects/9/subjects', () => HttpResponse.json({ request_id: 'sl', data: { items: [] } })),
      http.get('/api/v1/projects/9/domains', () => HttpResponse.json({ request_id: 'dl', data: { items: [] } })),
      http.get('/api/v1/projects/9/icp-filings', () => HttpResponse.json({ request_id: 'il', data: { items: [] } }))
    );

    renderProjects();
    expect(await screen.findByText('Default Project')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '创建项目' }));
    expect(await screen.findByRole('heading', { name: '创建项目' })).toBeInTheDocument();
    const page = document.body;
    await userEvent.type(inputFor(page, '项目编码'), 'customer-a');
    await userEvent.type(inputFor(page, '项目名称'), '客户 A');
    await userEvent.type(inputFor(page, '业务单元'), 'security');
    await userEvent.click(within(page).getByRole('button', { name: '下一步' }));

    await userEvent.type(inputFor(page, '单位名称'), '客户 A 有限公司');
    await userEvent.type(inputFor(page, '统一社会信用代码'), 'TEST1234567890');
    await userEvent.click(within(page).getByRole('button', { name: '下一步' }));

    await userEvent.type(inputFor(page, '主域名'), 'example.com');
    await userEvent.type(inputFor(page, 'ICP 备案号（可选）'), '京ICP备00000000号');
    await userEvent.click(within(page).getByRole('button', { name: '创建项目草稿' }));

    await waitFor(() => expect(calls).toEqual(['project', 'subject', 'domain', 'icp']));
    expect(await screen.findByText('项目草稿已创建')).toBeInTheDocument();
  });

  it('continues a partially failed draft without creating the project twice', async () => {
    let projectCalls = 0;
    let subjectCalls = 0;
    let domainCalls = 0;
    server.use(
      http.post('/api/v1/projects', async ({ request }) => {
        projectCalls += 1;
        const body = await request.json() as Record<string, unknown>;
        return HttpResponse.json({ request_id: 'p', data: { id: 9, ...body, owner_user_id: '1', status: 'draft', created_at: '2026-07-10T00:00:00Z', updated_at: '2026-07-10T00:00:00Z' } }, { status: 201 });
      }),
      http.post('/api/v1/projects/9/subjects', async ({ request }) => {
        subjectCalls += 1;
        if (subjectCalls === 1) {
          return HttpResponse.json({ request_id: 's1', error: { code: 'TEMPORARY', message: '暂时无法保存主体' } }, { status: 503 });
        }
        const body = await request.json() as Record<string, unknown>;
        return HttpResponse.json({ request_id: 's2', data: { id: 21, project_id: 9, ...body } }, { status: 201 });
      }),
      http.post('/api/v1/projects/9/domains', async ({ request }) => {
        domainCalls += 1;
        const body = await request.json() as Record<string, unknown>;
        return HttpResponse.json({ request_id: 'd', data: { id: 31, project_id: 9, asset_id: 41, ...body } }, { status: 201 });
      })
    );

    renderProjects();
    await userEvent.click(await screen.findByRole('button', { name: '创建项目' }));
    const page = document.body;
    await userEvent.type(inputFor(page, '项目编码'), 'customer-a');
    await userEvent.type(inputFor(page, '项目名称'), '客户 A');
    await userEvent.type(inputFor(page, '业务单元'), 'security');
    await userEvent.click(within(page).getByRole('button', { name: '下一步' }));
    await userEvent.type(inputFor(page, '单位名称'), '客户 A 有限公司');
    await userEvent.click(within(page).getByRole('button', { name: '下一步' }));
    await userEvent.type(inputFor(page, '主域名'), 'example.com');
    await userEvent.click(within(page).getByRole('button', { name: '创建项目草稿' }));

    expect(await screen.findByText('保存未完成')).toBeInTheDocument();
    expect(projectCalls).toBe(1);
    await userEvent.click(screen.getByRole('button', { name: '继续保存' }));

    await waitFor(() => {
      expect(projectCalls).toBe(1);
      expect(subjectCalls).toBe(2);
      expect(domainCalls).toBe(1);
    });
    expect(await screen.findByText('项目草稿已创建')).toBeInTheDocument();
  });

  it('rejects an invalid root domain before sending create requests', async () => {
    let projectCalls = 0;
    server.use(
      http.post('/api/v1/projects', () => {
        projectCalls += 1;
        return HttpResponse.json({ request_id: 'unexpected', data: {} }, { status: 201 });
      })
    );

    renderProjects();
    await userEvent.click(await screen.findByRole('button', { name: '创建项目' }));
    const page = document.body;
    await userEvent.type(inputFor(page, '项目编码'), 'customer-a');
    await userEvent.type(inputFor(page, '项目名称'), '客户 A');
    await userEvent.type(inputFor(page, '业务单元'), 'security');
    await userEvent.click(within(page).getByRole('button', { name: '下一步' }));
    await userEvent.type(inputFor(page, '单位名称'), '客户 A 有限公司');
    await userEvent.click(within(page).getByRole('button', { name: '下一步' }));
    await userEvent.type(inputFor(page, '主域名'), 'https://example.com/path');
    await userEvent.click(within(page).getByRole('button', { name: '创建项目草稿' }));

    expect(await screen.findByText('请输入合法的根域名，例如 example.com')).toBeInTheDocument();
    expect(projectCalls).toBe(0);
  });
});
