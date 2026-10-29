import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

function renderProjects(
  permissions: Permission[] = [Permission.ProjectRead, Permission.ProjectCreate, Permission.ProjectWrite, Permission.ReportRead],
  role = 'security_admin'
) {
  localStorage.setItem('asm.auth', JSON.stringify({
    user: { id: '1', username: 'admin', displayName: 'Admin', role, projectId: 1 },
    accessToken: 'token',
    refreshToken: 'refresh',
    permissions
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
  it('creates a project draft with primary subject, managed domain and optional ICP filing', async () => {
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
        expect(body.domain).toBe('cn.bk.example.jp');
        expect(body.ownership_status).toBe('unverified');
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
    const sections = page.querySelectorAll<HTMLElement>('.project-create-fields');
    expect(sections).toHaveLength(3);
    expect(sections[0]).not.toHaveStyle({ display: 'none' });
    expect(sections[1]).toHaveStyle({ display: 'none' });
    expect(sections[2]).toHaveStyle({ display: 'none' });
    await userEvent.type(inputFor(page, '项目编码'), 'customer-a');
    await userEvent.type(inputFor(page, '项目名称'), '客户 A');
    await userEvent.type(inputFor(page, '业务单元'), 'security');
    await userEvent.click(within(page).getByRole('button', { name: '下一步' }));

    expect(sections[0]).toHaveStyle({ display: 'none' });
    expect(sections[1]).not.toHaveStyle({ display: 'none' });
    expect(sections[2]).toHaveStyle({ display: 'none' });
    await userEvent.type(inputFor(page, '单位名称'), '客户 A 有限公司');
    await userEvent.type(inputFor(page, '统一社会信用代码'), 'TEST1234567890');
    await userEvent.click(within(page).getByRole('button', { name: '下一步' }));

    expect(sections[0]).toHaveStyle({ display: 'none' });
    expect(sections[1]).toHaveStyle({ display: 'none' });
    expect(sections[2]).not.toHaveStyle({ display: 'none' });
    await userEvent.type(inputFor(page, '主域名 / 受管域名'), 'cn.bk.example.jp');
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
    await userEvent.type(inputFor(page, '主域名 / 受管域名'), 'example.com');
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

  it('rejects an invalid managed domain before sending create requests', async () => {
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
    await userEvent.type(inputFor(page, '主域名 / 受管域名'), 'https://example.com/path');
    await userEvent.click(within(page).getByRole('button', { name: '创建项目草稿' }));

    expect(await screen.findByText('请输入合法域名，例如 example.com 或 cn.example.com')).toBeInTheDocument();
    expect(projectCalls).toBe(0);
  });

  it('deletes an archived project only after reason and exact-name confirmation', async () => {
    let deleted = false;
    let deletionBody: Record<string, unknown> | undefined;
    server.use(
      http.get('/api/v1/projects', () => HttpResponse.json({
        request_id: 'projects',
        data: {
          items: deleted ? [] : [{
            id: 1,
            project_code: 'archived-project',
            name: 'Archived Project',
            owner_user_id: '1',
            business_unit: 'security',
            criticality: 'medium',
            status: 'archived',
            description: '',
            created_at: '2026-07-10T00:00:00Z',
            updated_at: '2026-07-10T00:00:00Z'
          }],
          total: deleted ? 0 : 1,
          page_size: 20,
          page_number: 1
        }
      })),
      http.get('/api/v1/projects/1/capabilities', () => HttpResponse.json({
        request_id: 'capabilities',
        data: {
          role: 'system_admin',
          permissions: [Permission.ProjectRead, Permission.ProjectDelete],
          can_activate: false,
          onboarding_missing: []
        }
      })),
      http.delete('/api/v1/projects/1', async ({ request }) => {
        deletionBody = await request.json() as Record<string, unknown>;
        deleted = true;
        return new HttpResponse(null, { status: 204 });
      })
    );
    localStorage.setItem('asm.lastProject', '1');

    renderProjects([Permission.ProjectRead, Permission.ProjectDelete], 'system_admin');
    await userEvent.click(await screen.findByRole('button', { name: '删除' }));

    const dialog = await screen.findByRole('dialog');
    const confirmButton = within(dialog).getByRole('button', { name: '确认删除' });
    expect(confirmButton).toBeDisabled();

    await userEvent.type(within(dialog).getByRole('textbox', { name: '删除原因' }), '重复项目');
    await userEvent.type(within(dialog).getByRole('textbox', { name: '项目名称确认' }), 'Archived Project');
    expect(confirmButton).toBeEnabled();
    await userEvent.click(confirmButton);

    await waitFor(() => expect(deletionBody).toEqual({
      confirmation: 'Archived Project',
      reason: '重复项目'
    }));
    expect(await screen.findByText('Archived Project 已删除')).toBeInTheDocument();
    expect(localStorage.getItem('asm.lastProject')).toBeNull();
  });
});
