import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

import { Permission } from '../auth/permissions';

const viewerPermissions = [
  Permission.ProjectRead,
  Permission.AssetRead,
  Permission.ExposureRead,
  Permission.DiscoveryRead,
  Permission.RiskRead,
  Permission.TicketRead,
  Permission.ReportRead
];

function storedAuth() {
  try {
    const raw = localStorage.getItem('asm.auth');
    return raw ? JSON.parse(raw) as {
      permissions?: Permission[];
      user?: { role?: string; mustChangePassword?: boolean; username?: string; displayName?: string };
    } : null;
  } catch {
    return null;
  }
}

function storedPermissions() {
  return storedAuth()?.permissions ?? viewerPermissions;
}

type PlatformUserRecord = {
  id: number;
  username: string;
  name: string;
  email: string;
  phone: string;
  department: string;
  role: 'system_admin' | 'security_admin' | null;
  project_count: number;
  status: 'active' | 'disabled';
  last_login_at: string;
  must_change_password: boolean;
  created_at: string;
  updated_at: string;
};

const platformUsers: PlatformUserRecord[] = [
  {
    id: 1,
    username: 'alice',
    name: 'Alice',
    email: 'alice@example.com',
    phone: '13800000001',
    department: '安全运营',
    role: 'security_admin',
    project_count: 2,
    status: 'active',
    last_login_at: '2026-07-10T08:00:00Z',
    must_change_password: false,
    created_at: '2026-06-30T00:00:00Z',
    updated_at: '2026-07-10T00:00:00Z'
  },
  {
    id: 2,
    username: 'bob',
    name: 'Bob',
    email: 'bob@example.com',
    phone: '13900000002',
    department: '研发',
    role: null,
    project_count: 1,
    status: 'disabled',
    last_login_at: '2026-07-09T09:00:00Z',
    must_change_password: true,
    created_at: '2026-07-01T00:00:00Z',
    updated_at: '2026-07-09T00:00:00Z'
  }
];

const platformRoles: Array<{ value: string; label: string; scope: 'tenant' | 'project'; permissions: string[] }> = [
  { value: 'system_admin', label: '系统管理员', scope: 'tenant', permissions: Object.values(Permission) },
  { value: 'security_admin', label: '安全管理员', scope: 'tenant', permissions: [Permission.ProjectRead] },
  { value: 'project_owner', label: '项目负责人', scope: 'project', permissions: [Permission.ProjectRead, Permission.ProjectWrite] },
  { value: 'security_ops', label: '安全运营人员', scope: 'project', permissions: [Permission.AssetRead, Permission.RiskWrite] },
  { value: 'developer', label: '整改人员', scope: 'project', permissions: [Permission.TicketWrite] },
  { value: 'viewer', label: '只读用户', scope: 'project', permissions: [Permission.AssetRead] }
];

export const server = setupServer(
  http.post('/api/v1/auth/login', async () =>
    HttpResponse.json({
      request_id: 'req-login',
      data: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        user: {
          id: 'u1',
          name: 'Alice',
          username: 'alice',
          display_name: 'Alice',
          role: 'viewer',
          project_id: 1,
          permissions: viewerPermissions,
          must_change_password: false
        }
      }
    })
  ),
  http.post('/api/v1/auth/refresh', async () =>
    HttpResponse.json({
      request_id: 'req-refresh',
      data: {
        access_token: 'next-token'
      }
    })
  ),
  http.get('/api/v1/auth/permissions', () =>
    HttpResponse.json({
      request_id: 'req-permissions',
      data: { permissions: storedPermissions() }
    })
  ),
  http.get('/api/v1/auth/me', () => {
    const user = storedAuth()?.user;
    return HttpResponse.json({
      request_id: 'req-me',
      data: {
        id: 'u1',
        username: user?.username ?? 'alice',
        display_name: user?.displayName ?? 'Alice',
        tenant_id: 't1',
        org_id: 'o1',
        must_change_password: user?.mustChangePassword ?? false
      }
    });
  }),
  http.post('/api/v1/auth/password/change', async ({ request }) => {
    const payload = (await request.json()) as { current_password?: string; new_password?: string };
    if (!payload.current_password) {
      return HttpResponse.json({ request_id: 'req-change-password', error: { code: 'INVALID_CURRENT_PASSWORD', message: '当前密码错误' } }, { status: 422 });
    }
    return HttpResponse.json({ request_id: 'req-change-password', data: { must_change_password: false } });
  }),
  http.get('/api/v1/projects', () =>
    HttpResponse.json({
      request_id: 'req-projects',
      data: {
        items: [{ id: 1, project_code: 'default', name: 'Default Project', owner_user_id: 'u1', business_unit: 'platform', criticality: 'medium', status: 'active', description: '', created_at: '2026-07-08T00:00:00Z', updated_at: '2026-07-08T00:00:00Z' }],
        total: 1,
        page_size: 100,
        page_number: 1
      }
    })
  ),
  http.get('/api/v1/projects/:projectId/capabilities', () =>
    HttpResponse.json({
      request_id: 'req-project-capabilities',
      data: {
        role: storedAuth()?.user?.role ?? 'viewer',
        permissions: storedPermissions(),
        can_activate: false,
        onboarding_missing: []
      }
    })
  ),
  http.get('/api/v1/projects/:projectId/onboarding-status', () =>
    HttpResponse.json({
      request_id: 'req-project-onboarding',
      data: {
        owner_configured: true,
        primary_subject_configured: true,
        primary_domain_configured: true,
        valid_scope_configured: true,
        ready_to_activate: true,
        missing: []
      }
    })
  ),
  http.get('/api/v1/workspace/summary', () =>
    HttpResponse.json({
      request_id: 'req-workspace-summary',
      data: {
        projects: { total: 1, active: 1, draft: 0, suspended: 0 },
        assets: { total: 2 },
        risks: { open: 3, critical_high: 1, overdue: 0 },
        tickets: { open: 2, overdue: 0 },
        recent_projects: [{
          id: 1,
          project_code: 'default',
          name: 'Default Project',
          owner_user_id: 'u1',
          business_unit: 'platform',
          criticality: 'medium',
          status: 'active',
          updated_at: '2026-07-08T00:00:00Z'
        }]
      }
    })
  ),
  http.get('/api/v1/admin/users', ({ request }) => {
    const url = new URL(request.url);
    const pageNumber = Number(url.searchParams.get('page_number') ?? 1);
    const pageSize = Number(url.searchParams.get('page_size') ?? 20);
    const q = url.searchParams.get('q')?.trim().toLowerCase() ?? '';
    const status = url.searchParams.get('status');
    const role = url.searchParams.get('role');
    const searchedItems = q
      ? platformUsers.filter((user) =>
          [user.username, user.name, user.email, user.phone, user.department].some((item) => item.toLowerCase().includes(q))
        )
      : platformUsers;
    const items = searchedItems.filter((user) =>
      (!status || user.status === status) && (!role || (role === 'none' ? user.role === null : user.role === role))
    );
    const safeStart = Math.max(1, Math.floor(pageNumber));
    const safeSize = Math.max(1, Math.floor(pageSize));
    const sliceStart = (safeStart - 1) * safeSize;
    const pageItems = items.slice(sliceStart, sliceStart + safeSize);

    return HttpResponse.json({
      request_id: 'req-platform-users',
      data: {
        items: pageItems,
        total: items.length,
        page_size: safeSize,
        page_number: safeStart
      }
    });
  }),
  http.get('/api/v1/admin/roles', () =>
    HttpResponse.json({
      request_id: 'req-admin-roles',
      data: platformRoles
    })
  ),
  http.post('/api/v1/admin/users', async ({ request }) => {
    const body = (await request.json()) as {
      username: string;
      name: string;
      email: string;
      phone?: string;
      department?: string;
      role: 'system_admin' | 'security_admin' | null;
      status: 'active' | 'disabled';
      password?: string;
    };
    const next: PlatformUserRecord = {
      id: platformUsers.length + 1,
      username: body.username,
      name: body.name,
      email: body.email,
      phone: body.phone ?? '',
      department: body.department ?? '',
      role: body.role,
      project_count: 0,
      status: body.status ?? 'active',
      last_login_at: '',
      must_change_password: true,
      created_at: '2026-07-10T00:00:00Z',
      updated_at: '2026-07-10T00:00:00Z'
    };
    if (!body.password || body.password.length < 12) {
      return HttpResponse.json({ request_id: 'req-platform-user-create', error: { code: 'BAD_REQUEST', message: '临时密码无效' } }, { status: 400 });
    }
    platformUsers.push(next);
    return HttpResponse.json({ request_id: 'req-platform-user-create', data: next });
  }),
  http.patch('/api/v1/admin/users/:userId', async ({ params, request }) => {
    const userId = Number(params.userId);
    const payload = (await request.json()) as { name?: string; email?: string; phone?: string; department?: string };
    const target = platformUsers.find((item) => item.id === userId);
    if (!target) {
      return HttpResponse.json({ request_id: 'req-platform-user-update', error: { code: 'NOT_FOUND', message: '用户不存在' } }, { status: 404 });
    }
    Object.assign(target, payload, { updated_at: '2026-07-10T01:00:00Z' });
    return HttpResponse.json({ request_id: 'req-platform-user-update', data: target });
  }),
  http.post('/api/v1/admin/users/:userId/transitions', async ({ params, request }) => {
    const userId = Number(params.userId);
    const payload = (await request.json()) as { status: 'active' | 'disabled'; reason?: string };
    const target = platformUsers.find((item) => item.id === userId);
    if (!target) {
      return HttpResponse.json({ request_id: 'req-platform-user-status', error: { code: 'NOT_FOUND', message: '用户不存在' } }, { status: 404 });
    }
    if (!payload.status || !payload.reason?.trim()) {
      return HttpResponse.json({ request_id: 'req-platform-user-status', error: { code: 'BAD_REQUEST', message: '缺少变更原因' } }, { status: 400 });
    }
    target.status = payload.status;
    target.updated_at = '2026-07-10T01:00:00Z';
    return HttpResponse.json({ request_id: 'req-platform-user-status', data: target });
  }),
  http.put('/api/v1/admin/users/:userId/tenant-role', async ({ params, request }) => {
    const userId = Number(params.userId);
    const payload = (await request.json()) as { role: 'system_admin' | 'security_admin' | null };
    const target = platformUsers.find((item) => item.id === userId);
    if (!target) {
      return HttpResponse.json({ request_id: 'req-platform-user-role', error: { code: 'NOT_FOUND', message: '用户不存在' } }, { status: 404 });
    }
    if (payload.role !== null && !platformRoles.some((role) => role.scope === 'tenant' && role.value === payload.role)) {
      return HttpResponse.json({ request_id: 'req-platform-user-role', error: { code: 'BAD_REQUEST', message: '角色无效' } }, { status: 400 });
    }
    target.role = payload.role;
    target.updated_at = '2026-07-10T01:00:00Z';
    return HttpResponse.json({ request_id: 'req-platform-user-role', data: target });
  }),
  http.post('/api/v1/admin/users/:userId/password-reset', async ({ params, request }) => {
    const userId = Number(params.userId);
    const payload = (await request.json()) as { temporary_password?: string };
    const target = platformUsers.find((item) => item.id === userId);
    if (!target) {
      return HttpResponse.json({ request_id: 'req-platform-user-reset', error: { code: 'NOT_FOUND', message: '用户不存在' } }, { status: 404 });
    }
    if (!payload.temporary_password || payload.temporary_password.length < 12) {
      return HttpResponse.json({ request_id: 'req-platform-user-reset', error: { code: 'BAD_REQUEST', message: '临时密码无效' } }, { status: 400 });
    }
    target.must_change_password = true;
    return HttpResponse.json({ request_id: 'req-platform-user-reset', data: { user_id: userId, must_change_password: true } });
  }),
  http.get('/api/v1/admin/users/:userId/projects', async ({ params }) => {
    const userId = Number(params.userId);
    const target = platformUsers.find((item) => item.id === userId);
    if (!target) {
      return HttpResponse.json({ request_id: 'req-admin-user-projects', error: { code: 'NOT_FOUND', message: '用户不存在' } }, { status: 404 });
    }
    return HttpResponse.json({
      request_id: 'req-admin-user-projects',
      data: { items: [{ id: 1, project_code: 'default', name: 'Default Project', role: 'viewer', status: 'active', updated_at: '2026-07-10T00:00:00Z' }] }
    });
  }),
  http.get('/api/v1/projects/1/reports/dashboard', () =>
    HttpResponse.json({
      request_id: 'req-report-dashboard',
      data: {
        risk: {
          total: 18,
          open: 11,
          critical: 2,
          high: 4,
          overdue: 2,
          fixed: 5
        },
        ticket: {
          total: 4,
          open: 2,
          overdue: 1,
          closed: 2
        },
        exposure: {
          total: 12,
          ports: 3,
          web: 5,
          expiring_certs: 1
        },
        trend: [{ day: '2026-07-08', new: 12, fixed: 4 }, { day: '2026-07-09', new: 7, fixed: 3 }]
      }
    })
  ),
  http.get('/api/v1/projects/1/reports/trends', ({ request }) => {
    const url = new URL(request.url);
    const days = url.searchParams.get('days');
    const hasDays = days ? Number(days) : 0;
    const trend = [
      { day: '2026-07-08', new: 12, fixed: 4 },
      { day: '2026-07-09', new: 10, fixed: 5 },
      { day: '2026-07-10', new: 7, fixed: 3 },
      { day: '2026-07-11', new: 9, fixed: 6 }
    ].slice(-(hasDays > 0 ? hasDays : 4));
    return HttpResponse.json({ request_id: 'req-report-trends', data: trend });
  }),
  http.get('/api/v1/projects/1/reports/remediation', () =>
    HttpResponse.json({
      request_id: 'req-report-remediation',
      data: {
        total_risks: 18,
        fixed_risks: 5,
        sla_met_risks: 16,
        sla_hit_rate: 88,
        mttr_hours: 34,
        age_0_7: 4,
        age_8_30: 9,
        age_over_30: 5,
        reopened_risks: 2,
        recurrence_rate: 6
      }
    })
  )
);
