import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from '../App';
import { AuthProvider } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { server } from '../test/server';

vi.mock('@antv/g6', () => ({
  Graph: vi.fn().mockImplementation(() => ({
    render: vi.fn(),
    destroy: vi.fn()
  }))
}));

const assetRows = [
  {
    id: 1,
    project_id: 1,
    asset_type: 'domain',
    asset_key: 'domain:example.com',
    display_name: 'Example',
    value: 'example.com',
    source: 'manual',
    owner: 'alice',
    business_unit: 'platform',
    confidence: 95,
    miss_count: 0,
    status: 'active',
    first_seen: '2026-07-08T00:00:00.000Z',
    last_seen: '2026-07-08T00:00:00.000Z',
    created_at: '2026-07-08T00:00:00.000Z',
    updated_at: '2026-07-08T00:00:00.000Z',
    created_by: 'u1',
    updated_by: 'u1'
  },
  {
    id: 2,
    project_id: 1,
    asset_type: 'ip',
    asset_key: 'ip:203.0.113.10',
    display_name: 'Edge IP',
    value: '203.0.113.10',
    source: 'manual',
    owner: 'bob',
    business_unit: 'edge',
    confidence: 90,
    miss_count: 0,
    status: 'inactive',
    first_seen: '2026-07-08T00:00:00.000Z',
    last_seen: '2026-07-08T00:00:00.000Z',
    created_at: '2026-07-08T00:00:00.000Z',
    updated_at: '2026-07-08T00:00:00.000Z',
    created_by: 'u1',
    updated_by: 'u1'
  }
];

function renderAssets(path = '/assets') {
  localStorage.setItem(
    'asm.auth',
    JSON.stringify({
      user: { id: 'u1', name: 'Alice', role: 'project_owner', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [Permission.AssetRead, Permission.AssetWrite, Permission.ReportRead]
    })
  );
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('AssetsPage', () => {
  beforeEach(() => {
    server.use(
      http.get('/api/v1/projects/1/assets', ({ request }) => {
        const url = new URL(request.url);
        const category = url.searchParams.get('category');
        const assetType = url.searchParams.get('asset_type');
        let items = assetRows;
        if (category === 'domains') items = items.filter((item) => item.asset_type === 'domain' || item.asset_type === 'subdomain');
        if (category === 'ips') items = items.filter((item) => item.asset_type === 'ip');
        if (category === 'web') items = items.filter((item) => item.asset_type === 'web');
        if (category === 'external') items = items.filter((item) => item.asset_type === 'cloud_resource' || item.asset_type === 'third_party');
        if (assetType) items = items.filter((item) => item.asset_type === assetType);
        return HttpResponse.json({
          request_id: 'req-assets',
          data: {
            items,
            total: items.length,
            page_size: Number(url.searchParams.get('page_size') ?? 20),
            page_number: Number(url.searchParams.get('page_number') ?? 1)
          }
        });
      }),
      http.get('/api/v1/projects/1/assets/summary', () =>
        HttpResponse.json({
          request_id: 'req-summary',
          data: {
            inventory: { total: 2, managed_total: 2, active: 1, inactive: 1, ignored: 0 },
            by_type: {
              domain: 1,
              subdomain: 0,
              ip: 1,
              port: 0,
              service: 0,
              web: 0,
              certificate: 0,
              cloud_resource: 0,
              third_party: 0
            },
            freshness: { new_24h: 0, observed_24h: 0, stale_30d: 2 },
            governance: {
              unowned: 0,
              unassigned_business_unit: 0,
              low_confidence: 0,
              low_confidence_below: 50
            }
          }
        })
      ),
      http.get('/api/v1/projects/1/assets/1', () =>
        HttpResponse.json({
          request_id: 'req-asset',
          data: assetRows[0]
        })
      ),
      http.get('/api/v1/projects/1/assets/1/graph', () =>
        HttpResponse.json({
          request_id: 'req-graph',
          data: {
            nodes: [
              { id: 1, asset_type: 'domain', display_name: 'Example', value: 'example.com', status: 'active', source: 'manual', owner: 'alice', business_unit: 'platform', confidence: 95, last_seen: '2026-07-08T00:00:00.000Z', focus: true },
              { id: 2, asset_type: 'ip', display_name: 'Edge IP', value: '203.0.113.10', status: 'inactive', source: 'manual', owner: 'bob', business_unit: 'edge', confidence: 90, last_seen: '2026-07-08T00:00:00.000Z', focus: false }
            ],
            edges: [{ id: 10, from_asset_id: 1, to_asset_id: 2, relation_type: 'resolves_to', source: 'manual', confidence: 90, last_seen: '2026-07-08T00:00:00.000Z' }],
            truncated: false
          }
        })
      ),
      http.post('/api/v1/projects/1/assets/import', ({ request }) => {
        const dryRun = new URL(request.url).searchParams.get('dry_run') === 'true';
        return HttpResponse.json({
          request_id: 'req-import',
          data: dryRun ? {
            total: 2,
            new: 1,
            update: 0,
            duplicate: 0,
            failed: 1,
            rows: [
              { index: 0, status: 'new', asset_type: 'domain', value: 'example.com', asset_key: 'domain:example.com' },
              { index: 1, status: 'invalid', error: 'invalid asset type' }
            ]
          } : {
            total: 2,
            success: 1,
            failed: 1,
            rows: [
              { index: 0, status: 'imported', asset_id: 1, asset_key: 'domain:example.com' },
              { index: 1, status: 'failed', error: 'invalid asset type' }
            ]
          }
        });
      })
    );
  });

  it('renders paginated asset table and opens graph detail', async () => {
    renderAssets();
    expect(await screen.findByText('Example')).toBeInTheDocument();
    expect(screen.queryByText('203.0.113.10')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('tab', { name: /IP 资产 1/ }));
    expect(await screen.findByText('Edge IP')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('tab', { name: /域名资产 1/ }));
    await screen.findByText('Example');

    await userEvent.click(screen.getByText('Example'));

    const drawer = await screen.findByRole('dialog');
    expect(within(drawer).getByText('资产详情 · Example')).toBeInTheDocument();
    await userEvent.click(within(drawer).getByRole('tab', { name: '关系 1' }));
    expect(screen.getByTestId('asset-graph')).toBeInTheDocument();
    const relationList = screen.getByRole('list', { name: '关系列表' });
    expect(relationList).toHaveTextContent('Example');
    expect(relationList).toHaveTextContent('Edge IP');
    expect(relationList).toHaveTextContent('解析到');
    expect(screen.queryByText('Asset 2')).not.toBeInTheDocument();
  });

  it('previews and commits a batch import with per-row results', async () => {
    renderAssets();
    await screen.findByText('Example');
    await userEvent.click(screen.getByRole('button', { name: '导入' }));

    const drawer = await screen.findByText('导入资产');
    expect(drawer).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: '批量粘贴' }));
    await userEvent.click(screen.getByRole('button', { name: '预览' }));

    expect(await screen.findByText('invalid asset type')).toBeInTheDocument();
    const stats = screen.getByText('失败').closest('.ant-statistic');
    if (!stats) throw new Error('missing failed import statistic');
    expect(within(stats as HTMLElement).getByText('1')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '确认导入' }));
    expect(await screen.findByText('imported')).toBeInTheDocument();
  });

  it('passes pagination parameters to backend', async () => {
    let seenPageSize = '';
    server.use(
      http.get('/api/v1/projects/1/assets', ({ request }) => {
        const url = new URL(request.url);
        seenPageSize = url.searchParams.get('page_size') ?? '';
        return HttpResponse.json({
          request_id: 'req-assets',
          data: { items: assetRows.slice(0, 1), total: 1, page_size: Number(seenPageSize), page_number: 1 }
        });
      })
    );
    renderAssets();
    await screen.findByText('Example');
    await waitFor(() => expect(seenPageSize).toBe('20'));
  });
  it('shows field validation without a service failure for an empty import', async () => {
    const previewRequest = vi.fn();
    server.use(http.post('*/projects/:projectId/assets/import', () => { previewRequest(); return HttpResponse.json({}); }));
    renderAssets();
    await userEvent.click(await screen.findByRole('button', { name: '导入' }));
    await userEvent.click(screen.getByRole('button', { name: '预览' }));
    expect(await screen.findByText('请输入资产值')).toBeInTheDocument();
    expect(screen.queryByText('导入预览失败')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '确认导入' })).toBeDisabled();
    expect(previewRequest).not.toHaveBeenCalled();
  });

  it('sends the visible asset keyword and clears the URL filter on reset', async () => {
    const requests: string[] = [];
    server.use(http.get('/api/v1/projects/1/assets', ({ request }) => {
      const keyword = new URL(request.url).searchParams.get('keyword') ?? '';
      requests.push(keyword);
      return HttpResponse.json({ data: { items: keyword ? [] : assetRows, total: keyword ? 0 : assetRows.length, page_size: 20, page_number: 1 } });
    }));
    renderAssets('/projects/1/assets?q=old-search');
    const input = await screen.findByLabelText('关键词');
    expect(input).toHaveValue('old-search');
    await userEvent.clear(input);
    await userEvent.type(input, 'no-match');
    await userEvent.click(screen.getByRole('button', { name: /查.*询/ }));
    await waitFor(() => expect(requests.at(-1)).toBe('no-match'));
    await userEvent.click(screen.getByRole('button', { name: /重.*置/ }));
    await waitFor(() => expect(requests.at(-1)).toBe(''));
    expect(await screen.findByText('Example')).toBeInTheDocument();
    const globalSearch = screen.getByLabelText('全局搜索');
    await userEvent.type(globalSearch, 'asset:prefixed-search{enter}');
    await waitFor(() => expect(requests.at(-1)).toBe('prefixed-search'));
    expect(globalSearch).toHaveValue('prefixed-search');
    expect(screen.getByLabelText('关键词')).toHaveValue('prefixed-search');
    await userEvent.click(screen.getByRole('button', { name: /重.*置/ }));
    await waitFor(() => expect(globalSearch).toHaveValue(''));
    await waitFor(() => expect(requests.at(-1)).toBe(''));
  });

  it('invalidates a preview when single import data changes and submits only the new preview', async () => {
    const user = userEvent.setup();
    const submitted: string[] = [];
    server.use(http.post('/api/v1/projects/1/assets/import', async ({ request }) => {
      const body = await request.json() as { rows: Array<{ value: string }> };
      const value = body.rows[0].value;
      if (new URL(request.url).searchParams.has('dry_run')) {
        return HttpResponse.json({ data: { total: 1, new: 1, update: 0, duplicate: 0, failed: 0, rows: [{ index: 0, status: 'new', value }] } });
      }
      submitted.push(value);
      return HttpResponse.json({ data: { total: 1, success: 1, failed: 0, rows: [] } });
    }));
    renderAssets();
    await userEvent.click(await screen.findByRole('button', { name: '导入' }));
    const input = screen.getByLabelText('资产值');
    await user.click(input);
    await user.paste('before.example.com');
    await userEvent.click(screen.getByRole('button', { name: '预览' }));
    await waitFor(() => expect(screen.getByRole('button', { name: '确认导入' })).toBeEnabled());
    await userEvent.clear(input);
    await user.click(input);
    await user.paste('after.example.com');
    expect(screen.getByRole('button', { name: '确认导入' })).toBeDisabled();
    expect(screen.queryByText('before.example.com')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '预览' }));
    await waitFor(() => expect(screen.getByRole('button', { name: '确认导入' })).toBeEnabled());
    await userEvent.click(screen.getByRole('button', { name: '确认导入' }));
    await waitFor(() => expect(submitted).toEqual(['after.example.com']));
  });

  it('ignores an in-flight preview after the input changes', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const started = vi.fn();
    server.use(http.post('/api/v1/projects/1/assets/import', async () => {
      started();
      await gate;
      return HttpResponse.json({ data: { total: 1, new: 1, update: 0, duplicate: 0, failed: 0, rows: [{ index: 0, status: 'new', value: 'stale.example.com' }] } });
    }));
    renderAssets();
    await userEvent.click(await screen.findByRole('button', { name: '导入' }));
    const input = screen.getByLabelText('资产值');
    await userEvent.type(input, 'stale.example.com');
    await userEvent.click(screen.getByRole('button', { name: '预览' }));
    await waitFor(() => expect(started).toHaveBeenCalled());
    await userEvent.clear(input);
    release();
    await waitFor(() => expect(screen.getByRole('button', { name: '确认导入' })).toBeDisabled());
    expect(screen.queryByText('stale.example.com')).not.toBeInTheDocument();
  });

  it('clears an incompatible type filter when switching asset categories', async () => {
    renderAssets('/projects/1/assets?view=domains&asset_type=domain');
    await screen.findByText('Example');
    await userEvent.click(screen.getByRole('tab', { name: /IP 资产 1/ }));
    expect(await screen.findByText('Edge IP')).toBeInTheDocument();
    expect(screen.queryByLabelText('已应用的资产筛选')).not.toBeInTheDocument();
  });

  it('opens a linked asset and preserves base details if its graph fails', async () => {
    server.use(http.get('/api/v1/projects/1/assets/1/graph', () => HttpResponse.json({error:{message:'关系服务暂不可用'}},{status:503})));
    renderAssets('/projects/1/assets?view=domains&asset_id=1');
    const drawer = await screen.findByRole('dialog');
    expect(await within(drawer).findByText('example.com')).toBeInTheDocument();
    expect(within(drawer).getByText('alice')).toBeInTheDocument();
    await userEvent.click(within(drawer).getByRole('tab', { name: '关系' }));
    expect(await within(drawer).findByText('关联信息加载失败')).toBeInTheDocument();
  });

  it('edits management fields and sends only the changed ones', async () => {
    const patches: unknown[] = [];
    let listRequests = 0;
    server.use(
      http.get('/api/v1/projects/1/assets', () => {
        listRequests += 1;
        return HttpResponse.json({ data: { items: assetRows.slice(0, 1), total: 1, page_size: 20, page_number: 1 } });
      }),
      http.patch('/api/v1/projects/1/assets/1', async ({ request }) => {
        const body = await request.json() as Record<string, string>;
        patches.push(body);
        return HttpResponse.json({ data: { ...assetRows[0], ...body } });
      })
    );
    renderAssets('/projects/1/assets?view=domains&asset_id=1');
    const drawer = await screen.findByRole('dialog');
    expect(await within(drawer).findByText('手动维护')).toBeInTheDocument();
    await userEvent.click(within(drawer).getByRole('button', { name: /编辑/ }));
    const owner = within(drawer).getByLabelText('负责人');
    await userEvent.clear(owner);
    await userEvent.type(owner, 'carol');
    const requestsBeforeSave = listRequests;
    await userEvent.click(within(drawer).getByRole('button', { name: /保.*存/ }));

    await waitFor(() => expect(patches).toEqual([{ owner: 'carol' }]));
    expect(await within(drawer).findByText('carol')).toBeInTheDocument();
    expect(within(drawer).queryByLabelText('负责人')).not.toBeInTheDocument();
    await waitFor(() => expect(listRequests).toBeGreaterThan(requestsBeforeSave));
  });

  it('asks for confirmation before ignoring an asset', async () => {
    const patches: unknown[] = [];
    server.use(http.patch('/api/v1/projects/1/assets/1', async ({ request }) => {
      const body = await request.json() as Record<string, string>;
      patches.push(body);
      return HttpResponse.json({ data: { ...assetRows[0], ...body } });
    }));
    renderAssets('/projects/1/assets?view=domains&asset_id=1');
    const drawer = await screen.findByRole('dialog');
    await userEvent.click(await within(drawer).findByRole('button', { name: /编辑/ }));
    await userEvent.click(within(drawer).getByRole('combobox'));
    await userEvent.click(await screen.findByTitle('已忽略'));
    expect(within(drawer).getByText('忽略后该资产不再计入纳管统计')).toBeInTheDocument();

    await userEvent.click(within(drawer).getByRole('button', { name: /保.*存/ }));
    expect(patches).toEqual([]);
    await userEvent.click(await screen.findByRole('button', { name: '确认忽略' }));
    await waitFor(() => expect(patches).toEqual([{ status: 'ignored' }]));
  });

  it('hides editing without asset write permission', async () => {
    localStorage.setItem('asm.auth', JSON.stringify({
      user: { id: 'u1', name: 'Alice', role: 'viewer', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [Permission.AssetRead, Permission.ReportRead]
    }));
    render(
      <MemoryRouter initialEntries={['/projects/1/assets?view=domains&asset_id=1']}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    );
    const drawer = await screen.findByRole('dialog');
    expect(await within(drawer).findByText('example.com')).toBeInTheDocument();
    expect(within(drawer).queryByRole('button', { name: /编辑/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '导入' })).not.toBeInTheDocument();
  });

  it('lists risks raised on the asset when the user can read risks', async () => {
    const assetIds: string[] = [];
    server.use(http.get('/api/v1/projects/1/risks', ({ request }) => {
      assetIds.push(new URL(request.url).searchParams.get('asset_id') ?? '');
      return HttpResponse.json({ data: { items: [{ id: 7, project_id: 1, risk_key: 'r7', title: 'RDP open to internet', severity: 'critical', status: 'new', owner: '', business_unit: '', score: 95, created_at: '2026-07-08T00:00:00Z' }], total: 1, page_size: 50, page_number: 1 } });
    }));
    localStorage.setItem('asm.auth', JSON.stringify({
      user: { id: 'u1', name: 'Alice', role: 'project_owner', projectId: 1 },
      accessToken: 'token',
      refreshToken: 'refresh',
      permissions: [Permission.AssetRead, Permission.RiskRead, Permission.ReportRead]
    }));
    render(
      <MemoryRouter initialEntries={['/projects/1/assets?view=domains&asset_id=1']}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    );
    const drawer = await screen.findByRole('dialog');
    await userEvent.click(await within(drawer).findByRole('tab', { name: '关联风险' }));
    expect(await within(drawer).findByRole('link', { name: 'RDP open to internet' })).toHaveAttribute('href', '/projects/1/risks?risk_id=7');
    expect(assetIds).toEqual(['1']);
  });

  it('toggles a status filter from the overview counts', async () => {
    const statuses: string[] = [];
    server.use(http.get('/api/v1/projects/1/assets', ({ request }) => {
      statuses.push(new URL(request.url).searchParams.get('status') ?? '');
      return HttpResponse.json({ data: { items: assetRows, total: assetRows.length, page_size: 20, page_number: 1 } });
    }));
    renderAssets('/projects/1/assets?view=all');
    await screen.findByText('Example');
    const inactive = within(screen.getByLabelText('资产概况')).getByRole('button', { name: /不活跃/ });
    await userEvent.click(inactive);
    await waitFor(() => expect(statuses.at(-1)).toBe('inactive'));
    expect(inactive).toHaveAttribute('aria-pressed', 'true');
    await userEvent.click(inactive);
    await waitFor(() => expect(statuses.at(-1)).toBe(''));
  });

  it('pins asset_type for single-type views and remembers the last view', async () => {
    const types: string[] = [];
    server.use(http.get('/api/v1/projects/1/assets', ({ request }) => {
      types.push(new URL(request.url).searchParams.get('asset_type') ?? '');
      return HttpResponse.json({ data: { items: [], total: 0, page_size: 20, page_number: 1 } });
    }));
    const { unmount } = renderAssets('/projects/1/assets');
    await userEvent.click(await screen.findByRole('tab', { name: /端口 0/ }));
    await waitFor(() => expect(types.at(-1)).toBe('port'));
    unmount();

    renderAssets('/projects/1/assets');
    await waitFor(() => expect(screen.getByRole('tab', { name: /端口 0/ })).toHaveAttribute('aria-selected', 'true'));
    expect(screen.queryByRole('button', { name: /导出/ })).not.toBeInTheDocument();
  });

});
