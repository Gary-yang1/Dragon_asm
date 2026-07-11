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

function renderAssets() {
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
    <MemoryRouter initialEntries={['/assets']}>
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
        return HttpResponse.json({
          request_id: 'req-assets',
          data: {
            items: assetRows,
            total: 2,
            page_size: Number(url.searchParams.get('page_size') ?? 20),
            page_number: Number(url.searchParams.get('page_number') ?? 1)
          }
        });
      }),
      http.get('/api/v1/projects/1/assets/1', () =>
        HttpResponse.json({
          request_id: 'req-asset',
          data: assetRows[0]
        })
      ),
      http.get('/api/v1/projects/1/assets/1/relations', () =>
        HttpResponse.json({
          request_id: 'req-relations',
          data: {
            items: [{ id: 10, project_id: 1, from_asset_id: 1, to_asset_id: 2, relation_type: 'resolves_to', source: 'manual', confidence: 90, direction: 'out' }],
            total: 1,
            page_size: 100,
            page_number: 1
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
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument();

    await userEvent.click(screen.getByText('Example'));

    expect(await screen.findByText('资产详情')).toBeInTheDocument();
    expect(screen.getByTestId('asset-graph')).toBeInTheDocument();
    expect(screen.getByText(/1 → 2/)).toBeInTheDocument();
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
});
