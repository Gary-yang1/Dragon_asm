import { ProTable, type ActionType, type ProColumns } from '@ant-design/pro-components';
import { Alert, Button, Drawer, Segmented, Space, Tabs, Tag, Typography } from 'antd';
import { Upload } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import {
  getAsset,
  getAssetGraph,
  getAssetSummary,
  listAssets,
  type Asset,
  type AssetGraphData,
  type AssetListQuery,
  type AssetSummary
} from '../../api/assets';
import { errorMessage } from '../../api/errorMessage';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StateView } from '../../components/StateView';
import { ConfidenceMeter, EnumChip } from '../../components/StatusChip';
import { useProjectId } from '../../projects/ProjectContext';
import { assetSourceMeta, assetStatusMeta, assetTypeMeta, describe, toValueEnum } from '../../utils/taxonomy';
import { AssetDetail } from './AssetDetail';
import { AssetImportDrawer } from './AssetImportDrawer';
import { WebResults } from '../../components/WebResults';

type AssetView = 'domains' | 'ips' | 'ports' | 'services' | 'web' | 'certificates' | 'external' | 'all';

// Single-type views pin asset_type instead of a category; the type filter is
// hidden for them because there is nothing left to narrow.
const assetViews: Array<{ key: AssetView; label: string; category?: AssetListQuery['category']; assetType?: string }> = [
  { key: 'domains', label: '域名资产', category: 'domains' },
  { key: 'ips', label: 'IP 资产', category: 'ips' },
  { key: 'ports', label: '端口', assetType: 'port' },
  { key: 'services', label: '服务', assetType: 'service' },
  { key: 'web', label: 'Web 资产', category: 'web' },
  { key: 'certificates', label: '证书', assetType: 'certificate' },
  { key: 'external', label: '云与第三方', category: 'external' },
  { key: 'all', label: '全部资产' }
];

const lastViewKey = 'asm.assetView';

function isAssetView(value: string | null): value is AssetView {
  return assetViews.some((item) => item.key === value);
}

function parseAssetView(value: string | null): AssetView {
  if (isAssetView(value)) return value;
  try {
    const remembered = localStorage.getItem(lastViewKey);
    if (isAssetView(remembered)) return remembered;
  } catch { /* Fall back to the default view when storage is unavailable. */ }
  return 'domains';
}

function viewCount(view: AssetView, summary: AssetSummary | null) {
  if (!summary) return undefined;
  switch (view) {
    case 'domains':
      return summary.by_type.domain + summary.by_type.subdomain;
    case 'ips':
      return summary.by_type.ip;
    case 'ports':
      return summary.by_type.port;
    case 'services':
      return summary.by_type.service;
    case 'certificates':
      return summary.by_type.certificate;
    case 'web':
      return summary.by_type.web;
    case 'external':
      return summary.by_type.cloud_resource + summary.by_type.third_party;
    case 'all':
      return summary.inventory.total;
  }
}

export function AssetsPage() {
  const { can } = usePermission();
  const projectId = useProjectId();
  const [searchParams, setSearchParams] = useSearchParams();
  const routeQuery = (searchParams.get('q') ?? '').trim();
  const activeView = parseAssetView(searchParams.get('view'));
  const activeViewMeta = assetViews.find((item) => item.key === activeView);
  const activeCategory = activeViewMeta?.category;
  const pinnedAssetType = activeViewMeta?.assetType;
  const tableAction = useRef<ActionType>();
  const selectedId = Number(searchParams.get('asset_id')) || 0;
  const [columnView, setColumnView] = useState('technical');
  const [graphError, setGraphError] = useState('');
  const [graphRevision, setGraphRevision] = useState(0);
  const openDetail = (asset: Asset) => {
    const next = new globalThis.URLSearchParams(searchParams);
    next.set('asset_id', String(asset.id));
    setSearchParams(next);
  };
  const [detail, setDetail] = useState<Asset | null>(null);
  const [graph, setGraph] = useState<AssetGraphData | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [listError, setListError] = useState('');
  const [summary, setSummary] = useState<AssetSummary | null>(null);
  const [summaryError, setSummaryError] = useState('');
  const [tableVersion, setTableVersion] = useState(0);
  const [summaryVersion, setSummaryVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setSummaryError('');
    getAssetSummary(projectId)
      .then((response) => {
        if (active) setSummary(response);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setSummary(null);
        setSummaryError(errorMessage(error));
      });
    return () => {
      active = false;
    };
  }, [projectId, summaryVersion]);

  useEffect(() => {
    if (selectedId <= 0) { setDrawerOpen(false); setDetail(null); setGraph(null); return; }
    let active = true;
    setDetailLoading(true);
    setDetailError('');
    setDetail(null);
    setDrawerOpen(true);
    getAsset(projectId, selectedId)
      .then((asset) => { if (active) setDetail(asset); })
      .catch((error: unknown) => { if (active) setDetailError(errorMessage(error)); })
      .finally(() => { if (active) setDetailLoading(false); });
    return () => {
      active = false;
    };
  }, [projectId, selectedId]);

  useEffect(() => {
    if (selectedId <= 0) return;
    let active = true;
    setGraphError('');
    setGraph(null);
    getAssetGraph(projectId, selectedId)
      .then((assetGraph) => { if (active) setGraph(assetGraph); })
      .catch((error: unknown) => { if (active) setGraphError(errorMessage(error)); });
    return () => {
      active = false;
    };
  }, [projectId, selectedId, graphRevision]);

  const columns: ProColumns<Asset>[] = (() => {
    const common: ProColumns<Asset>[] = [
      {
        // Search-only field: the server matches the keyword against name, value,
        // owner and business unit, so labelling it "资产" undersold it.
        title: '关键词',
        dataIndex: 'keyword',
        hideInTable: true,
        fieldProps: { placeholder: '名称 / 值 / 负责人 / 业务单元' }
      },
      {
        title: '资产',
        dataIndex: 'display_name',
        search: false,
        width: '27%',
        ellipsis: true,
        render: (_, row) => (
          <Space direction="vertical" size={0}>
            <Button type="link" className="table-detail-link" onClick={(event) => { event.stopPropagation(); openDetail(row); }}>{row.display_name || row.value}</Button>
            {row.value && row.value !== row.display_name ? (
              <Typography.Text type="secondary" ellipsis={{ tooltip: row.value }}>
                {row.value}
              </Typography.Text>
            ) : null}
          </Space>
        )
      },
      {
        title: '类型',
        dataIndex: 'asset_type',
        valueType: 'select',
        valueEnum: toValueEnum(assetTypeMeta),
        hideInSearch: activeView !== 'domains' && activeView !== 'all',
        hideInTable: Boolean(pinnedAssetType),
        render: (_, row) => <EnumChip map={assetTypeMeta} value={row.asset_type} variant="outline" />
      },
      {
        title: '管理状态',
        dataIndex: 'status',
        valueType: 'select',
        render: (_, row) => <EnumChip map={assetStatusMeta} value={row.status} />,
        valueEnum: toValueEnum(assetStatusMeta)
      },
      { title: '负责人', dataIndex: 'owner', search: false, hideInTable: columnView !== 'governance' },
      { title: '业务单元', dataIndex: 'business_unit', search: false, hideInTable: columnView !== 'governance' },
      {
        title: '置信度',
        dataIndex: 'confidence',
        hideInTable: columnView !== 'governance',
        search: false,
        width: 130,
        render: (_, row) => {
          const value = row.confidence > 1 ? row.confidence : row.confidence * 100;
          return <ConfidenceMeter value={value} />;
        }
      },
      { title: '发现来源', dataIndex: 'source', search: false, hideInTable: columnView !== 'technical', renderText: (value: string) => (value ? describe(assetSourceMeta, value).label : '未记录') },
      { title: '关联信息', key: 'related', search: false, hideInTable: columnView !== 'technical', render: (_, row) => <Space><Button type="link" size="small" onClick={event => { event.stopPropagation(); openDetail(row); }}>查看关联</Button>{['domain', 'subdomain', 'ip'].includes(row.asset_type) && <Link onClick={event => event.stopPropagation()} to={`/projects/${projectId}/assets?view=web&q=${encodeURIComponent(row.value)}`}>查找网站</Link>}</Space> },
      { title: '最近发现', dataIndex: 'last_seen', valueType: 'dateTime', search: false }
    ];
    return common;
  })();

  const selectView = (view: AssetView) => {
    try { localStorage.setItem(lastViewKey, view); } catch { /* View memory is best effort. */ }
    const next = new globalThis.URLSearchParams(searchParams);
    next.set('view', view);
    ['asset_type', 'status', 'asset_id', 'web_outcome', 'web_cdn', 'web_cloud', 'web_page'].forEach(key => next.delete(key));
    setSearchParams(next);
    setListError('');
  };

  const closeDetail = () => {
    setDrawerOpen(false);
    const next = new globalThis.URLSearchParams(searchParams);
    next.delete('asset_id');
    setSearchParams(next);
    setDetail(null);
    setGraph(null);
    setDetailError('');
  };

  const applyStatusFilter = (status: string) => {
    const next = new globalThis.URLSearchParams(searchParams);
    if (searchParams.get('status') === status) next.delete('status'); else next.set('status', status);
    next.delete('asset_id');
    if (activeView === 'web') next.set('view', 'all');
    setSearchParams(next);
  };

  const handleUpdated = (asset: Asset) => {
    setDetail(asset);
    setSummaryVersion((value) => value + 1);
    // reload keeps the current page; bumping the table key would reset to page 1.
    void tableAction.current?.reload();
  };

  const refreshAfterImport = () => {
    setTableVersion((value) => value + 1);
    setSummaryVersion((value) => value + 1);
  };

  const listKey = `${routeQuery || 'assets'}-${activeView}-${searchParams.get('asset_type') || ''}-${searchParams.get('status') || ''}`;

  return (
    <section className="page-surface asset-center-page">
      <PageHeader
        title="资产中心"
        subtitle="查看资产清单、归属与最近发现记录"
        actions={can(Permission.AssetWrite) ? <Button icon={<Upload size={16} />} type="primary" onClick={() => setImportOpen(true)}>导入</Button> : null}

      />

      {summaryError ? (
        <Alert
          type="error"
          showIcon
          message="资产统计加载失败"
          description="列表仍可使用，但不会用当前页数据冒充项目统计。"
          action={<Button size="small" onClick={() => setSummaryVersion((value) => value + 1)}>重试</Button>}
          className="list-error-alert"
        />
      ) : null}

      <AssetOverviewLine summary={summary} activeStatus={searchParams.get('status')} onStatusFilter={applyStatusFilter} />

      <Tabs
        className="asset-view-tabs"
        activeKey={activeView}
        onChange={(key) => selectView(key as AssetView)}
        items={assetViews.map((item) => {
          const count = viewCount(item.key, summary);
          return { key: item.key, label: count === undefined ? item.label : `${item.label} ${count}` };
        })}
      />

      {listError ? (
        <Alert
          type="error"
          showIcon
          message="资产列表加载失败"
          description={listError}
          action={<Button size="small" onClick={() => setTableVersion((value) => value + 1)}>重试</Button>}
          className="list-error-alert"
        />
      ) : null}

      {activeView !== 'web' && (routeQuery || searchParams.get('asset_type') || searchParams.get('status')) && <div className="asset-applied-filters" aria-label="已应用的资产筛选">{['q', 'asset_type', 'status'].filter(key => searchParams.get(key)).map(key => <Tag key={key} closable onClose={() => { const next = new globalThis.URLSearchParams(searchParams); next.delete(key); setSearchParams(next); }}>{key === 'q' ? `搜索：${routeQuery}` : describe(key === 'asset_type' ? assetTypeMeta : assetStatusMeta, searchParams.get(key)!).label}</Tag>)}</div>}
      {activeView === 'web' ? <WebResults key={`${projectId}-${tableVersion}`} projectId={projectId} /> : <ProTable<Asset>
        key={`${listKey}-${tableVersion}`}
        rowKey="id"
        scroll={{ x: 1000 }}
        columns={columns}
        search={{ labelWidth: 72 }}
        actionRef={tableAction}
        form={{ initialValues: { keyword: routeQuery, asset_type: searchParams.get('asset_type') || undefined, status: searchParams.get('status') || undefined } }}
        onSubmit={(values) => {
          const next = new globalThis.URLSearchParams(searchParams);
          const keyword = String(values.keyword ?? '').trim();
          if (keyword) next.set('q', keyword); else next.delete('q');
          for (const key of ['asset_type', 'status']) {
            if (values[key]) next.set(key, String(values[key])); else next.delete(key);
          }
          setSearchParams(next);
        }}
        onReset={() => {
          const next = new globalThis.URLSearchParams(searchParams);
          for (const key of ['q', ...['asset_type', 'status']]) next.delete(key);
          setSearchParams(next);
        }}
        options={false}
        className="surface-table"
        toolbar={{ title: '资产清单' }}
        toolBarRender={() => [<Segmented key="columns" aria-label="资产列视图" value={columnView} onChange={value => setColumnView(String(value))} options={[{label:'资产信息',value:'technical'},{label:'治理信息',value:'governance'}]} />]}
        request={async (params) => {
          const keyword = typeof params.keyword === 'string' ? params.keyword.trim() : routeQuery;
          try {
            const page = await listAssets({
              projectId,
              pageSize: params.pageSize ?? 20,
              pageNumber: params.current ?? 1,
              category: activeCategory,
              assetType: pinnedAssetType ?? (typeof params.asset_type === 'string' ? params.asset_type : undefined),
              status: typeof params.status === 'string' ? params.status : undefined,
              keyword: keyword || undefined
            });
            setListError('');
            return { data: page.items, total: page.total, success: true };
          } catch (error) {
            setListError(errorMessage(error));
            return { data: [], total: 0, success: false };
          }
        }}
        pagination={{ pageSize: 20 }}
        onRow={(record) => ({ onClick: () => openDetail(record) })}
      />}

      <Drawer className="asset-details-drawer" title={detail ? `资产详情 · ${detail.display_name || detail.value}` : '资产详情'} open={drawerOpen} onClose={closeDetail} width={860}>
        <StateView loading={detailLoading} error={detailError} empty={!detail}>
          {detail ? (
            <AssetDetail
              projectId={projectId}
              asset={detail}
              graph={graph}
              graphError={graphError}
              canEdit={can(Permission.AssetWrite)}
              canReadRisks={can(Permission.RiskRead)}
              onRetryGraph={() => setGraphRevision((value) => value + 1)}
              onUpdated={handleUpdated}
            />
          ) : null}
        </StateView>
      </Drawer>

      <AssetImportDrawer
        projectId={projectId}
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={refreshAfterImport}
      />
    </section>
  );
}

type OverviewMetric = { key: string; label: string; value: number | undefined; status?: string; hint?: string };

/** One line of project-wide counts; status counts double as list filters. */
function AssetOverviewLine({ summary, activeStatus, onStatusFilter }: { summary: AssetSummary | null; activeStatus: string | null; onStatusFilter: (status: string) => void }) {
  const metrics: OverviewMetric[] = [
    { key: 'managed', label: '纳管资产', value: summary?.inventory.managed_total, hint: '不含已忽略' },
    { key: 'active', label: '活跃', value: summary?.inventory.active, status: 'active' },
    { key: 'inactive', label: '不活跃', value: summary?.inventory.inactive, status: 'inactive' },
    { key: 'ignored', label: '已忽略', value: summary?.inventory.ignored, status: 'ignored' },
    { key: 'new', label: '24h 新增', value: summary?.freshness.new_24h },
    { key: 'stale', label: '30 天未发现', value: summary?.freshness.stale_30d },
    { key: 'unowned', label: '未设负责人', value: summary?.governance.unowned },
    { key: 'no-bu', label: '未设业务单元', value: summary?.governance.unassigned_business_unit },
    {
      key: 'low-confidence',
      label: '低置信度',
      value: summary?.governance.low_confidence,
      hint: summary ? `置信度低于 ${summary.governance.low_confidence_below}` : undefined
    }
  ];
  return (
    <div className="asset-overview-line" aria-label="资产概况">
      {metrics.map((metric) => {
        const content = <>{metric.label}<strong>{metric.value ?? '—'}</strong></>;
        if (!metric.status) return <span key={metric.key} title={metric.hint}>{content}</span>;
        const pressed = activeStatus === metric.status;
        return (
          <button
            key={metric.key}
            type="button"
            className={`asset-overview-filter${pressed ? ' is-active' : ''}`}
            aria-pressed={pressed}
            title={pressed ? '再次点击取消筛选' : `筛选${metric.label}资产`}
            onClick={() => onStatusFilter(metric.status!)}
          >
            {content}
          </button>
        );
      })}
    </div>
  );
}
