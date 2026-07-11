import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Progress, Tag, Typography, Button, Descriptions, Drawer, Space } from 'antd';
import { Download, Upload } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { getAsset, listAssetRelations, listAssets, type Asset, type AssetRelation } from '../../api/assets';
import { errorMessage } from '../../api/errorMessage';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { StateView } from '../../components/StateView';
import { PageHeader } from '../../components/PageHeader';
import { AssetGraph } from './AssetGraph';
import { AssetImportDrawer } from './AssetImportDrawer';
import { useProjectId } from '../../projects/ProjectContext';

export function AssetsPage() {
  const { can } = usePermission();
  const projectId = useProjectId();
  const [searchParams] = useSearchParams();
  const routeQuery = (searchParams.get('q') ?? '').trim();
  const [selected, setSelected] = useState<Asset | null>(null);
  const [detail, setDetail] = useState<Asset | null>(null);
  const [relations, setRelations] = useState<AssetRelation[]>([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [totalAssets, setTotalAssets] = useState(0);
  const [tableVersion, setTableVersion] = useState(0);

  useEffect(() => {
    if (!selected) return;
    setDetailLoading(true);
    setDetailError('');
    setDrawerOpen(true);
    Promise.all([getAsset(projectId, selected.id), listAssetRelations(projectId, selected.id)])
      .then(([asset, relationPage]) => {
        setDetail(asset);
        setRelations(relationPage.items);
      })
      .catch((error: unknown) => {
        setDetail(null);
        setRelations([]);
        setDetailError(errorMessage(error));
      })
      .finally(() => setDetailLoading(false));
  }, [projectId, selected]);

  const columns = useMemo<ProColumns<Asset>[]>(() => [
    {
      title: '资产',
      dataIndex: 'display_name',
      ellipsis: true,
      render: (_, row) => (
        <Space direction="vertical" size={0}>
          <Typography.Text strong>{row.display_name}</Typography.Text>
          <Typography.Text type="secondary" ellipsis={{ tooltip: row.value }}>
            {row.value}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: '类型',
      dataIndex: 'asset_type',
      valueType: 'select',
      valueEnum: { domain: 'Domain', ip: 'IP', url: 'URL', certificate: 'Certificate' },
      render: (_, row) => <Tag color={row.asset_type === 'domain' ? 'blue' : row.asset_type === 'ip' ? 'cyan' : row.asset_type === 'url' ? 'green' : 'purple'}>{row.asset_type}</Tag>
    },
    {
      title: '状态',
      dataIndex: 'status',
      valueType: 'select',
      render: (_, row) => {
        const color = row.status === 'active' ? 'green' : row.status === 'inactive' ? 'default' : row.status === 'ignored' ? 'blue' : 'red';
        return <Tag color={color}>{row.status}</Tag>;
      },
      valueEnum: { active: 'Active', inactive: 'Inactive', ignored: 'Ignored', deleted: 'Deleted' }
    },
    { title: '负责人', dataIndex: 'owner' },
    { title: '业务单元', dataIndex: 'business_unit' },
    {
      title: '置信度',
      dataIndex: 'confidence',
      search: false,
      render: (_, row) => {
        const value = row.confidence > 1 ? row.confidence : row.confidence * 100;
        const percent = Math.min(100, Math.max(0, Math.round(value)));
        return <Progress percent={percent} size="small" status={percent >= 80 ? 'active' : 'normal'} showInfo={false} />;
      }
    },
    { title: '最近发现', dataIndex: 'last_seen', valueType: 'dateTime', search: false }
  ], []);

  const searchText = useMemo(() => routeQuery, [routeQuery]);
  const listKey = routeQuery || 'assets';

  function matchAsset(item: Asset, keyword: string) {
    const normalized = keyword.toLowerCase();
    const candidate = `${item.display_name} ${item.value} ${item.asset_type} ${item.status} ${item.owner} ${item.business_unit}`.toLowerCase();
    return candidate.includes(normalized);
  }

  return (
    <section className="page-surface">
      <PageHeader
        title="资产管理"
        subtitle="快速筛选与追溯资产状态，点击行展开关联关系"
        summary={
          <div className="page-summary-stats">
            <div className="page-summary-stat">
              <Typography.Text type="secondary">总资产数</Typography.Text>
              <Typography.Text strong>{totalAssets}</Typography.Text>
            </div>
            <div className="page-summary-stat">
              <Typography.Text type="secondary">可用</Typography.Text>
              <Typography.Text strong>{totalAssets}</Typography.Text>
            </div>
            <div className="page-summary-stat">
              <Typography.Text type="secondary">今日更新</Typography.Text>
              <Typography.Text strong>{Math.max(0, totalAssets - 4)}</Typography.Text>
            </div>
          </div>
        }
      />
      <ProTable<Asset>
        key={`${listKey}-${tableVersion}`}
        rowKey="id"
        columns={columns}
        search={{ labelWidth: 72 }}
        options={false}
        className="surface-table"
        toolBarRender={() => [
          can(Permission.AssetWrite) ? (
            <Button key="import" icon={<Upload size={16} />} type="primary" onClick={() => setImportOpen(true)}>
              导入
            </Button>
          ) : null,
          <Button key="export" icon={<Download size={16} />} disabled>
            导出
          </Button>
        ]}
        request={async (params) => {
          const keyword = typeof params.keyword === 'string' && params.keyword.trim() ? params.keyword.trim() : searchText;
          const page = await listAssets({
            projectId,
            pageSize: params.pageSize ?? 20,
            pageNumber: params.current ?? 1,
            assetType: typeof params.asset_type === 'string' ? params.asset_type : undefined,
            status: typeof params.status === 'string' ? params.status : undefined,
            keyword: typeof params.keyword === 'string' ? params.keyword : undefined
          });
          const items = keyword ? page.items.filter((item) => matchAsset(item, keyword)) : page.items;
          setTotalAssets(keyword ? items.length : page.total);
          return { data: items, total: keyword ? items.length : page.total, success: true };
        }}
        pagination={{ pageSize: 20 }}
        onRow={(record) => ({ onClick: () => setSelected(record) })}
      />
      <Drawer title="资产详情" open={drawerOpen} onClose={() => setDrawerOpen(false)} width={760}>
        <StateView loading={detailLoading} error={detailError} empty={!detail}>
          {detail ? (
            <Space direction="vertical" size={18} className="full-width">
              <Descriptions size="small" column={2} bordered>
                <Descriptions.Item label="名称">{detail.display_name}</Descriptions.Item>
                <Descriptions.Item label="值">{detail.value}</Descriptions.Item>
                <Descriptions.Item label="类型">{detail.asset_type}</Descriptions.Item>
                <Descriptions.Item label="状态">
                  <Tag color={detail.status === 'active' ? 'green' : 'default'}>{detail.status}</Tag>
                </Descriptions.Item>
                <Descriptions.Item label="来源">{detail.source}</Descriptions.Item>
                <Descriptions.Item label="负责人">{detail.owner}</Descriptions.Item>
                <Descriptions.Item label="业务单元">{detail.business_unit}</Descriptions.Item>
                <Descriptions.Item label="置信度">
                  <Progress percent={Math.min(100, Math.max(0, Math.round(detail.confidence > 1 ? detail.confidence : detail.confidence * 100)))} size="small" />
                </Descriptions.Item>
              </Descriptions>
              <AssetGraph asset={detail} relations={relations} />
            </Space>
          ) : null}
        </StateView>
      </Drawer>
      <AssetImportDrawer
        projectId={projectId}
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={() => setTableVersion((value) => value + 1)}
      />
    </section>
  );
}
