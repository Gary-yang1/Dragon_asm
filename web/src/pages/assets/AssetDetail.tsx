import { Alert, Button, Descriptions, Form, Input, Popconfirm, Progress, Select, Space, Tabs, Tooltip, message } from 'antd';
import { Pencil } from 'lucide-react';
import { useState, type ReactNode } from 'react';

import { updateAsset, type Asset, type AssetGraphData, type AssetUpdateInput } from '../../api/assets';
import { errorMessage } from '../../api/errorMessage';
import { AssetRiskList } from '../../components/AssetRiskList';
import { EnumChip } from '../../components/StatusChip';
import { assetSourceMeta, assetStatusMeta, assetTypeMeta, describe } from '../../utils/taxonomy';
import { AssetGraph } from './AssetGraph';

// Mirrors the column widths enforced by internal/asset/service.go so overflow is
// caught in the form instead of surfacing as a 422.
const maxDisplayNameLen = 255;
const maxOwnerLen = 64;
const maxBusinessUnitLen = 128;

const editableStatuses = ['active', 'inactive', 'ignored'];

type EditValues = Required<AssetUpdateInput>;

type AssetDetailProps = {
  projectId: number;
  asset: Asset;
  graph: AssetGraphData | null;
  graphError: string;
  canEdit: boolean;
  canReadRisks: boolean;
  onRetryGraph: () => void;
  onUpdated: (asset: Asset) => void;
};

export function AssetDetail({ projectId, asset, graph, graphError, canEdit, canReadRisks, onRetryGraph, onUpdated }: AssetDetailProps) {
  return (
    <Tabs
      className="asset-detail-tabs"
      items={[
        {
          key: 'overview',
          label: '概览',
          children: <AssetOverview key={asset.id} projectId={projectId} asset={asset} canEdit={canEdit} onUpdated={onUpdated} />
        },
        {
          key: 'relations',
          label: `关系${graph ? ` ${graph.edges.length}` : ''}`,
          children: graphError
            ? <Alert type="warning" message="关联信息加载失败" description={graphError} action={<Button onClick={onRetryGraph}>重试</Button>} />
            : <AssetGraph graph={graph} projectId={projectId} />
        },
        ...(canReadRisks ? [{
          key: 'risks',
          label: '关联风险',
          children: <AssetRiskList projectId={projectId} assetId={asset.id} />
        }] : [])
      ]}
    />
  );
}

function AssetOverview({ projectId, asset, canEdit, onUpdated }: Omit<AssetDetailProps, 'graph' | 'graphError' | 'onRetryGraph' | 'canReadRisks'>) {
  const confidence = Math.min(100, Math.max(0, Math.round(asset.confidence > 1 ? asset.confidence : asset.confidence * 100)));
  return (
    <Space direction="vertical" size={18} className="full-width">
      <AssetManagementCard projectId={projectId} asset={asset} canEdit={canEdit} onUpdated={onUpdated} />
      <Descriptions size="small" column={2} bordered>
        <Descriptions.Item label="值" span={2}>{asset.value}</Descriptions.Item>
        <Descriptions.Item label="类型">{describe(assetTypeMeta, asset.asset_type).label}</Descriptions.Item>
        <Descriptions.Item label="来源">{describe(assetSourceMeta, asset.source).label}</Descriptions.Item>
        <Descriptions.Item label="首次发现">{formatTime(asset.first_seen)}</Descriptions.Item>
        <Descriptions.Item label="最近发现">{formatTime(asset.last_seen)}</Descriptions.Item>
        <Descriptions.Item label={<Tooltip title="连续多次发现任务未再观测到该资产的次数，达到阈值后资产转为不活跃">连续未发现</Tooltip>}>
          {asset.miss_count > 0 ? `${asset.miss_count} 次` : '无'}
        </Descriptions.Item>
        <Descriptions.Item label="置信度">
          <Progress percent={confidence} size="small" />
        </Descriptions.Item>
      </Descriptions>
    </Space>
  );
}

type AssetManagementCardProps = {
  projectId: number;
  asset: Asset;
  canEdit: boolean;
  onUpdated: (asset: Asset) => void;
  /** Read-only rows appended after the editable fields, e.g. ownership context. */
  extra?: ReactNode;
};

/** Owner, business unit and lifecycle status, editable in place by asset writers. */
export function AssetManagementCard({ projectId, asset, canEdit, onUpdated, extra }: AssetManagementCardProps) {
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [form] = Form.useForm<EditValues>();
  const nextStatus = Form.useWatch('status', form);
  const ignoring = editing && nextStatus === 'ignored' && asset.status !== 'ignored';

  function startEdit() {
    setSaveError('');
    setEditing(true);
  }

  async function save() {
    if (saving) return;
    const values = await form.validateFields();
    // Send only what changed so the audit record lists the fields the operator
    // actually touched.
    const changed: AssetUpdateInput = {};
    for (const key of ['display_name', 'owner', 'business_unit', 'status'] as const) {
      const value = (values[key] ?? '').trim();
      if (value !== (asset[key] ?? '')) changed[key] = value;
    }
    if (Object.keys(changed).length === 0) {
      setEditing(false);
      return;
    }
    setSaving(true);
    setSaveError('');
    try {
      const updated = await updateAsset(projectId, asset.id, changed);
      onUpdated(updated);
      setEditing(false);
      message.success('资产信息已更新');
    } catch (error) {
      setSaveError(errorMessage(error));
    } finally {
      setSaving(false);
    }
  }

  if (editing) {
    return (
      <Space direction="vertical" size={12} className="full-width">
        {saveError ? <Alert type="error" showIcon message="保存失败" description={saveError} /> : null}
        <Form
          form={form}
          layout="vertical"
          disabled={saving}
          className="asset-edit-form"
          initialValues={{ display_name: asset.display_name, owner: asset.owner, business_unit: asset.business_unit, status: asset.status }}
        >
          <Form.Item name="display_name" label="显示名称" rules={[{ max: maxDisplayNameLen }]} extra="留空时列表显示资产值">
            <Input placeholder={asset.value} />
          </Form.Item>
          <Form.Item name="owner" label="负责人" rules={[{ max: maxOwnerLen }]}>
            <Input placeholder="未设置" />
          </Form.Item>
          <Form.Item name="business_unit" label="业务单元" rules={[{ max: maxBusinessUnitLen }]}>
            <Input placeholder="未设置" />
          </Form.Item>
          <Form.Item name="status" label="管理状态" rules={[{ required: true }]}>
            <Select options={editableStatuses.map((value) => ({ value, label: describe(assetStatusMeta, value).label }))} />
          </Form.Item>
          {ignoring ? (
            <Alert
              type="warning"
              showIcon
              message="忽略后该资产不再计入纳管统计"
              description="之后的发现任务或导入再次命中该资产时，状态仍保持为已忽略，需要手动恢复。"
            />
          ) : null}
        </Form>
        <Space>
          <Popconfirm
            title="确认忽略该资产？"
            okText="确认忽略"
            okButtonProps={{ danger: true }}
            disabled={!ignoring}
            onConfirm={() => void save()}
          >
            <Button type="primary" loading={saving} onClick={ignoring ? undefined : () => void save()}>保存</Button>
          </Popconfirm>
          <Button disabled={saving} onClick={() => setEditing(false)}>取消</Button>
        </Space>
      </Space>
    );
  }

  return (
    <Descriptions
      size="small"
      column={2}
      bordered
      title="管理信息"
      extra={canEdit ? <Button size="small" icon={<Pencil size={14} />} onClick={startEdit}>编辑</Button> : null}
    >
      <Descriptions.Item label="显示名称">{asset.display_name || asset.value}</Descriptions.Item>
      <Descriptions.Item label="管理状态"><EnumChip map={assetStatusMeta} value={asset.status} /></Descriptions.Item>
      <Descriptions.Item label="负责人">{asset.owner || <span className="secondary-text">未设置</span>}</Descriptions.Item>
      <Descriptions.Item label="业务单元">{asset.business_unit || <span className="secondary-text">未设置</span>}</Descriptions.Item>
      {extra}
    </Descriptions>
  );
}

export function formatTime(value: string) {
  return value ? new Date(value).toLocaleString() : '未记录';
}
