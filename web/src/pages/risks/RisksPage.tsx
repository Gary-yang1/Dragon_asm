import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Button, Descriptions, Drawer, Form, Input, Modal, Progress, Select, Space, Tag, Timeline, message, Typography } from 'antd';
import { AlertTriangle, Clock, FileText, History, Plus, Scale, ShieldCheck, Siren, UserPlus } from 'lucide-react';
import type { Key } from 'react';
import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import {
  batchAssignRisks,
  createManualRisk,
  createSuppressionRule,
  getRisk,
  listRisks,
  listSuppressionRules,
  transitionRisk,
  type Risk,
  type RiskDetail,
  type RiskSeverity,
  type SuppressionRule
} from '../../api/risks';
import { errorMessage } from '../../api/errorMessage';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StatCard } from '../../components/StatCard';
import { StateView } from '../../components/StateView';
import { useProjectId } from '../../projects/ProjectContext';

const severityColor: Record<string, string> = { low: 'cyan', medium: 'gold', high: 'volcano', critical: 'red' };

export function RisksPage() {
  const { can } = usePermission();
  const projectId = useProjectId();
  const [searchParams] = useSearchParams();
  const routeQuery = (searchParams.get('q') ?? '').trim();
  const [totalRisks, setTotalRisks] = useState(0);
  const [riskItems, setRiskItems] = useState<Risk[]>([]);
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([]);
  const [detail, setDetail] = useState<RiskDetail | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [manualOpen, setManualOpen] = useState(false);
  const [assignOpen, setAssignOpen] = useState(false);
  const [suppressionOpen, setSuppressionOpen] = useState(false);
  const [rules, setRules] = useState<SuppressionRule[]>([]);
  const [manualForm] = Form.useForm<{ title: string; severity: RiskSeverity; owner: string; evidence: string }>();
  const [assignForm] = Form.useForm<{ owner: string }>();
  const [suppressionForm] = Form.useForm<{ name: string; pattern: string; expires_at: string }>();
  const [reloadKey, setReloadKey] = useState(0);

  async function openDetail(row: Risk) {
    setDetailLoading(true);
    setDetailError('');
    setDetailOpen(true);
    try {
      const risk = await getRisk(projectId, row.id);
      setDetail(risk);
    } catch (error) {
      setDetail(null);
      setDetailError(errorMessage(error));
    } finally {
      setDetailLoading(false);
    }
  }

  async function submitTransition(action: string) {
    if (!detail) return;
    const updated = await transitionRisk(projectId, detail.id, action, 'operator action');
    setDetail(updated);
    setReloadKey((value) => value + 1);
    message.success('状态已更新');
  }

  async function submitManualRisk() {
    const values = await manualForm.validateFields();
    await createManualRisk(projectId, values);
    setManualOpen(false);
    manualForm.resetFields();
    setReloadKey((value) => value + 1);
    message.success('风险已创建');
  }

  async function submitBatchAssign() {
    const values = await assignForm.validateFields();
    await batchAssignRisks(projectId, selectedRowKeys.map(Number), values.owner);
    setAssignOpen(false);
    assignForm.resetFields();
    setSelectedRowKeys([]);
    setReloadKey((value) => value + 1);
    message.success('已批量分派');
  }

  async function openSuppressions() {
    const page = await listSuppressionRules(projectId);
    setRules(page.items);
    setSuppressionOpen(true);
  }

  async function submitSuppression() {
    const values = await suppressionForm.validateFields();
    const created = await createSuppressionRule(projectId, values);
    setRules((current) => [created, ...current]);
    suppressionForm.resetFields();
    message.success('抑制规则已创建');
  }

  const columns = useMemo<ProColumns<Risk>[]>(() => [
    {
      title: '风险',
      dataIndex: 'title',
      ellipsis: true,
      render: (_, row) => (
        <Space direction="vertical" size={0}>
          <Typography.Text strong>{row.title}</Typography.Text>
          <Typography.Text type="secondary">{row.business_unit}</Typography.Text>
        </Space>
      )
    },
    {
      title: '等级',
      dataIndex: 'severity',
      valueType: 'select',
      valueEnum: { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' },
      render: (_, row) => <Tag color={severityColor[row.severity]}>{row.severity}</Tag>
    },
    {
      title: '状态',
      dataIndex: 'status',
      valueType: 'select',
      valueEnum: { new: 'New', confirmed: 'Confirmed', assigned: 'Assigned', fixing: 'Fixing', risk_accepted: 'Accepted', false_positive: 'False Positive', fixed: 'Fixed', reopened: 'Reopened' },
      render: (_, row) => {
        const color = row.status === 'new' || row.status === 'confirmed' ? 'blue' : row.status === 'fixed' ? 'green' : row.status === 'false_positive' ? 'default' : 'orange';
        return <Tag color={color}>{row.status}</Tag>;
      }
    },
    { title: '负责人', dataIndex: 'owner' },
    { title: '业务单元', dataIndex: 'business_unit', search: false, ellipsis: true },
    {
      title: '评分',
      dataIndex: 'score',
      search: false,
      render: (_, row) => <Progress percent={Math.min(100, Math.max(0, row.score))} size="small" />
    },
    { title: 'SLA', dataIndex: 'sla_due_at', valueType: 'dateTime', search: false }
  ], []);

  const tableKey = routeQuery || 'risks';

  function matchRisk(item: Risk, keyword: string) {
    const normalized = keyword.toLowerCase();
    const candidate = `${item.title} ${item.severity} ${item.status} ${item.owner} ${item.business_unit}`.toLowerCase();
    return candidate.includes(normalized);
  }

  const riskKpis = useMemo(() => {
    const highCount = riskItems.filter((item) => item.severity === 'critical' || item.severity === 'high').length;
    const overdueCount = riskItems.filter((item) => item.sla_due_at && new Date(item.sla_due_at) < new Date()).length;
    return { open: totalRisks, high: highCount, overdue: overdueCount };
  }, [riskItems, totalRisks]);

  return (
    <section className="page-surface">
      <PageHeader
        title="风险中心"
        subtitle="统一处理风险闭环，支持分派、抑制和状态流转"
        summary={
          <div className="metric-grid metric-grid--3">
            <StatCard label="待处理风险" value={riskKpis.open} icon={<Siren size={18} />} tone={riskKpis.open > 0 ? 'critical' : 'good'} />
            <StatCard label="高危风险" value={riskKpis.high} icon={<AlertTriangle size={18} />} tone={riskKpis.high > 0 ? 'high' : 'good'} hint="当前视图" />
            <StatCard label="SLA 逾期" value={riskKpis.overdue} icon={<Clock size={18} />} tone={riskKpis.overdue > 0 ? 'critical' : 'good'} hint="当前视图" />
          </div>
        }
      />
      <ProTable<Risk>
        key={`${reloadKey}-${tableKey}`}
        rowKey="id"
        columns={columns}
        search={{ labelWidth: 72 }}
        options={false}
        className="surface-table"
        rowSelection={{ selectedRowKeys, onChange: setSelectedRowKeys }}
        toolBarRender={() => [
          <Typography.Text key="selected" type="secondary">
            已选 {selectedRowKeys.length} 项
          </Typography.Text>,
          can(Permission.RiskWrite) ? (
            <Button key="assign" icon={<UserPlus size={16} />} disabled={selectedRowKeys.length === 0} onClick={() => setAssignOpen(true)}>
              批量分派
            </Button>
          ) : null,
          can(Permission.RiskWrite) ? (
            <Button key="manual" icon={<Plus size={16} />} onClick={() => setManualOpen(true)}>
              人工录入
            </Button>
          ) : null,
          can(Permission.RiskSuppress) ? (
            <Button key="suppress" icon={<ShieldCheck size={16} />} onClick={() => void openSuppressions()}>
              抑制规则
            </Button>
          ) : null
        ]}
        request={async (params) => {
          const keyword = typeof params.keyword === 'string' && params.keyword.trim() ? params.keyword.trim() : routeQuery;
          const page = await listRisks({
            projectId,
            pageSize: params.pageSize ?? 20,
            pageNumber: params.current ?? 1,
            severity: typeof params.severity === 'string' ? params.severity : undefined,
            status: typeof params.status === 'string' ? params.status : undefined,
            owner: typeof params.owner === 'string' ? params.owner : undefined
          });
          const items = keyword ? page.items.filter((item) => matchRisk(item, keyword)) : page.items;
          setRiskItems(items);
          setTotalRisks(keyword ? items.length : page.total);
          return { data: items, total: keyword ? items.length : page.total, success: true };
        }}
        pagination={{ pageSize: 20 }}
        onRow={(record) => ({ onClick: () => void openDetail(record) })}
      />
      <Drawer title="风险详情" open={detailOpen} onClose={() => setDetailOpen(false)} width={820}>
        <StateView loading={detailLoading} error={detailError} empty={!detail}>
          {detail ? (
            <Space direction="vertical" size={18} className="full-width">
              <div className="detail-banner">
                <div className="detail-banner-main">
                  <Tag color={severityColor[detail.severity]} className="detail-banner-severity">{detail.severity}</Tag>
                  <div className="detail-banner-title">{detail.title}</div>
                </div>
                <div className="detail-banner-meta">
                  <div className="detail-banner-meta-item">
                    <span className="detail-banner-meta-label">状态</span>
                    <Tag color={detail.status === 'fixed' ? 'green' : detail.status === 'new' || detail.status === 'confirmed' ? 'blue' : 'orange'}>{detail.status}</Tag>
                  </div>
                  <div className="detail-banner-meta-item">
                    <span className="detail-banner-meta-label">负责人</span>
                    <span>{detail.owner || '-'}</span>
                  </div>
                  <div className="detail-banner-meta-item">
                    <span className="detail-banner-meta-label">评分</span>
                    <span className="detail-banner-score">{detail.score}</span>
                  </div>
                </div>
              </div>
              <Space wrap>
                {detail.available_actions.map((action, index) => (
                  <Button
                    key={action}
                    type={index === 0 ? 'primary' : 'default'}
                    onClick={() => void submitTransition(action)}
                  >
                    {action}
                  </Button>
                ))}
              </Space>
              <Descriptions title={<div className="card-title-row"><FileText size={16} /><span>证据</span></div>} bordered size="small" column={1}>
                {detail.evidence.map((item) => (
                  <Descriptions.Item key={item.label} label={item.label}>{item.value}</Descriptions.Item>
                ))}
              </Descriptions>
              <Descriptions title={<div className="card-title-row"><Scale size={16} /><span>评分明细</span></div>} bordered size="small" column={1}>
                {detail.score_factors.map((factor) => (
                  <Descriptions.Item key={factor.name} label={`${factor.name}=${factor.value}`}>{factor.reason}</Descriptions.Item>
                ))}
              </Descriptions>
              <div className="card-title-row drawer-section-title"><History size={16} /><span>处置时间线</span></div>
              <Timeline items={detail.timeline.map((item) => ({ children: `${item.at} · ${item.actor} · ${item.action}${item.note ? ` · ${item.note}` : ''}` }))} />
            </Space>
          ) : null}
        </StateView>
      </Drawer>
      <Modal title="人工录入风险" open={manualOpen} onCancel={() => setManualOpen(false)} onOk={() => void submitManualRisk()} okText="保存">
        <Form form={manualForm} layout="vertical" initialValues={{ severity: 'medium' }}>
          <Form.Item name="title" label="标题" rules={[{ required: true, max: 160 }]}><Input /></Form.Item>
          <Form.Item name="severity" label="等级" rules={[{ required: true }]}><Select options={['low', 'medium', 'high', 'critical'].map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="owner" label="负责人" rules={[{ required: true, max: 80 }]}><Input /></Form.Item>
          <Form.Item name="evidence" label="证据" rules={[{ required: true, max: 1000 }]}><Input.TextArea rows={4} /></Form.Item>
        </Form>
      </Modal>
      <Modal title="批量分派" open={assignOpen} onCancel={() => setAssignOpen(false)} onOk={() => void submitBatchAssign()} okText="保存">
        <Form form={assignForm} layout="vertical">
          <Form.Item name="owner" label="负责人" rules={[{ required: true, max: 80 }]}><Input /></Form.Item>
        </Form>
      </Modal>
      <Modal title="抑制规则" open={suppressionOpen} onCancel={() => setSuppressionOpen(false)} onOk={() => void submitSuppression()} okText="新增规则">
        <Form form={suppressionForm} layout="vertical">
          <Form.Item name="name" label="名称" rules={[{ required: true, max: 120 }]}><Input /></Form.Item>
          <Form.Item name="pattern" label="匹配模式" rules={[{ required: true, max: 300 }]}><Input /></Form.Item>
          <Form.Item name="expires_at" label="过期时间" rules={[{ required: true }]}><Input placeholder="2026-08-08T00:00:00Z" /></Form.Item>
        </Form>
        <Space direction="vertical" className="full-width">
          {rules.map((rule) => (
            <Tag key={rule.id} color={rule.enabled ? 'green' : 'default'}>{rule.name} · {rule.pattern}</Tag>
          ))}
        </Space>
      </Modal>
    </section>
  );
}
