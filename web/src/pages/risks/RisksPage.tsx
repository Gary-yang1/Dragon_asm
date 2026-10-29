import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Alert, Button, Descriptions, Drawer, Form, Input, Modal, Select, Space, Tag, Timeline, message, Typography } from 'antd';
import { AlertTriangle, Clock, FileText, History, Scale, ShieldCheck, Siren } from 'lucide-react';
import type { Key } from 'react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import {
  createSuppressionRule,
  getRisk,
  listRisks,
  listSuppressionRules,
  setSuppressionRuleEnabled,
  riskDecisionActions,
  riskActionsRequiringReason,
  transitionRisk,
  type Risk,
  type RiskDetail,
  type RiskTransitionInput,
  type SuppressionRule
} from '../../api/risks';
import { errorMessage } from '../../api/errorMessage';
import { EnumChip, ScoreMeter, StatusChip } from '../../components/StatusChip';
import { describe, riskActionMeta, riskStatusMeta, riskTypeMeta, severityMeta, toValueEnum } from '../../utils/taxonomy';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StatCard } from '../../components/StatCard';
import { StateView } from '../../components/StateView';
import { useProjectId } from '../../projects/ProjectContext';

export function RisksPage() {
  const { can } = usePermission();
  const projectId = useProjectId();
  const [searchParams, setSearchParams] = useSearchParams();
  const routeQuery = (searchParams.get('q') ?? '').trim();
  // Set by links from an asset's detail; narrows the list to that asset's risks.
  const assetFilter = Number(searchParams.get('asset_id')) || 0;
  const linkedRiskId = Number(searchParams.get('risk_id')) || 0;
  const [totalRisks, setTotalRisks] = useState(0);
  const [riskItems, setRiskItems] = useState<Risk[]>([]);
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([]);
  const [detail, setDetail] = useState<RiskDetail | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [suppressionOpen, setSuppressionOpen] = useState(false);
  const [rules, setRules] = useState<SuppressionRule[]>([]);
  const [suppressionForm] = Form.useForm<{ name: string; risk_type?: string; rule_id?: string; reason: string; expires_at?: string }>();
  const [reloadKey, setReloadKey] = useState(0);
  const [listError, setListError] = useState('');
  const [pendingAction, setPendingAction] = useState<string>('');
  const [transitionForm] = Form.useForm<{
    reason: string; owner: string; sla_due_at: string; approved_by: string; expires_at: string;
  }>();

  // requestedRiskRef discards a slow response for a previously clicked row so it
  // cannot overwrite the drawer opened for a newer one.
  const requestedRiskRef = useRef<number>(0);

  async function openDetail(row: Risk) {
    requestedRiskRef.current = row.id;
    setDetailLoading(true);
    setDetailError('');
    setDetailOpen(true);
    try {
      const risk = await getRisk(projectId, row.id);
      if (requestedRiskRef.current !== row.id) return;
      setDetail(risk);
    } catch (error) {
      if (requestedRiskRef.current !== row.id) return;
      setDetail(null);
      setDetailError(errorMessage(error));
    } finally {
      if (requestedRiskRef.current === row.id) setDetailLoading(false);
    }
  }

  // A link from an asset detail opens that risk directly.
  useEffect(() => {
    if (linkedRiskId > 0) void openDetail({ id: linkedRiskId } as Risk);
    // openDetail is stable in behaviour; re-running only on a new linked id is intended.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linkedRiskId, projectId]);

  function closeDetail() {
    setDetailOpen(false);
    if (searchParams.has('risk_id')) {
      const next = new globalThis.URLSearchParams(searchParams);
      next.delete('risk_id');
      setSearchParams(next, { replace: true });
    }
  }

  function clearAssetFilter() {
    const next = new globalThis.URLSearchParams(searchParams);
    next.delete('asset_id');
    setSearchParams(next);
  }

  // Every action opens the form: the reason lands in the immutable status history,
  // so it must come from the operator rather than a hardcoded literal, and the
  // decision actions need an approver and a review date the server enforces.
  function beginTransition(action: string) {
    // No resetFields() here: the form lives inside the modal and is not mounted
    // yet, so the instance is unconnected. destroyOnHidden clears it instead.
    setPendingAction(action);
  }

  async function submitTransition() {
    if (!detail || !pendingAction) return;
    const values = await transitionForm.validateFields();
    const input: RiskTransitionInput = { action: pendingAction, reason: values.reason };
    if (pendingAction === 'assign') {
      input.owner = values.owner;
      input.sla_due_at = values.sla_due_at ? new Date(values.sla_due_at).toISOString() : undefined;
    }
    if (riskDecisionActions.includes(pendingAction)) {
      input.approved_by = values.approved_by;
      input.expires_at = values.expires_at ? new Date(values.expires_at).toISOString() : undefined;
    }
    try {
      const updated = await transitionRisk(projectId, detail.id, input);
      setDetail(updated);
      setPendingAction('');
      setReloadKey((value) => value + 1);
      message.success('状态已更新');
    } catch (error) {
      message.error(errorMessage(error));
    }
  }

  async function openSuppressions() {
    try {
      const page = await listSuppressionRules(projectId);
      setRules(page.items);
      setSuppressionOpen(true);
    } catch (error) {
      message.error(errorMessage(error));
    }
  }

  async function submitSuppression() {
    const values = await suppressionForm.validateFields();
    try {
      const created = await createSuppressionRule(projectId, {
        ...values,
        expires_at: values.expires_at ? new Date(values.expires_at).toISOString() : undefined
      });
      setRules((current) => [created, ...current]);
      suppressionForm.resetFields();
      message.success('抑制规则已创建');
    } catch (error) {
      message.error(errorMessage(error));
    }
  }

  async function toggleSuppression(rule: SuppressionRule) {
    try {
      await setSuppressionRuleEnabled(projectId, rule.id, !rule.enabled);
      setRules((current) => current.map((r) => (r.id === rule.id ? { ...r, enabled: !r.enabled } : r)));
    } catch (error) {
      message.error(errorMessage(error));
    }
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
      valueEnum: toValueEnum(severityMeta),
      render: (_, row) => <EnumChip map={severityMeta} value={row.severity} dot />
    },
    {
      title: '状态',
      dataIndex: 'status',
      valueType: 'select',
      valueEnum: toValueEnum(riskStatusMeta),
      render: (_, row) => <EnumChip map={riskStatusMeta} value={row.status} />
    },
    { title: '负责人', dataIndex: 'owner' },
    { title: '业务单元', dataIndex: 'business_unit', search: false, ellipsis: true },
    {
      title: '评分',
      dataIndex: 'score',
      search: false,
      width: 150,
      render: (_, row) => <ScoreMeter score={row.score} />
    },
    { title: 'SLA', dataIndex: 'sla_due_at', valueType: 'dateTime', search: false }
  ], []);

  const tableKey = `${routeQuery || 'risks'}-${assetFilter}`;


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
      {listError ? (
        <Alert
          type="error"
          showIcon
          message="风险列表加载失败"
          description={listError}
          action={<Button size="small" onClick={() => setReloadKey((value) => value + 1)}>重试</Button>}
          className="list-error-alert"
        />
      ) : null}
      {assetFilter ? <div className="asset-applied-filters" aria-label="已应用的风险筛选"><Tag closable onClose={clearAssetFilter}>仅看资产 #{assetFilter} 的风险</Tag></div> : null}
      <ProTable<Risk>
        key={`${reloadKey}-${tableKey}`}
        rowKey="id"
        columns={columns}
        search={{ labelWidth: 72 }}
        form={{ initialValues: { title: routeQuery, severity: searchParams.get('severity') || undefined, status: searchParams.get('status') || undefined, owner: searchParams.get('owner') || undefined } }}
        onSubmit={(values) => {
          const next = new globalThis.URLSearchParams(searchParams);
          const keyword = String(values.title ?? '').trim();
          if (keyword) next.set('q', keyword); else next.delete('q');
          for (const key of ['severity', 'status', 'owner']) {
            if (values[key]) next.set(key, String(values[key])); else next.delete(key);
          }
          setSearchParams(next);
        }}
        onReset={() => {
          const next = new globalThis.URLSearchParams(searchParams);
          for (const key of ['q', 'asset_id', ...['severity', 'status', 'owner']]) next.delete(key);
          setSearchParams(next);
        }}
        options={false}
        className="surface-table"
        rowSelection={{ selectedRowKeys, onChange: setSelectedRowKeys }}
        toolBarRender={() => [
          <Typography.Text key="selected" type="secondary">
            已选 {selectedRowKeys.length} 项
          </Typography.Text>,
          can(Permission.RiskSuppress) ? (
            <Button key="suppress" icon={<ShieldCheck size={16} />} onClick={() => void openSuppressions()}>
              抑制规则
            </Button>
          ) : null
        ]}
        request={async (params) => {
          const keyword = typeof params.title === 'string' ? params.title.trim() : routeQuery;
          try {
            // The server now applies these filters, so the result is the whole
            // matching set rather than whatever happened to be on the current page.
            const page = await listRisks({
              projectId,
              pageSize: params.pageSize ?? 20,
              pageNumber: params.current ?? 1,
              severity: typeof params.severity === 'string' ? params.severity : undefined,
              status: typeof params.status === 'string' ? params.status : undefined,
              owner: typeof params.owner === 'string' ? params.owner : undefined,
              keyword: keyword || undefined,
              assetId: assetFilter || undefined
            });
            setRiskItems(page.items);
            setTotalRisks(page.total);
            setListError('');
            return { data: page.items, total: page.total, success: true };
          } catch (error) {
            // A failed fetch previously rendered as an empty table, which reads as
            // "no risks" on a security console.
            setListError(errorMessage(error));
            setRiskItems([]);
            return { data: [], total: 0, success: false };
          }
        }}
        pagination={{ pageSize: 20 }}
        onRow={(record) => ({ onClick: () => void openDetail(record) })}
      />
      <Drawer title="风险详情" open={detailOpen} onClose={closeDetail} width={820}>
        <StateView loading={detailLoading} error={detailError} empty={!detail}>
          {detail ? (
            <Space direction="vertical" size={18} className="full-width">
              <div className="detail-banner">
                <div className="detail-banner-main">
                  <span className="detail-banner-severity"><EnumChip map={severityMeta} value={detail.severity} dot /></span>
                  <div className="detail-banner-title">{detail.title}</div>
                </div>
                <div className="detail-banner-meta">
                  <div className="detail-banner-meta-item">
                    <span className="detail-banner-meta-label">状态</span>
                    <EnumChip map={riskStatusMeta} value={detail.status} />
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
                {(detail.available_actions ?? []).map((action, index) => (
                  <Button
                    key={action}
                    type={index === 0 ? 'primary' : 'default'}
                    onClick={() => beginTransition(action)}
                  >
                    {describe(riskActionMeta, action).label}
                  </Button>
                ))}
              </Space>
              <Descriptions title={<div className="card-title-row"><FileText size={16} /><span>证据</span></div>} bordered size="small" column={1}>
                <Descriptions.Item label="证据摘要">{detail.evidence_summary || '-'}</Descriptions.Item>
                <Descriptions.Item label="证据引用">{detail.evidence_ref || '-'}</Descriptions.Item>
                <Descriptions.Item label="来源">{detail.source || '-'}</Descriptions.Item>
                <Descriptions.Item label="规则">{detail.rule_id || '-'}</Descriptions.Item>
              </Descriptions>
              <Descriptions
                title={<div className="card-title-row"><Scale size={16} /><span>评分明细</span></div>}
                bordered
                size="small"
                column={1}
                extra={detail.score_model_version ? `模型 ${detail.score_model_version}` : undefined}
              >
                {Object.entries(detail.score_factors ?? {}).map(([name, value]) => (
                  <Descriptions.Item key={name} label={name}>{value}</Descriptions.Item>
                ))}
              </Descriptions>
              <div className="card-title-row drawer-section-title"><History size={16} /><span>处置时间线</span></div>
              <Timeline
                items={[
                  detail.first_seen ? { children: `${detail.first_seen} · 首次发现` } : null,
                  detail.confirmed_at ? { children: `${detail.confirmed_at} · 已确认` } : null,
                  detail.fixed_at ? { children: `${detail.fixed_at} · 已修复` } : null,
                  detail.last_seen ? { children: `${detail.last_seen} · 最近发现` } : null
                ].filter((item): item is { children: string } => item !== null)}
              />
            </Space>
          ) : null}
        </StateView>
      </Drawer>
      <Modal
        title={`风险状态流转 · ${describe(riskActionMeta, pendingAction).label}`}
        open={pendingAction !== ''}
        onCancel={() => setPendingAction('')}
        onOk={() => void submitTransition()}
        okText="提交"
        okButtonProps={{ danger: riskDecisionActions.includes(pendingAction) }}
        destroyOnHidden
      >
        {riskDecisionActions.includes(pendingAction) ? (
          <Typography.Paragraph type="danger">
            该操作会在不修复的情况下关闭风险，需填写审批人并接受复核期限。审批人必须与当前操作者不同。
          </Typography.Paragraph>
        ) : null}
        <Form form={transitionForm} layout="vertical">
          <Form.Item
            name="reason"
            label="操作原因"
            rules={[{ required: riskActionsRequiringReason.includes(pendingAction), max: 1024 }]}
            extra="将写入不可变的状态变更历史"
          >
            <Input.TextArea rows={2} />
          </Form.Item>
          {pendingAction === 'assign' ? (
            <>
              <Form.Item name="owner" label="负责人" rules={[{ required: true, max: 64 }]}>
                <Input />
              </Form.Item>
              <Form.Item name="sla_due_at" label="SLA 到期时间" extra="留空则按 SLA 策略推导">
                <Input type="datetime-local" />
              </Form.Item>
            </>
          ) : null}
          {riskDecisionActions.includes(pendingAction) ? (
            <>
              <Form.Item name="approved_by" label="审批人" rules={[{ required: true, max: 64 }]}>
                <Input />
              </Form.Item>
              <Form.Item name="expires_at" label="有效期至" rules={[{ required: true }]}>
                <Input type="datetime-local" />
              </Form.Item>
            </>
          ) : null}
        </Form>
      </Modal>
      <Modal title="抑制规则" open={suppressionOpen} onCancel={() => setSuppressionOpen(false)} onOk={() => void submitSuppression()} okText="新增规则">
        <Form form={suppressionForm} layout="vertical">
          <Form.Item name="name" label="名称" rules={[{ required: true, max: 120 }]}><Input /></Form.Item>
          {/* Matching is by risk_type / rule_id, not a free-form pattern. */}
          <Form.Item name="risk_type" label="风险类型" extra="留空表示不限类型">
            <Select allowClear options={Object.entries(riskTypeMeta).map(([value, meta]) => ({ value, label: meta.label }))} />
          </Form.Item>
          <Form.Item name="rule_id" label="规则编号" extra="留空表示不限规则"><Input placeholder="RULE-0001" /></Form.Item>
          <Form.Item name="reason" label="抑制原因" rules={[{ required: true, max: 1024 }]} extra="将写入审计">
            <Input.TextArea rows={2} />
          </Form.Item>
          <Form.Item name="expires_at" label="过期时间" extra="留空表示长期有效">
            <Input type="datetime-local" />
          </Form.Item>
        </Form>
        <Space direction="vertical" size={8} className="full-width">
          {rules.length === 0 ? <Typography.Text type="secondary">暂无抑制规则</Typography.Text> : null}
          {rules.map((rule) => (
            <div key={rule.id} className="suppression-row">
              <Space size={8} wrap>
                <StatusChip label={rule.enabled ? '生效中' : '已停用'} tone={rule.enabled ? 'success' : 'neutral'} />
                <Typography.Text strong>{rule.name}</Typography.Text>
                {rule.risk_type ? <EnumChip map={riskTypeMeta} value={rule.risk_type} variant="outline" /> : null}
                {rule.rule_id ? <Typography.Text type="secondary">{rule.rule_id}</Typography.Text> : null}
              </Space>
              <Button size="small" onClick={() => void toggleSuppression(rule)}>
                {rule.enabled ? '停用' : '启用'}
              </Button>
            </div>
          ))}
        </Space>
      </Modal>
    </section>
  );
}
