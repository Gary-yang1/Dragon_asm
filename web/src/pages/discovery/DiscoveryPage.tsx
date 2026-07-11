import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Button, Form, Input, Modal, Progress, Select, Space, Tabs, Tag, Timeline, Typography, message } from 'antd';
import { Globe, Network, Play, Plus, Server, Square, ShieldCheck } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';

import {
  cancelTaskRun,
  createScope,
  listChangeEvents,
  listExposures,
  listScopes,
  listTaskRuns,
  listTaskTemplates,
  triggerTaskRun,
  type ChangeEvent,
  type Exposure,
  type Scope,
  type ScopeInput,
  type TaskRun,
  type TaskTemplate
} from '../../api/discovery';
import { errorMessage } from '../../api/errorMessage';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StatCard } from '../../components/StatCard';
import { StateView } from '../../components/StateView';
import { useProjectId } from '../../projects/ProjectContext';

const severityColor: Record<string, string> = {
  info: 'blue',
  low: 'cyan',
  medium: 'gold',
  high: 'volcano',
  critical: 'red'
};

const exposureIcon: Record<string, ReactNode> = {
  port: <Network size={18} />,
  service: <Server size={18} />,
  web: <Globe size={18} />,
  certificate: <ShieldCheck size={18} />
};

export function DiscoveryPage() {
  const { can } = usePermission();
  const projectId = useProjectId();
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [templates, setTemplates] = useState<TaskTemplate[]>([]);
  const [runs, setRuns] = useState<TaskRun[]>([]);
  const [exposures, setExposures] = useState<Exposure[]>([]);
  const [events, setEvents] = useState<ChangeEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [activeTab, setActiveTab] = useState('scope');
  const [scopeOpen, setScopeOpen] = useState(false);
  const [scopeForm] = Form.useForm<ScopeInput & { target_value: string; target_type: ScopeInput['targets'][number]['target_type'] }>();
  const [eventFilter, setEventFilter] = useState<{ entityType?: string; severity?: string }>({});
  const eventEntityType = eventFilter.entityType;
  const eventSeverity = eventFilter.severity;

  const reload = useCallback(async (showLoading = false) => {
    if (showLoading) setLoading(true);
    setLoadError('');
    try {
      const [scopePage, templatePage, runPage, exposurePage, eventPage] = await Promise.all([
        listScopes(projectId),
        listTaskTemplates(projectId),
        listTaskRuns(projectId),
        listExposures(projectId),
        listChangeEvents(projectId, { entityType: eventEntityType, severity: eventSeverity })
      ]);
      setScopes(scopePage.items);
      setTemplates(templatePage.items);
      setRuns(runPage.items);
      setExposures(exposurePage.items);
      setEvents(eventPage.items);
    } catch (error) {
      setLoadError(errorMessage(error));
    } finally {
      setLoading(false);
    }
  }, [eventEntityType, eventSeverity, projectId]);

  useEffect(() => {
    void reload(true);
  }, [reload]);

  const scopeColumns = useMemo<ProColumns<Scope>[]>(() => [
    { title: 'Scope', dataIndex: 'name' },
    { title: '状态', dataIndex: 'status', render: (_, row) => <Tag color={row.status === 'active' ? 'green' : 'default'}>{row.status}</Tag> },
    { title: '授权人', dataIndex: 'authorized_by' },
    { title: '生效时间', dataIndex: 'valid_from', valueType: 'dateTime' },
    { title: '失效时间', dataIndex: 'valid_until', valueType: 'dateTime' },
    {
      title: '目标',
      search: false,
      render: (_, row) => (
        <Space wrap>
          {row.targets.map((target) => (
            <Tag key={`${target.match_type}:${target.value}`} color={target.match_type === 'exclude' ? 'red' : 'blue'}>
              {target.match_type}:{target.value}
            </Tag>
          ))}
        </Space>
      )
    }
  ], []);

  const templateColumns = useMemo<ProColumns<TaskTemplate>[]>(() => [
    { title: '模板', dataIndex: 'name' },
    { title: '类型', dataIndex: 'task_type' },
    { title: 'Scope', dataIndex: 'scope_id' },
    { title: 'Schedule', dataIndex: 'schedule' },
    { title: '并发', dataIndex: 'concurrency' },
    { title: '速率/分钟', dataIndex: 'rate_limit_per_minute' },
    { title: '状态', dataIndex: 'enabled', render: (_, row) => <Tag color={row.enabled ? 'green' : 'default'}>{row.enabled ? 'enabled' : 'disabled'}</Tag> },
    {
      title: '操作',
      valueType: 'option',
      render: (_, row) =>
        can(Permission.DiscoveryRun) ? [
          <Button
            key="run"
            aria-label={`触发 ${row.name}`}
            icon={<Play size={14} />}
            size="small"
            type="link"
            onClick={async () => {
              await triggerTaskRun(projectId, row.id);
              message.success('任务已触发');
              await reload();
            }}
          >
            触发
          </Button>
        ] : []
    }
  ], [can, projectId, reload]);

  const runColumns = useMemo<ProColumns<TaskRun>[]>(() => [
    { title: 'Run ID', dataIndex: 'id' },
    { title: '类型', dataIndex: 'task_type' },
    { title: '状态', dataIndex: 'status', render: (_, row) => <Tag color={runColor(row.status)}>{row.status}</Tag> },
    { title: '进度', dataIndex: 'progress', render: (_, row) => <Progress percent={row.progress} size="small" /> },
    { title: '错误摘要', dataIndex: 'error_summary', ellipsis: true },
    {
      title: '操作',
      valueType: 'option',
      render: (_, row) =>
        can(Permission.DiscoveryRun) && ['pending', 'running'].includes(row.status) ? [
          <Button
            key="cancel"
            aria-label={`取消 run ${row.id}`}
            danger
            icon={<Square size={14} />}
            size="small"
            type="link"
            onClick={async () => {
              await cancelTaskRun(projectId, row.id);
              message.success('任务已取消');
              await reload();
            }}
          >
            取消
          </Button>
        ] : []
    }
  ], [can, projectId, reload]);

  const exposureColumns = useMemo<ProColumns<Exposure>[]>(() => [
    { title: '暴露面', dataIndex: 'title' },
    { title: '类型', dataIndex: 'exposure_type', valueType: 'select', valueEnum: { port: 'Port', service: 'Service', web: 'Web', certificate: 'Certificate' } },
    { title: '端点', dataIndex: 'endpoint', ellipsis: true },
    { title: '等级', dataIndex: 'severity', render: (_, row) => <Tag color={severityColor[row.severity]}>{row.severity}</Tag> },
    { title: '最近发现', dataIndex: 'last_seen', valueType: 'dateTime' }
  ], []);

  const exposureStats = useMemo(
    () => ['port', 'service', 'web', 'certificate'].map((type) => ({ type, count: exposures.filter((item) => item.exposure_type === type).length })),
    [exposures]
  );

  async function submitScope() {
    const values = await scopeForm.validateFields();
    await createScope(projectId, {
      name: values.name,
      authorized_by: values.authorized_by,
      valid_from: values.valid_from,
      valid_until: values.valid_until,
      targets: [{ target_type: values.target_type, match_type: 'include', value: values.target_value }]
    });
    setScopeOpen(false);
    scopeForm.resetFields();
    message.success('Scope 已创建');
    await reload();
  }

  return (
    <section className="page-surface">
      <StateView loading={loading} error={loadError} onRetry={() => void reload(true)}>
            <PageHeader
              title="发现中心"
              subtitle="资产范围、任务编排与变化监控"
              summary={
                <div className="page-summary-stats">
                  <div className="page-summary-stat">
                    <Typography.Text type="secondary">授权范围</Typography.Text>
                    <Typography.Text strong>{scopes.length}</Typography.Text>
                  </div>
                  <div className="page-summary-stat">
                    <Typography.Text type="secondary">任务模板</Typography.Text>
                    <Typography.Text strong>{templates.length}</Typography.Text>
                  </div>
                  <div className="page-summary-stat">
                    <Typography.Text type="secondary">待处理事件</Typography.Text>
                    <Typography.Text strong>{events.length}</Typography.Text>
                  </div>
                </div>
              }
            />
            <Tabs
              activeKey={activeTab}
              onChange={setActiveTab}
              items={[
                {
                  key: 'scope',
                  label: '授权范围',
                  children: (
                    <>
                      <div className="page-heading">
                        <h3>授权范围</h3>
                        {can(Permission.ScopeWrite) ? (
                          <Button icon={<Plus size={16} />} type="primary" onClick={() => setScopeOpen(true)}>
                            新建 Scope
                          </Button>
                        ) : null}
                      </div>
                      <ProTable<Scope> className="surface-table" rowKey="id" columns={scopeColumns} dataSource={scopes} search={false} options={false} pagination={false} />
                    </>
                  )
                },
                {
                  key: 'tasks',
                  label: '任务',
                  children: (
                    <Space direction="vertical" size={18} className="full-width">
                      <div className="page-summary-stats">
                        <div className="page-summary-stat">
                          <Typography.Text type="secondary">运行任务模板</Typography.Text>
                          <Typography.Text strong>{templates.length}</Typography.Text>
                        </div>
                        <div className="page-summary-stat">
                          <Typography.Text type="secondary">运行记录</Typography.Text>
                          <Typography.Text strong>{runs.length}</Typography.Text>
                        </div>
                        <div className="page-summary-stat">
                          <Typography.Text type="secondary">运行中</Typography.Text>
                          <Typography.Text strong>{runs.filter((run) => run.status === 'running').length}</Typography.Text>
                        </div>
                      </div>
                      <ProTable<TaskTemplate> className="surface-table" headerTitle="任务模板" rowKey="id" columns={templateColumns} dataSource={templates} search={false} options={false} pagination={false} />
                      <ProTable<TaskRun> className="surface-table" headerTitle="执行记录" rowKey="id" columns={runColumns} dataSource={runs} search={false} options={false} pagination={false} />
                </Space>
              )
                },
                {
                  key: 'exposures',
                  label: '暴露面',
                  children: (
                  <Space direction="vertical" size={18} className="full-width">
                    <div className="metric-grid">
                      {exposureStats.map((item) => (
                        <StatCard
                          key={item.type}
                          label={item.type}
                          value={item.count}
                          icon={exposureIcon[item.type]}
                          tone="neutral"
                        />
                      ))}
                    </div>
                    <ProTable<Exposure> className="surface-table" rowKey="id" columns={exposureColumns} dataSource={exposures} options={false} pagination={{ pageSize: 20 }} />
                  </Space>
                )
                },
                {
                  key: 'changes',
                  label: '变化监控',
                  children: (
                <Space direction="vertical" size={16} className="full-width">
                  <Space wrap>
                    <select
                      aria-label="实体类型"
                      className="plain-select"
                      value={eventEntityType ?? ''}
                      onChange={(event) => setEventFilter((current) => ({ ...current, entityType: event.target.value || undefined }))}
                    >
                      <option value="">实体类型</option>
                      <option value="asset">asset</option>
                      <option value="exposure">exposure</option>
                      <option value="certificate">certificate</option>
                      <option value="risk">risk</option>
                    </select>
                    <select
                      aria-label="事件等级"
                      className="plain-select"
                      value={eventSeverity ?? ''}
                      onChange={(event) => setEventFilter((current) => ({ ...current, severity: event.target.value || undefined }))}
                    >
                      <option value="">事件等级</option>
                      <option value="info">info</option>
                      <option value="low">low</option>
                      <option value="medium">medium</option>
                      <option value="high">high</option>
                      <option value="critical">critical</option>
                    </select>
                  </Space>
                  <Timeline
                    style={{ marginTop: 8 }}
                    items={events.map((event) => ({
                      color: event.severity === 'critical' || event.severity === 'high' ? 'red' : 'blue',
                      children: (
                        <Space direction="vertical" size={2}>
                          <Space>
                            <Tag color={severityColor[event.severity]}>{event.severity}</Tag>
                            <strong>{event.title}</strong>
                          </Space>
                          <span>{event.entity_type} · {event.change_type} · {event.detected_at}</span>
                        </Space>
                      )
                    }))}
                  />
                </Space>
              )
            }
          ]}
        />
      </StateView>
      <Modal className="surface-card" title="新建 Scope" open={scopeOpen} onCancel={() => setScopeOpen(false)} onOk={() => void submitScope()} okText="保存">
        <Form form={scopeForm} layout="vertical" initialValues={{ target_type: 'domain' }}>
          <Form.Item name="name" label="名称" rules={[{ required: true, max: 128 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="authorized_by" label="授权人" rules={[{ required: true, max: 128 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="valid_from" label="生效时间" rules={[{ required: true }]}>
            <Input placeholder="2026-07-08T00:00:00Z" />
          </Form.Item>
          <Form.Item name="valid_until" label="失效时间" rules={[{ required: true }]}>
            <Input placeholder="2026-08-08T00:00:00Z" />
          </Form.Item>
          <Space.Compact className="full-width">
            <Form.Item name="target_type" rules={[{ required: true }]} className="scope-target-type">
              <Select
                options={[
                  { value: 'domain', label: 'Domain' },
                  { value: 'ip', label: 'IP' },
                  { value: 'cidr', label: 'CIDR' },
                  { value: 'url', label: 'URL' }
                ]}
              />
            </Form.Item>
            <Form.Item name="target_value" rules={[{ required: true, max: 512 }]} className="scope-target-value">
              <Input placeholder="example.com" />
            </Form.Item>
          </Space.Compact>
        </Form>
      </Modal>
    </section>
  );
}

function runColor(status: TaskRun['status']) {
  if (status === 'success') return 'green';
  if (status === 'failed') return 'red';
  if (status === 'cancelled') return 'default';
  if (status === 'partial_success') return 'gold';
  return 'blue';
}
