import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Alert, Button, Drawer, Form, Input, InputNumber, Select, Switch, Tabs, message } from 'antd';
import { useCallback, useEffect, useMemo, useState } from 'react';

import { listNotificationRules, listSlaPolicies, saveNotificationRule, saveSlaPolicy, type NotificationRule, type NotificationRuleInput, type SlaPolicy, type SlaPolicyInput } from '../../api/operations';
import { errorMessage } from '../../api/errorMessage';
import { PageHeader } from '../../components/PageHeader';
import { StateView } from '../../components/StateView';
import { useProjectId } from '../../projects/ProjectContext';
import { describe, severityMeta } from '../../utils/taxonomy';

export function SettingsPage() {
  const projectId = useProjectId();
  const [policies, setPolicies] = useState<SlaPolicy[]>([]);
  const [rules, setRules] = useState<NotificationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [editing, setEditing] = useState<'sla' | 'notification' | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [slaForm] = Form.useForm<SlaPolicyInput>();
  const [ruleForm] = Form.useForm<NotificationRuleInput>();

  const reload = useCallback(async () => {
    setLoading(true);
    setLoadError('');
    try {
      const [policyItems, ruleItems] = await Promise.all([listSlaPolicies(projectId), listNotificationRules(projectId)]);
      setPolicies(policyItems);
      setRules(ruleItems);
    } catch (error) {
      setLoadError(errorMessage(error));
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => { setEditing(null); void reload(); }, [reload]);

  const policyColumns = useMemo<ProColumns<SlaPolicy>[]>(() => [
    { title: '风险等级', dataIndex: 'severity', render: (_, row) => describe(severityMeta, row.severity).label },
    { title: '业务单元', dataIndex: 'business_unit' },
    { title: '响应时限（小时）', dataIndex: 'response_hours' },
    { title: '解决时限（小时）', dataIndex: 'resolution_hours' }
  ], []);

  const ruleColumns = useMemo<ProColumns<NotificationRule>[]>(() => [
    { title: '规则', dataIndex: 'name' },
    { title: '触发条件', dataIndex: 'trigger' },
    { title: '渠道', dataIndex: 'channel', render: (_, row) => row.channel === 'email' ? '邮件' : 'Webhook' },
    { title: '接收地址', dataIndex: 'recipients', render: (_, row) => row.recipients.join(', ') },
    { title: '通知间隔（秒）', dataIndex: 'throttle_window' },
    { title: '状态', dataIndex: 'enabled', render: (_, row) => row.enabled ? '已启用' : '已停用' }
  ], []);

  async function submit() {
    if (saving || !editing) return;
    setSaving(true);
    setSaveError('');
    try {
      if (editing === 'sla') await saveSlaPolicy(projectId, await slaForm.validateFields());
      else await saveNotificationRule(projectId, await ruleForm.validateFields());
      message.success(editing === 'sla' ? 'SLA 策略已保存' : '通知规则已保存');
      setEditing(null);
      await reload();
    } catch (error) {
      if (!(typeof error === 'object' && error !== null && 'errorFields' in error)) setSaveError(errorMessage(error));
    } finally {
      setSaving(false);
    }
  }

  function openEditor(kind: 'sla' | 'notification') {
    setSaveError('');
    slaForm.resetFields();
    ruleForm.resetFields();
    setEditing(kind);
  }

  return <section className="page-surface">
    <PageHeader title="项目设置" subtitle="管理风险响应时限和通知方式" />
    <StateView loading={loading} error={loadError} onRetry={() => void reload()}>
      <Tabs items={[
        { key: 'sla', label: `SLA 策略`, children: <>
          <div className="section-toolbar"><span>按风险等级和业务单元设置响应、解决时限。</span><Button type="primary" onClick={() => openEditor('sla')}>添加 SLA 策略</Button></div>
          <ProTable<SlaPolicy> className="surface-table" rowKey="id" search={false} options={false} columns={policyColumns} dataSource={policies} pagination={false} />
        </> },
        { key: 'notification', label: '通知规则', children: <>
          <div className="section-toolbar"><span>配置发生风险事件时的通知方式和接收地址。</span><Button type="primary" onClick={() => openEditor('notification')}>添加通知规则</Button></div>
          <ProTable<NotificationRule> className="surface-table" rowKey="id" search={false} options={false} columns={ruleColumns} dataSource={rules} pagination={false} />
        </> }
      ]} />
    </StateView>
    <Drawer title={editing === 'sla' ? '添加 SLA 策略' : '添加通知规则'} width={560} open={editing !== null} onClose={() => { if (!saving) setEditing(null); }}>
      {saveError && <Alert className="list-error-alert" type="error" showIcon message={saveError} />}
      {editing === 'sla' ? <Form form={slaForm} disabled={saving} layout="vertical" initialValues={{ severity: 'high', business_unit: 'default', response_hours: 24, resolution_hours: 72 }}>
        <Form.Item name="severity" label="风险等级" rules={[{ required: true }]}><Select options={['low', 'medium', 'high', 'critical'].map((value) => ({ value, label: describe(severityMeta, value).label }))} /></Form.Item>
        <Form.Item name="business_unit" label="业务单元" rules={[{ required: true, max: 80 }]}><Input /></Form.Item>
        <div className="record-form">
          <Form.Item name="response_hours" label="响应时限（小时）" rules={[{ required: true }]}><InputNumber min={1} max={8760} className="full-width" /></Form.Item>
          <Form.Item name="resolution_hours" label="解决时限（小时）" rules={[{ required: true }]}><InputNumber min={1} max={8760} className="full-width" /></Form.Item>
        </div>
      </Form> : <Form form={ruleForm} disabled={saving} layout="vertical" initialValues={{ trigger: 'risk.created', channel: 'webhook', throttle_window: 3600, enabled: true }}>
        <Form.Item name="name" label="名称" rules={[{ required: true, max: 120 }]}><Input /></Form.Item>
        <Form.Item name="trigger" label="触发条件" extra="例如 risk.created（发现新风险）。" rules={[{ required: true }]}><Input /></Form.Item>
        <Form.Item name="channel" label="通知渠道" rules={[{ required: true }]}><Select options={[{ value: 'webhook', label: 'Webhook' }, { value: 'email', label: '邮件（暂不可用）', disabled: true }]} /></Form.Item>
        <Form.Item name="recipients" label="接收地址" extra="输入 Webhook 地址后按回车，可添加多个。" rules={[{ required: true }]}><Select mode="tags" tokenSeparators={[',']} /></Form.Item>
        <Form.Item name="throttle_window" label="最短通知间隔（秒）" extra="同类通知在该时间内限制重复发送，避免打扰。" rules={[{ required: true }]}><InputNumber min={0} max={4294967295} className="full-width" /></Form.Item>
        <Form.Item name="enabled" label="启用规则" valuePropName="checked"><Switch /></Form.Item>
      </Form>}
      <Button type="primary" loading={saving} onClick={() => void submit()}>{editing === 'sla' ? '保存 SLA' : '保存通知'}</Button>
    </Drawer>
  </section>;
}
