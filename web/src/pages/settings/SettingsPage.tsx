import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Button, Card, Form, Input, InputNumber, Select, Switch, Tabs, Typography, message } from 'antd';
import { useCallback, useEffect, useMemo, useState } from 'react';

import { listNotificationRules, listSlaPolicies, saveNotificationRule, saveSlaPolicy, type NotificationRule, type NotificationRuleInput, type SlaPolicy, type SlaPolicyInput } from '../../api/operations';
import { errorMessage } from '../../api/errorMessage';
import { PageHeader } from '../../components/PageHeader';
import { StateView } from '../../components/StateView';
import { useProjectId } from '../../projects/ProjectContext';

export function SettingsPage() {
  const projectId = useProjectId();
  const [policies, setPolicies] = useState<SlaPolicy[]>([]);
  const [rules, setRules] = useState<NotificationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
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

  useEffect(() => {
    void reload();
  }, [reload]);

  const policyColumns = useMemo<ProColumns<SlaPolicy>[]>(() => [
    { title: '等级', dataIndex: 'severity' },
    { title: '业务单元', dataIndex: 'business_unit' },
    { title: '响应时限（小时）', dataIndex: 'response_hours' },
    { title: '解决时限（小时）', dataIndex: 'resolution_hours' }
  ], []);

  const ruleColumns = useMemo<ProColumns<NotificationRule>[]>(() => [
    { title: '规则', dataIndex: 'name' },
    { title: '触发器', dataIndex: 'trigger' },
    { title: '渠道', dataIndex: 'channel' },
    { title: '收件人', dataIndex: 'recipients', render: (_, row) => row.recipients.join(', ') },
    { title: '节流窗口（秒）', dataIndex: 'throttle_window' },
    { title: '启用', dataIndex: 'enabled', render: (_, row) => <Switch checked={row.enabled} disabled /> }
  ], []);

  async function submitSla() {
    await saveSlaPolicy(projectId, await slaForm.validateFields());
    slaForm.resetFields();
    message.success('SLA 策略已保存');
    await reload();
  }

  async function submitRule() {
    await saveNotificationRule(projectId, await ruleForm.validateFields());
    ruleForm.resetFields();
    message.success('通知规则已保存');
    await reload();
  }

  return (
    <section className="page-surface">
      <StateView loading={loading} error={loadError} onRetry={() => void reload()}>
        <Tabs
          items={[
          {
            key: 'sla',
            label: 'SLA 策略',
            children: (
              <>
                <PageHeader
                  title="系统配置"
                  subtitle="SLA 与通知策略配置"
                  summary={
                    <div className="page-summary-stats">
                      <div className="page-summary-stat">
                        <Typography.Text type="secondary">SLA 规则</Typography.Text>
                        <Typography.Text strong>{policies.length}</Typography.Text>
                      </div>
                      <div className="page-summary-stat">
                        <Typography.Text type="secondary">通知规则</Typography.Text>
                        <Typography.Text strong>{rules.length}</Typography.Text>
                      </div>
                    </div>
                  }
                />
                <Card className="surface-card" title="SLA 策略">
                <Form form={slaForm} layout="inline" initialValues={{ severity: 'high', business_unit: 'default', response_hours: 24, resolution_hours: 72 }}>
                  <Form.Item name="severity" label="等级" rules={[{ required: true }]}><Select style={{ width: 140 }} options={['low', 'medium', 'high', 'critical'].map((value) => ({ value, label: value }))} /></Form.Item>
                  <Form.Item name="business_unit" label="业务单元" rules={[{ required: true, max: 80 }]}><Input /></Form.Item>
                  <Form.Item name="response_hours" label="响应小时" rules={[{ required: true }]}><InputNumber min={1} max={8760} /></Form.Item>
                  <Form.Item name="resolution_hours" label="解决小时" rules={[{ required: true }]}><InputNumber min={1} max={8760} /></Form.Item>
                  <Button type="primary" onClick={() => void submitSla()}>保存 SLA</Button>
                </Form>
                  <ProTable<SlaPolicy> className="surface-table" rowKey="id" search={false} options={false} columns={policyColumns} dataSource={policies} pagination={false} />
                </Card>
              </>
            )
          },
          {
            key: 'notification',
            label: '通知规则',
            children: (
              <Card className="surface-card" title="通知规则">
                <Form form={ruleForm} layout="inline" initialValues={{ trigger: 'risk.created', channel: 'email', throttle_window: 3600, enabled: true }}>
                  <Form.Item name="name" label="名称" rules={[{ required: true, max: 120 }]}><Input /></Form.Item>
                  <Form.Item name="trigger" label="触发器" rules={[{ required: true }]}><Input /></Form.Item>
                  <Form.Item name="channel" label="渠道" rules={[{ required: true }]}><Select style={{ width: 120 }} options={[{ value: 'email', label: 'email' }, { value: 'webhook', label: 'webhook' }]} /></Form.Item>
                  <Form.Item name="recipients" label="收件人" rules={[{ required: true }]}><Select mode="tags" style={{ minWidth: 220 }} tokenSeparators={[',']} /></Form.Item>
                  <Form.Item name="throttle_window" label="节流秒数" rules={[{ required: true }]}><InputNumber min={0} max={4294967295} /></Form.Item>
                  <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
                  <Button type="primary" onClick={() => void submitRule()}>保存通知</Button>
                </Form>
                <ProTable<NotificationRule> className="surface-table" rowKey="id" search={false} options={false} columns={ruleColumns} dataSource={rules} pagination={false} />
              </Card>
            )
          },
          {
            key: 'empty',
            label: '项目设置',
            children: (
              <Card className="surface-card" title="项目设置">
                <div className="settings-placeholder">暂无更多项目设置项</div>
              </Card>
            )
          }
          ]}
        />
      </StateView>
    </section>
  );
}
