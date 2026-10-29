import { Alert, App as AntApp, Badge, Button, Checkbox, Descriptions, Drawer, Form, Input, InputNumber, Result, Select, Skeleton, Space, Table, Tabs } from 'antd';
import { RefreshCw, Settings } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';

import { checkDiscoveryEngine, getDiscoveryEngines, getEngineConfiguration, saveEngineConfiguration, type EngineConfiguration, type EngineHealth, type EngineManagementOverview, type EngineRoute, type EngineSummary } from '../../api/engineManagement';
import { errorMessage } from '../../api/errorMessage';
import { ApiError } from '../../api/http';
import { PageHeader } from '../../components/PageHeader';

const healthMeta: Record<EngineHealth, { label: string; status: 'success' | 'warning' | 'error' | 'default' }> = {
  healthy: { label: '连接正常', status: 'success' }, degraded: { label: '需要处理', status: 'warning' },
  unreachable: { label: '连接失败', status: 'error' }, unconfigured: { label: '未配置', status: 'default' }, unknown: { label: '尚未检测', status: 'default' }
};
const capabilityLabels: Record<string, string> = { passive_intel: '被动情报', dns: 'DNS 解析', network_enrichment: '网络归属补充', org_intel: '主体情报', portscan: '端口探测', port_probe: '端口探测', webscan: 'Web 探测', web_probe: 'Web 探测', fingerprint: '指纹识别' };
type Section = 'passive' | 'active' | 'providers' | 'policy';

export function EngineManagementPage() { return <AntApp><EngineManagementContent /></AntApp>; }

function EngineManagementContent() {
  const { message } = AntApp.useApp();
  const [overview, setOverview] = useState<EngineManagementOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [failure, setFailure] = useState<{ message: string; forbidden: boolean } | null>(null);
  const [checking, setChecking] = useState<Set<EngineRoute>>(new Set());
  const [editor, setEditor] = useState<Section | null>(null);
  const [rowErrors, setRowErrors] = useState<Partial<Record<EngineRoute, string>>>({});
  const sequence = useRef(0);
  const checks = useRef<Set<EngineRoute>>(new Set());
  const generations = useRef<Record<EngineRoute, number>>({ passive: 0, active: 0 });
  const alive = useRef(true);
  const visibleVersion = useRef(0);
  visibleVersion.current = overview?.configuration_version ?? 0;

  const load = useCallback(async () => {
    const request = ++sequence.current;
    const before = { ...generations.current };
    setLoading(true);
    setFailure(null);
    try {
      const result = await getDiscoveryEngines();
      if (request !== sequence.current) return;
      setOverview((current) => {
        if ((current?.configuration_version ?? 0) > (result.configuration_version ?? 0)) return current;
        return { ...result, items: (result.items ?? []).map((item) =>
          current && before[item.route] !== generations.current[item.route] && current.configuration_version === result.configuration_version
            ? current.items.find((old) => old.route === item.route) ?? item : item) };
      });
    } catch (reason) {
      if (request !== sequence.current) return;
      const forbidden = reason instanceof ApiError && reason.status === 403;
      if (forbidden) setOverview(null);
      setFailure({ message: errorMessage(reason, '引擎配置加载失败'), forbidden });
    } finally { if (request === sequence.current) setLoading(false); }
  }, []);

  useEffect(() => {
    alive.current = true;
    void load();
    return () => { alive.current = false; sequence.current += 1; };
  }, [load]);

  useEffect(() => { setRowErrors({}); }, [overview?.configuration_version]);
  useEffect(() => {
    if (overview?.worker?.config_matches !== false) return;
    const timer = globalThis.setInterval(() => void load(), 15000);
    return () => globalThis.clearInterval(timer);
  }, [overview?.worker?.config_matches, load]);

  async function checkConnection(engine: EngineSummary) {
    if (checks.current.has(engine.route)) return;
    const checkedVersion = engine.configuration_version ?? visibleVersion.current;
    checks.current.add(engine.route);
    generations.current[engine.route] += 1;
    setChecking(new Set(checks.current));
    setRowErrors((current) => ({ ...current, [engine.route]: undefined }));
    try {
      const next = await checkDiscoveryEngine(engine.route);
      if (!alive.current) return;
      if ((next.configuration_version ?? 0) !== visibleVersion.current) { message.info('配置已更新，请刷新配置后重新检测'); return; }
      setOverview((current) => !current || (current.configuration_version ?? 0) !== (next.configuration_version ?? 0) ? current : {
        ...current, items: current.items.map((item) => item.route === next.route ? next : item)
      });
      if (next.health === 'healthy') message.success(`${engine.name}连接测试完成`);
      else setRowErrors((current) => ({ ...current, [engine.route]: next.error_summary || `${engine.name}需要检查连接配置` }));
    } catch (reason) {
      if (alive.current && checkedVersion === visibleVersion.current) setRowErrors((current) => ({ ...current, [engine.route]: errorMessage(reason, '连接检测失败，请稍后重试') }));
    } finally {
      generations.current[engine.route] += 1;
      checks.current.delete(engine.route);
      if (alive.current) setChecking(new Set(checks.current));
    }
  }

  const worker = overview?.worker;
  const policy = overview?.active_policy;
  return <section className="page-surface engine-management-page">
    <PageHeader title="引擎管理" subtitle="管理连接与数据源配置，独立检测每个引擎的可用性"
      actions={<Space><Button icon={<RefreshCw size={16} />} loading={loading} onClick={() => void load()}>刷新配置</Button>
        <Button type="primary" icon={<Settings size={16} />} disabled={!overview?.editable} onClick={() => setEditor('passive')}>编辑配置</Button></Space>} />
    {failure?.forbidden ? <Result status="403" title="403" subTitle="无权查看引擎管理" extra={<Button onClick={() => void load()}>重试</Button>} /> : <>
      {failure && <Alert type="error" showIcon message={failure.message} action={<Button onClick={() => void load()}>重试</Button>} />}
      {!overview && loading ? <Skeleton active paragraph={{ rows: 5 }} /> : overview && <>
        <div className="engine-runtime-line">
          <span>配置版本 <strong>{overview.configuration_version ?? '环境配置'}</strong></span>
          <span><Badge status={worker?.status === 'online' ? 'success' : 'default'} /> Worker {worker?.status === 'online' ? '在线' : worker?.status === 'stale' ? '上报超时' : '状态未知'}</span>
          <span>主动任务{policy?.enabled ? '已开启' : '已关闭'} · 审批{policy?.require_approval ? '必须' : '非必须'} · 权属校验{policy?.require_ownership ? '必须' : '非必须'}</span>
          <Button type="link" disabled={!overview.editable} onClick={() => setEditor('policy')}>调整策略</Button>
        </div>
        {worker?.config_matches === false && <Alert type="info" showIcon message="Worker 尚未上报当前配置版本" description="新任务会读取数据库中的配置，运行状态将在 Worker 下次上报后更新。" />}
        {!overview.editable && <Alert type="info" showIcon message="当前部署尚未启用配置加密存储" description="请按部署说明配置共享加密密钥并完成迁移，即可在线编辑。" />}
        <Table<EngineSummary> rowKey="route" pagination={false} dataSource={overview.items} scroll={{ x: 840 }}
          locale={{ emptyText: '暂无已注册引擎' }}
          columns={[
            { title: '引擎', dataIndex: 'name', width: 190, render: (name, row) => <div><strong>{name}</strong><div className="secondary-text">{row.route === 'passive' ? '被动发现' : '主动发现'}</div></div> },
            { title: '服务地址', dataIndex: 'base_url', ellipsis: true, render: (url) => url || '尚未配置' },
            { title: '连接状态', width: 165, render: (_, row) => checking.has(row.route) ? <span role="status">正在检测…</span> : <Badge status={healthMeta[row.health]?.status ?? 'default'} text={healthMeta[row.health]?.label ?? '未知'} /> },
            { title: '最近检测', dataIndex: 'last_checked_at', width: 165, render: (value) => formatDateTime(value) },
            { title: '响应时间', dataIndex: 'latency_ms', width: 110, render: (value, row) => row.last_checked_at && typeof value === 'number' ? `${value} ms` : '—' },
            { title: '操作', width: 190, render: (_, row) => <Space><Button type="link" disabled={!overview.editable} aria-label={`编辑 ${row.name} 配置`} onClick={() => setEditor(row.route)}>编辑</Button><Button aria-label={`测试 ${row.name} 连接`} disabled={checking.has(row.route) || !row.configured} loading={checking.has(row.route)} onClick={() => void checkConnection(row)}>检测连接</Button></Space> }
          ]}
          expandable={{ expandedRowRender: (engine) => <EngineDetails engine={engine} />, rowExpandable: () => true }}
        />
        <p className="secondary-text">展开引擎可查看能力、数据源和节点。检测不会启动扫描；刷新配置不会重新检测连接。</p>
        {overview.items.map((engine) => (rowErrors[engine.route] || engine.error_summary) && <Alert key={engine.route} type="warning" showIcon message={`${engine.name}：${rowErrors[engine.route] || engine.error_summary}`} />)}
        <div className="engine-provider-toolbar"><div><h3>数据源配置</h3><p className="secondary-text">集中维护 Subfinder、FOFA、Quake、Hunter 和 DNS 配置。</p></div><Button disabled={!overview.editable} onClick={() => setEditor('providers')}>编辑数据源</Button></div>
      </>}
    </>}
    <ConfigurationEditor section={editor} onClose={() => setEditor(null)} onSaved={() => { setEditor(null); void load(); }} />
  </section>;
}

function EngineDetails({ engine }: { engine: EngineSummary }) {
  return <div className="engine-detail-content">
    <Descriptions size="small" column={{ xs: 1, md: 2 }}>
      <Descriptions.Item label="能力">{(engine.capabilities ?? []).map((value) => capabilityLabels[value] ?? value).join('、') || '未报告'}</Descriptions.Item>
      <Descriptions.Item label="引擎实例">{engine.instance_id || '—'}</Descriptions.Item>
      {(engine.credentials ?? []).map((value) => <Descriptions.Item key={value.key} label={value.label}>{value.configured ? value.masked_value || '已配置' : '未配置'}</Descriptions.Item>)}
      {engine.route === 'active' && <Descriptions.Item label="项目关联">ASM 自动管理{engine.project_mapping_count ? `，兼容 ${engine.project_mapping_count} 条历史映射` : ''}</Descriptions.Item>}
    </Descriptions>
    {(engine.providers ?? []).map((provider) => <div key={provider.key} className="engine-provider-row"><strong>{provider.name}</strong><span className="secondary-text">{provider.configured ? '已启用并配置' : '未启用或未配置'}</span>{provider.credentials.map((credential) => <span key={credential.key}>{credential.label}：<code>{credential.masked_value || '未配置'}</code></span>)}</div>)}
    {engine.route === 'active' && <div className="engine-provider-row"><strong>在线节点</strong>{engine.nodes?.length ? engine.nodes.map((node) => <span key={node.node_id}><strong>{node.node_id}</strong> · {node.capabilities.map((v) => capabilityLabels[v] ?? v).join('、')}</span>) : <span>未报告节点，请先检测连接。</span>}</div>}
  </div>;
}

type Field = { key: string; label: string; secret?: boolean; kind?: 'bool' | 'number' | 'map'; help?: string };
const fields: Record<Section, Field[]> = {
  passive: [
    { key: 'passive_url', label: 'Baiyan 服务地址', help: '填写服务根地址，例如 https://engine.example.com。' },
    { key: 'passive_token', label: '连接 Token', secret: true, help: '填写 Baiyan 服务接受的 Token。修改此值不会改变远端服务的认证密钥。' }
  ],
  active: [
    { key: 'active_url', label: '主动引擎服务地址' }, { key: 'active_access_key', label: 'Access Key', secret: true }, { key: 'active_secret_key', label: 'Secret Key', secret: true, help: '至少 32 位，填写主动引擎签发的密钥。' },
  ],
  providers: [
    { key: 'subfinder_disabled', label: 'Subfinder 公共来源', kind: 'bool', help: '使用镜像内的 Subfinder 收集公开子域名，不启动端口扫描。' }, { key: 'quake_enabled', label: '启用 Quake', kind: 'bool' }, { key: 'quake_key', label: 'Quake Key', secret: true }, { key: 'hunter_enabled', label: '启用 Hunter', kind: 'bool' }, { key: 'hunter_key', label: 'Hunter Key', secret: true },
    { key: 'fofa_enabled', label: '启用 FOFA', kind: 'bool' }, { key: 'fofa_email', label: 'FOFA 邮箱', secret: true }, { key: 'fofa_key', label: 'FOFA Key', secret: true }, { key: 'fofa_max_results', label: 'FOFA 最大结果数', kind: 'number' },
    { key: 'provider_name', label: '被动数据源名称' }, { key: 'provider_url', label: '被动数据源地址', help: '留空不使用自定义被动数据源。' }, { key: 'provider_token', label: '被动数据源 Token', secret: true }, { key: 'provider_max_results', label: '被动数据源最大结果数', kind: 'number' },
    { key: 'dns_url', label: 'DNS 服务地址', help: '留空使用系统 DNS 解析。' }, { key: 'dns_token', label: 'DNS 服务 Token', secret: true }, { key: 'dns_max_results', label: 'DNS 服务单批上限', kind: 'number', help: '仅用于自定义 DNS 服务。全部目标会分批处理，不按此值截断总结果。' }
  ],
  policy: [
    { key: 'active_enabled', label: '允许创建主动发现任务', kind: 'bool' },
    { key: 'require_approval', label: '主动任务需要另一位人员审批', kind: 'bool' },
    { key: 'require_ownership', label: '主动任务需要权属核验', kind: 'bool' }
  ]
};
const sections: Array<{ key: Section; label: string }> = [{ key: 'passive', label: '被动引擎' }, { key: 'active', label: '主动引擎' }, { key: 'providers', label: '数据源' }, { key: 'policy', label: '任务策略' }];

function ConfigurationEditor({ section, onClose, onSaved }: { section: Section | null; onClose: () => void; onSaved: () => void }) {
  const { message } = AntApp.useApp();
  const [form] = Form.useForm();
  const [config, setConfig] = useState<EngineConfiguration | null>(null);
  const [active, setActive] = useState<Section>('passive');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [clearSecrets, setClearSecrets] = useState<string[]>([]);
  const sequence = useRef(0);
  const busy = useRef(false);
  const load = useCallback(async () => {
    const request = ++sequence.current;
    setLoading(true); setError(''); setConfig(null); setClearSecrets([]); form.resetFields();
    try {
      const result = await getEngineConfiguration();
      if (request !== sequence.current) return;
      setConfig(result);
      form.setFieldsValue({ ...result.values, ...Object.fromEntries(Object.keys(result.secrets).map((key) => [key, ''])), reason: '' });
    } catch (reason) { if (request === sequence.current) setError(errorMessage(reason, '配置读取失败')); }
    finally { if (request === sequence.current) setLoading(false); }
  }, [form]);
  useEffect(() => {
    if (section) { setActive(section); void load(); }
    return () => { sequence.current += 1; };
  }, [section, load]);
  async function save() {
    if (!config || busy.current) return;
    busy.current = true; setSaving(true); setError('');
    try {
      await form.validateFields();
      const values = form.getFieldsValue(true) as Record<string, unknown>;
      const changed: Record<string, string> = {};
      for (const [key, value] of Object.entries(values)) {
        if (key === 'reason') continue;
        const text = String(value ?? '');
        if (key in config.secrets ? text !== '' : text !== (config.values[key] ?? '')) changed[key] = text;
      }
      if (!Object.keys(changed).length && !clearSecrets.length) { message.info('配置没有变化'); return; }
      await saveEngineConfiguration({ version: config.version, values: changed, clear_secrets: clearSecrets, reason: String(values.reason ?? '') });
      form.resetFields();
      message.success('配置已保存，新任务将使用新版本；已有任务保持原配置。');
      onSaved();
    } catch (reason) {
      if (!(typeof reason === 'object' && reason !== null && 'errorFields' in reason)) setError(errorMessage(reason, '配置保存失败'));
    } finally { busy.current = false; setSaving(false); }
  }
  return <Drawer title="编辑引擎配置" width={680} open={section !== null} onClose={() => { if (!saving) { form.resetFields(); onClose(); } }}
    footer={<Space><Button onClick={onClose} disabled={saving}>取消</Button><Button type="primary" loading={saving} disabled={!config || loading} onClick={() => void save()}>保存配置</Button></Space>}>
    {error && <Alert type="error" showIcon message={error} action={<Button disabled={saving} onClick={() => void load()}>重新加载配置</Button>} />}
    {loading ? <Skeleton active paragraph={{ rows: 8 }} /> : config && <>
      <p className="secondary-text">当前版本 {config.version}。密钥不会回显；留空保持不变。保存不触发连接测试或扫描。</p>
      <Form form={form} layout="vertical" disabled={saving}>
        <Tabs activeKey={active} onChange={(value) => { if (!saving) setActive(value as Section); }} items={sections.map((item) => ({ key: item.key, label: item.label, children: <>
          {item.key === 'active' && <p className="secondary-text">项目由 ASM 自动关联，首次运行时建立，后续自动复用。服务账号需要项目读取和创建权限；已有项目关联会保留。</p>}
          {item.key === 'providers' && config.provider_error ? <Alert type="warning" showIcon message={config.provider_error} /> : fields[item.key].map((field) => <div key={field.key}>
            <Form.Item name={field.key} label={field.label} extra={field.help}>
              {field.secret ? <Input.Password autoComplete="new-password" placeholder={config.secrets[field.key]?.configured ? '已配置，留空保持不变' : '尚未配置'} disabled={saving || clearSecrets.includes(field.key)} />
                : field.kind === 'bool' ? <Select options={field.key === 'subfinder_disabled' ? [{ value: 'false', label: '启用' }, { value: 'true', label: '停用' }] : [{ value: 'true', label: '开启' }, { value: 'false', label: '关闭' }]} />
                : field.kind === 'number' ? <InputNumber min={1} max={field.key === 'dns_max_results' ? 500 : 1000} className="full-width" />
                : field.kind === 'map' ? <Input.TextArea rows={4} spellCheck={false} /> : <Input autoComplete="off" />}
            </Form.Item>
            {field.secret && config.secrets[field.key]?.configured && <Checkbox className="engine-clear-secret" disabled={saving} checked={clearSecrets.includes(field.key)} onChange={(event) => setClearSecrets((current) => event.target.checked ? [...current, field.key] : current.filter((key) => key !== field.key))}>清空已保存的{field.label}</Checkbox>}
          </div>)}
        </> }))} />
        <Form.Item name="reason" label="变更原因" rules={[{ required: true, message: '请填写变更原因' }, { max: 512 }]}><Input.TextArea rows={2} placeholder="简述本次配置调整的原因" /></Form.Item>
      </Form>
    </>}
  </Drawer>;
}

function formatDateTime(value?: string) {
  if (!value) return '尚未检测';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('zh-CN', { hour12: false });
}
