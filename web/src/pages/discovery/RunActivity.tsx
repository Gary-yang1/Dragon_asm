import { Alert, Button, Space, Table, Tag, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ApiError, getJSON } from '../../api/http';
import { errorMessage } from '../../api/errorMessage';

type Stage = { stage: string; provider: string; target: string; status: string; discovered: number; completed: number; total: number; failed: number; no_records: number; message?: string };
type Discovery = { type: string; value: string; provider: string; observed_at: string; dns_status?: string; dns_error?: string };
type Activity = { status: string; stages: Stage[]; recent: Discovery[]; asset_count: number; subdomain_count: number; ip_count: number; received_batches: number; processed_batches: number; failed_batches: number; retrying_batches?: number; truncated: boolean };
const states: Record<string, string> = { queued:'等待执行', running:'执行中', success:'已完成', partial:'部分完成', failed:'失败', skipped:'未配置 / 跳过' };
const providers: Record<string,string> = {fofa:'FOFA',quake:'Quake',hunter:'Hunter',subfinder:'Subfinder',dns:'DNS 解析',certificate_transparency:'证书透明度'};

function stageMessage(message?: string) {
  if (!message) return '';
  if (message.includes('DNS_PARTIAL_FAILURE') || message.includes('DNS resolution')) return '部分域名解析未完成，成功结果已保留。旧任务可能未记录具体失败域名。';
  if (message.includes('PROVIDER_NOT_CONFIGURED') || message.includes('not configured')) return '该来源未启用或未配置，请在引擎管理中检查。';
  if (message.includes('PROVIDER_UNAVAILABLE') || message.includes('provider request failed')) return '该来源请求未完成，已收到的发现结果已保留。';
  return message;
}

export function RunActivity({ projectId, runId }: { projectId: number; runId: number }) {
  const [data, setData] = useState<Activity>();
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new globalThis.AbortController();
    let timer: ReturnType<typeof globalThis.setTimeout>;
    let failures = 0;
    setData(undefined); setError('');
    async function load() {
      try {
        const next = await getJSON<Activity>(`/projects/${projectId}/discovery/runs/${runId}/activity`, undefined, controller.signal);
        if (controller.signal.aborted) return;
        setData(next); setError(''); failures = 0;
        if (['pending','running'].includes(next.status)) timer = globalThis.setTimeout(() => void load(), 4000);
      } catch (reason) {
        if (controller.signal.aborted) return;
        setError(errorMessage(reason));
        if (reason instanceof ApiError && [401,403,404].includes(reason.status)) setData(undefined);
        else if (++failures <= 3) timer = globalThis.setTimeout(() => void load(), 4000);
      }
    }
    void load();
    return () => { controller.abort(); globalThis.clearTimeout(timer); };
  }, [projectId, runId, revision]);
  return <section className="discovery-live-activity" aria-label="实时发现进度">
    <div className="discovery-live-heading"><Typography.Title level={5}>实时发现进度</Typography.Title><Typography.Text type="secondary">{error ? '更新中断，可手动重试' : data && !['pending','running'].includes(data.status) ? '本次执行记录' : '执行中每 4 秒更新'}</Typography.Text></div>
    {error && <Alert type="warning" showIcon message="进度暂时无法更新" description={data ? `${error}。当前保留上次成功读取的结果。` : error} action={<Button size="small" onClick={() => setRevision(v => v + 1)}>重试</Button>} />}
    {!data && !error && <Typography.Text type="secondary">正在读取来源状态和已返回结果…</Typography.Text>}
    {data && <>
      <div className="discovery-summary-line"><span>已入库子域名 <strong>{data.subdomain_count}</strong></span><span>IP <strong>{data.ip_count}</strong></span><span>已处理批次 <strong>{data.processed_batches} / {data.received_batches}</strong></span></div>
      {(data.retrying_batches ?? 0) > 0 && <Alert type="info" showIcon message={`${data.retrying_batches} 个批次入库暂时失败，正在自动重试，无需操作。`} />}
      {data.failed_batches > 0 && <Alert type="warning" message={`${data.failed_batches} 个批次多次重试仍未入库，已成功入库的结果仍可查看。`} />}
      <Table<Stage> size="small" rowKey={s => `${s.stage}:${s.provider}:${s.target}`} pagination={false} dataSource={data.stages} locale={{emptyText:'尚未收到阶段状态，等待引擎回传。'}} columns={[
        {title:'来源 / 阶段',key:'source',render:(_,s)=><div>{providers[s.provider] || s.provider}{s.target && <div className="secondary-text">{s.target}</div>}</div>},
        {title:'状态',dataIndex:'status',render:(value:string)=><Tag color={value==='running'?'processing':value==='failed'||value==='partial'?'warning':value==='success'?'success':undefined}>{states[value]||value}</Tag>},
        {title:'结果',key:'results',render:(_,s)=>s.stage==='dns'?(s.total>0?`${s.completed} / ${s.total} 已处理 · ${s.no_records} 无记录 · ${s.failed} 异常`:'未记录逐项统计'):`发现 ${s.discovered} 个域名`},
      ]} expandable={{rowExpandable:s=>!!s.message,defaultExpandAllRows:true,expandedRowRender:s=><Typography.Text type="secondary">{stageMessage(s.message)}</Typography.Text>}} />
      {data.truncated && <Typography.Paragraph type="secondary">仅展示最近阶段记录。</Typography.Paragraph>}
      <div className="discovery-live-heading"><Typography.Title level={5}>已返回的资产</Typography.Title><span className="secondary-text">已入库 {data.asset_count} 项 · 展示最近 20 项</span></div>
      <Table<Discovery> size="small" rowKey={r=>`${r.type}:${r.value}`} pagination={false} dataSource={data.recent} locale={{emptyText:'尚无已入库资产；来源返回后会自动显示，无需等待任务结束。'}} columns={[
        {title:'资产',dataIndex:'value',render:(value:string,row)=><Link to={`/projects/${projectId}/assets?view=${row.type==='ip'?'ips':'domains'}&q=${encodeURIComponent(value)}`}>{value}</Link>},
        {title:'来源',dataIndex:'provider',render:(value:string)=>providers[value]||value},
        {title:'DNS 观察',key:'dns',render:(_,row)=>row.dns_status==='failed'?<span title={row.dns_error}>解析异常</span>:row.dns_status==='no_records'?'无解析记录':row.dns_status==='success'?'已解析':'—'},
      ]} />
      <Space className="discovery-live-note"><Typography.Text type="secondary">不同来源的域名数量可能重叠；已入库数量按资产去重。解析无记录与请求异常分别统计。</Typography.Text></Space>
    </>}
  </section>;
}
