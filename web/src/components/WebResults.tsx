import { Alert, Button, Drawer, Input, Select, Table, Tag, Tooltip, Typography } from 'antd';
import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ApiError, getJSON, postJSON } from '../api/http';
import { errorMessage } from '../api/errorMessage';
import { WebAssetDetail } from './WebAssetDetail';
import { crawlSource, enrichmentPending, fingerprintNames, missingTitleReason, outcomes, primaryIP, siteHost, stamp, type Website } from './webResultFormat';

export type { Website } from './webResultFormat';

type ResultPage = { items: Website[]; total: number; summary: {total: number; responded: number; titled: number; fingerprinted: number} };

export function WebResults({projectId, runId}: {projectId: number; runId?: number}) {
  const [query, setQuery] = useSearchParams();
  const keyword = query.get('q') ?? '';
  const outcome = query.get('web_outcome') ?? '';
  const cdn = query.get('web_cdn') ?? '';
  const cloud = query.get('web_cloud') ?? '';
  const sort = query.get('web_sort') === 'recent' ? 'recent' : '';
  const page = Math.max(1,Number(query.get('web_page')) || 1);
  const [draft, setDraft] = useState(keyword);
  const [data, setData] = useState<ResultPage>();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState<Website>();
  const [retrying, setRetrying] = useState(false);
  const [retryError, setRetryError] = useState('');
  const [waitingExpired, setWaitingExpired] = useState(false);
  const retryScope = useRef(0);
  const successfulScope = useRef('');
  const rowKey = (row: Website) => `${row.asset_id}:${row.url}`;
  useEffect(() => { setSelected(undefined); }, [projectId, runId, page, keyword, outcome, cdn, cloud, sort]);
  useEffect(()=>setDraft(keyword),[keyword]);
  useEffect(()=>{setSelected(undefined);setRetryError('');setRetrying(false);return()=>{retryScope.current+=1;};},[projectId,runId]);
  useEffect(()=>{
    const controller=new globalThis.AbortController();setLoading(true);setError('');setWaitingExpired(false);
    let timer: ReturnType<typeof globalThis.setTimeout> | undefined;
    let initialWaitPolls=0;
    const scope = JSON.stringify([projectId, runId, page, keyword, outcome, cdn, cloud, sort]);
    if (successfulScope.current !== scope) setData(undefined);
    const path = runId ? `/projects/${projectId}/discovery/runs/${runId}/results` : `/projects/${projectId}/assets/web-results`;
    const load = async () => {
      try {
        const value = await getJSON<ResultPage>(path,{page_number:page,page_size:20,keyword,outcome,cdn,cloud,sort:sort||undefined},controller.signal);
        if(controller.signal.aborted)return;
        successfulScope.current = scope;
        setError('');
        setData(value);
        setSelected(current => current ? value.items.find(row => row.url === current.url && row.run_id === current.run_id) ?? current : undefined);
        const pending=value.items.some(enrichmentPending);
        const notStarted=value.items.some(row=>row.enrichment_state==='not_started'&&row.run_id>0);
        const waitForStart=!pending&&notStarted&&initialWaitPolls<12;
        if(waitForStart)initialWaitPolls+=1;
        setWaitingExpired(!pending&&notStarted&&!waitForStart);
        if(pending||waitForStart) timer = globalThis.setTimeout(()=>{void load();},5000);
      } catch(reason) {
        if(!controller.signal.aborted){
          const forbidden = reason instanceof ApiError && [401, 403].includes(reason.status);
          if (forbidden || successfulScope.current !== scope) { setData(undefined); setSelected(undefined); successfulScope.current = ''; }
          setError(errorMessage(reason));
        }
      } finally {
        if(!controller.signal.aborted)setLoading(false);
      }
    };
    void load();
    return()=>{controller.abort();if(timer!==undefined)globalThis.clearTimeout(timer);};
  },[projectId,runId,page,keyword,outcome,cdn,cloud,sort,revision]);
  async function retryEnrichment(sourceRunId: number) {
    if(retrying)return;
    const scope=retryScope.current;
    setRetrying(true);setRetryError('');
    try {
      await postJSON(`/projects/${projectId}/discovery/runs/${sourceRunId}/network-enrichment/retry`);
      if(scope===retryScope.current)setRevision(value=>value+1);
    } catch(reason) {
      if(scope===retryScope.current)setRetryError(errorMessage(reason));
    } finally {
      if(scope===retryScope.current)setRetrying(false);
    }
  }
  function change(key: string,value: string){const next=new globalThis.URLSearchParams(query);if(value){next.set(key,value);}else{next.delete(key);}if(key!=='web_page')next.delete('web_page');setQuery(next);}
  const stats=data?.summary;
  const filters = [
    { key: 'q', value: keyword, label: `搜索：${keyword}` },
    { key: 'web_outcome', value: outcome, label: `探测：${outcomes[outcome] || outcome}` },
    { key: 'web_cdn', value: cdn, label: cdn === 'identified' ? '已识别 CDN' : 'CDN 未知' },
    { key: 'web_cloud', value: cloud, label: cloud === 'identified' ? '已识别云厂商' : '云归属未知' }
  ].filter(filter => filter.value);
  function clearFilters() {
    const next = new globalThis.URLSearchParams(query);
    ['q', 'web_outcome', 'web_cdn', 'web_cloud', 'web_page'].forEach(key => next.delete(key));
    setQuery(next);
  }
  return <section className="web-results">
    <div className="web-results-toolbar">
      <Input.Search className="web-search" aria-label="搜索网站" placeholder="搜索标题、URL、指纹、IP 或厂商" value={draft} maxLength={256} onChange={e=>setDraft(e.target.value)} onSearch={v=>change('q',v.trim())} allowClear />
      <Select className="web-filter" aria-label="探测结果" value={outcome} onChange={v=>change('web_outcome',v)} options={[{value:'',label:'全部探测结果'},...Object.entries(outcomes).map(([value,label])=>({value,label}))]} />
      <Select className="web-filter" aria-label="CDN 筛选" value={cdn} onChange={v=>change('web_cdn',v)} options={[{value:'',label:'全部 CDN 状态'},{value:'identified',label:'已识别 CDN'},{value:'unknown',label:'CDN 未知'}]} />
      <Select className="web-filter" aria-label="云归属筛选" value={cloud} onChange={v=>change('web_cloud',v)} options={[{value:'',label:'全部云归属'},{value:'identified',label:'已识别云厂商'},{value:'unknown',label:'云归属未知'}]} />
      <Select className="web-filter" aria-label="排序" value={sort} onChange={v=>change('web_sort',v)} options={[{value:'',label:'有标题优先'},{value:'recent',label:'最近观察'}]} />
      <Button className="web-refresh" onClick={()=>setRevision(v=>v+1)} loading={loading}>刷新</Button>
    </div>
    {error&&<Alert type="error" showIcon message="网站结果加载失败" description={data ? `${error}。已保留最近成功加载的结果，可重试更新。` : error} action={<Button onClick={()=>setRevision(v=>v+1)}>重试</Button>} />}
    {waitingExpired&&<Alert type="info" message="部分网络归属查询尚未开始" description="网站结果已可查看，暂未收到 Baiyan 的查询状态。可稍后刷新，或检查 Baiyan 服务配置。" action={<Button onClick={()=>setRevision(v=>v+1)}>刷新查询状态</Button>} />}
    {filters.length > 0 && <div className="asset-applied-filters" aria-label="已应用的网站筛选">{filters.map(filter => <Tag key={filter.key} closable onClose={() => change(filter.key, '')}>{filter.label}</Tag>)}<Button type="link" size="small" onClick={clearFilters}>清除筛选</Button></div>}
    {stats&&<div className="discovery-summary-line" aria-label="网站结果统计"><span>网站 <strong>{stats.total}</strong></span><span>有响应 <strong>{stats.responded}</strong></span><span>有标题 <strong>{stats.titled}</strong></span><span>有指纹 <strong>{stats.fingerprinted}</strong></span><span>未返回 HTTP 响应 <strong>{stats.total-stats.responded}</strong></span></div>}
    <p className="secondary-text web-results-note">{runId ? '本次任务的网站快照' : '网站最新观察'} · 网络归属由 Baiyan 补充。<Tooltip title="点击网站标题查看完整 IP、指纹、判断证据和采集时间。未知表示尚无结论，不代表未使用 CDN 或云服务。"><span className="web-note-help" tabIndex={0}>数据说明</span></Tooltip></p>
    <Table<Website> className="web-results-table" tableLayout="fixed" rowKey={rowKey} onRow={row=>({onClick:()=>setSelected(row),className:'web-result-row'})} dataSource={data?.items??[]} loading={loading} scroll={{x:960}} pagination={{current:page,pageSize:20,total:data?.total??0,showSizeChanger:false,showTotal:total=>`共 ${total} 个网站`,onChange:p=>change('web_page',String(p))}} locale={{emptyText:'没有匹配的网站结果'}} columns={[
      {title:'网站',key:'website',width:'30%',render:(_,row)=><div className="web-identity"><Button type="link" className="web-title-link" title={row.title||row.url} onClick={event=>{event.stopPropagation();setSelected(row);}}>{row.title||siteHost(row.url)}</Button><Typography.Text className="web-url" type="secondary" ellipsis={{tooltip:row.url}}>{row.title?row.url:missingTitleReason(row)}</Typography.Text>{crawlSource(row)&&<Tooltip title="来自搜索引擎的历史收录，不是本平台的实时探测"><Tag className="web-crawl-tag">{`${crawlSource(row)} 测绘`}</Tag></Tooltip>}</div>},
      {title:'状态码',key:'outcome',width:'10%',render:(_,row)=><span>{row.status_code ? <Tag color={row.status_code >= 400 ? 'orange' : 'green'}>{row.status_code}</Tag> : <span className="secondary-text">{crawlSource(row)?'测绘未提供':outcomes[row.outcome]||'未返回详情'}</span>}</span>},
      {title:'技术栈',key:'fingerprints',width:'18%',render:(_,row)=>{const names=fingerprintNames(row.fingerprints??[]);return <div className="web-fingerprints">{names.slice(0,2).map(name=><Button key={name} type="link" size="small" className="web-fingerprint-filter" title={`筛选 ${name}`} onClick={event=>{event.stopPropagation();change('q', name);}}>{name}</Button>)}{names.length>2&&<span className="secondary-text"> +{names.length-2}</span>}{!names.length&&<span className="secondary-text">未识别</span>}</div>;}},
      {title:'负责人',key:'owner',width:'10%',render:(_,row)=>row.asset_id>0?(row.owner?<span title={row.business_unit||undefined}>{row.owner}</span>:<span className="secondary-text">未设置</span>):<span className="secondary-text">-</span>},
      {title:'IP / CDN',key:'ips',width:'18%',render:(_,row)=>{const ip=primaryIP(row);const edge=[row.cdn?.status==='identified'?`CDN ${row.cdn.provider||'已识别'}`:'',row.cloud?.status==='identified'?(row.cloud.provider||'云'):''].filter(Boolean).join(' · ');return <div>{ip?<span className="web-ip">{ip}{row.resolved_ips.length>1?<span className="secondary-text"> 等 {row.resolved_ips.length} 个</span>:null}</span>:<span className="secondary-text">未知</span>}{edge?<span className="secondary-text web-cell-caption">{edge}</span>:null}</div>;}},
      {title:'最近观察',dataIndex:'observed_at',width:'14%',render:(value:string)=><span className="web-observed-at" title={stamp(value)}>{new Date(value).toLocaleDateString()}<br/><span className="secondary-text">{new Date(value).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</span></span>}
    ]} />
    <Drawer title="网站详情" className="web-details-drawer" open={!!selected} onClose={()=>setSelected(undefined)} width={860}>
      {selected&&<WebAssetDetail projectId={projectId} row={selected} runId={runId} retrying={retrying} retryError={retryError} onRetryEnrichment={sourceRunId=>void retryEnrichment(sourceRunId)} />}
    </Drawer>
  </section>;
}
