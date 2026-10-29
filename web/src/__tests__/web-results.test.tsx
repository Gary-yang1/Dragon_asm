import {act,render,screen,waitFor,within} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {MemoryRouter} from 'react-router-dom';
import {afterEach,beforeEach,describe,it,expect,vi} from 'vitest';
import {http,HttpResponse} from 'msw';
import {server} from '../test/server';
import {WebResults} from '../components/WebResults';
vi.mock('../auth/usePermission',()=>({usePermission:()=>({can:()=>true})}));
const item={asset_id:1,run_id:11,url:'https://example.test',title:'Example website',status_code:403,fingerprints:['nginx','React'],outcome:'responded',resolved_ips:['192.0.2.1','2001:db8::1'],connected_ip:'192.0.2.1',cname_chain:['a.cloudfront.net'],cdn:{status:'identified',provider:'Amazon CloudFront',evidence:['CNAME: a.cloudfront.net']},cloud:{status:'identified',provider:'AWS'},observed_at:'2026-09-16T01:00:00Z'};
const pageFor=(row:Record<string,unknown>)=>({data:{items:[row],total:1,summary:{total:1,responded:1,titled:1,fingerprinted:1}}});
function capturePolls(){
 const polls:Array<()=>void>=[];
 const original=globalThis.setTimeout;
 vi.spyOn(globalThis,'setTimeout').mockImplementation(((handler:Parameters<typeof globalThis.setTimeout>[0],delay?:number,...args:unknown[])=>{
  if(delay===5000&&typeof handler==='function'){
   const id=original(()=>undefined,60000);
   polls.push(()=>{globalThis.clearTimeout(id);handler();});
   return id;
  }
  return original(handler,delay,...args);
 }) as typeof globalThis.setTimeout);
 return polls;
}
const assetRecord={id:1,project_id:5,asset_type:'web',asset_key:'web:https://example.test',display_name:'',value:'https://example.test',source:'discovery',owner:'alice',business_unit:'retail',confidence:95,miss_count:0,status:'active',first_seen:'2026-09-01T00:00:00Z',last_seen:'2026-09-16T01:00:00Z',created_at:'2026-09-01T00:00:00Z',updated_at:'2026-09-16T01:00:00Z',created_by:'u1',updated_by:'u1'};
const hostGraph={nodes:[{id:1,asset_type:'web',value:item.url,display_name:''},{id:8,asset_type:'domain',value:'example.test',display_name:'Example domain'}],edges:[{id:3,from_asset_id:8,to_asset_id:1,relation_type:'contains',source:'discovery',confidence:95,last_seen:'2026-09-16T01:00:00Z'}],truncated:false};
const openSource=async(drawer:HTMLElement)=>userEvent.click(within(drawer).getByText('数据来源（探测证据、采集时间、来源任务）'));
const assetRisks=[{id:41,project_id:5,risk_key:'r41',title:'Fixed weak TLS',severity:'medium',status:'fixed',owner:'',business_unit:'',score:40,created_at:'2026-09-01T00:00:00Z'},{id:42,project_id:5,risk_key:'r42',title:'Admin login exposed',severity:'high',status:'new',owner:'',business_unit:'',score:80,created_at:'2026-09-02T00:00:00Z'}];
beforeEach(()=>{server.use(http.get('/api/v1/projects/5/assets/1',()=>HttpResponse.json({data:assetRecord})),http.get('/api/v1/projects/5/assets/1/graph',()=>HttpResponse.json({data:hostGraph})),http.get('/api/v1/projects/5/risks',()=>HttpResponse.json({data:{items:[],total:0,page_size:50,page_number:1}})));});
afterEach(()=>vi.restoreAllMocks());
describe('website results',()=>{
 it('opens a task-specific website snapshot and links to assets',async()=>{
  server.use(http.get('/api/v1/projects/5/discovery/runs/11/results',()=>HttpResponse.json({data:{items:[item],total:100,summary:{total:100,responded:47,titled:44,fingerprinted:35}}})));
  render(<MemoryRouter initialEntries={['/projects/5/discovery?run_id=11']}><WebResults projectId={5} runId={11}/></MemoryRouter>);
  await userEvent.click(await screen.findByRole('button',{name:'Example website'}));
  const drawer=await screen.findByRole('dialog');expect(within(drawer).getByText('nginx')).toBeInTheDocument();expect(within(drawer).getByText('React')).toBeInTheDocument();expect(within(drawer).getByText('2001:db8::1')).toBeInTheDocument();expect(within(drawer).getByRole('link',{name:'在 Web 资产中定位'})).toHaveAttribute('href','/projects/5/assets?view=web&q=https%3A%2F%2Fexample.test');
  expect(screen.queryByText('435')).not.toBeInTheDocument();
 });
 it('sends website search to the server and exposes a retryable failure',async()=>{
  const keywords:string[]=[];
  server.use(http.get('/api/v1/projects/5/assets/web-results',({request})=>{const keyword=new globalThis.URL(request.url).searchParams.get('keyword')??'';keywords.push(keyword);if(keyword==='bad')return HttpResponse.json({error:{message:'暂时不可用'}},{status:503});return HttpResponse.json({data:{items:[item],total:1,summary:{total:1,responded:1,titled:1,fingerprinted:1}}});}));
  render(<MemoryRouter><WebResults projectId={5}/></MemoryRouter>);await screen.findByRole('button',{name:'Example website'});
  await userEvent.type(screen.getByRole('searchbox',{name:'搜索网站'}),'bad{Enter}');await screen.findByText('网站结果加载失败');expect(keywords).toContain('bad');expect(screen.queryByRole('button',{name:'Example website'})).not.toBeInTheDocument();
 });
 it('updates separate Baiyan evidence in an open drawer and stops polling once complete',async()=>{
  const polls=capturePolls();let requests=0;
  server.use(http.get('/api/v1/projects/5/discovery/runs/11/results',()=>{
   requests+=1;
   return HttpResponse.json(pageFor(requests<=2?{...item,enrichment_state:requests===1?'not_started':'pending'}:{...item,enrichment_state:'complete',network_source:'baiyan',network_status:'partial',network_observed_at:'2026-09-16T01:05:00Z',resolved_ips:['192.0.2.20']}));
  }));
  render(<MemoryRouter initialEntries={['/projects/5/discovery?run_id=11']}><WebResults projectId={5} runId={11}/></MemoryRouter>);
  await userEvent.click(await screen.findByRole('button',{name:'Example website'}));
  expect(within(screen.getByRole('dialog')).getByText('网络归属尚未查询')).toBeInTheDocument();
  expect(polls).toHaveLength(1);
  await act(async()=>{polls.shift()?.();});
  await within(screen.getByRole('dialog')).findByText('网络归属查询中');
  await act(async()=>{polls.shift()?.();});
  const drawer=screen.getByRole('dialog');
  expect((await within(drawer).findAllByText('网络信息部分补齐')).length).toBeGreaterThan(0);
  await openSource(drawer);
  expect(await within(drawer).findByText('192.0.2.20（Baiyan 查询，可能与扫描时地址不同）')).toBeInTheDocument();
  expect(within(drawer).getAllByText('192.0.2.1').length).toBeGreaterThan(0);
  expect(within(drawer).getByText('有 HTTP 响应 · HTTP 403')).toBeInTheDocument();
  expect(polls).toHaveLength(0);expect(requests).toBe(3);
 });
 it('bounds the initial wait if network enrichment never starts',async()=>{
  const polls=capturePolls();let requests=0;
  server.use(http.get('/api/v1/projects/5/assets/web-results',()=>{requests+=1;return HttpResponse.json(pageFor({...item,enrichment_state:'not_started'}));}));
  render(<MemoryRouter><WebResults projectId={5}/></MemoryRouter>);
  await screen.findByRole('button',{name:'Example website'});
  for(let i=0;i<12;i+=1){
   expect(polls).toHaveLength(1);
   await act(async()=>{polls.shift()?.();});
   await waitFor(()=>expect(requests).toBe(i+2));
   if(i<11)await waitFor(()=>expect(polls).toHaveLength(1));
  }
  await screen.findByText('部分网络归属查询尚未开始');
  expect(polls).toHaveLength(0);expect(requests).toBe(13);
 });
 it('retries failed enrichment independently of the successful website task',async()=>{
  let retried=false;
  server.use(http.get('/api/v1/projects/5/assets/web-results',()=>HttpResponse.json(pageFor({...item,enrichment_state:retried?'complete':'failed',network_source:retried?'baiyan':undefined,network_status:retried?'success':undefined}))),http.post('/api/v1/projects/5/discovery/runs/11/network-enrichment/retry',()=>{retried=true;return HttpResponse.json({data:{queued:1}});}));
  render(<MemoryRouter><WebResults projectId={5}/></MemoryRouter>);
  await userEvent.click(await screen.findByRole('button',{name:'Example website'}));
  await userEvent.click(within(screen.getByRole('dialog')).getByRole('button',{name:'重试本次任务网络查询'}));
  await waitFor(()=>expect(within(screen.getByRole('dialog')).queryByText('网络归属查询失败')).not.toBeInTheDocument());
  expect(retried).toBe(true);expect(within(screen.getByRole('dialog')).getByText('HTTP 403')).toBeInTheDocument();
 });
 it('clears protected results and stops pending refresh when permission is revoked',async()=>{
  const polls=capturePolls();let requests=0;
  server.use(http.get('/api/v1/projects/5/assets/web-results',()=>{requests+=1;return requests===1?HttpResponse.json(pageFor({...item,enrichment_state:'running'})):HttpResponse.json({error:{message:'没有权限'}},{status:403});}));
  render(<MemoryRouter><WebResults projectId={5}/></MemoryRouter>);
  await userEvent.click(await screen.findByRole('button',{name:'Example website'}));
  await act(async()=>{polls.shift()?.();});
  await screen.findByText('网站结果加载失败');
  expect(screen.queryByRole('button',{name:'Example website'})).not.toBeInTheDocument();
  await waitFor(()=>expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(polls).toHaveLength(0);expect(requests).toBe(2);
 });
 it('keeps successful results and the drawer when a background refresh temporarily fails',async()=>{
  const polls=capturePolls();let requests=0;
  server.use(http.get('/api/v1/projects/5/assets/web-results',()=>{
   requests+=1;
   return requests===1?HttpResponse.json(pageFor({...item,enrichment_state:'running'})):HttpResponse.json({error:{message:'服务暂时不可用'}},{status:503});
  }));
  render(<MemoryRouter><WebResults projectId={5}/></MemoryRouter>);
  await userEvent.click(await screen.findByRole('button',{name:'Example website'}));
  await act(async()=>{polls.shift()?.();});
  await screen.findByText('网站结果加载失败');
  expect(screen.getByRole('button',{name:'Example website'})).toBeInTheDocument();
  expect(screen.getByRole('dialog')).toBeInTheDocument();
  expect(screen.getByText(/已保留最近成功加载的结果/)).toBeInTheDocument();
 });
 it('opens ownership first and keeps collection evidence folded',async()=>{
  const graphRequest=vi.fn();
  server.use(http.get('/api/v1/projects/5/assets/web-results',()=>HttpResponse.json(pageFor(item))),http.get('/api/v1/projects/5/assets/1/graph',()=>{graphRequest();return HttpResponse.json({data:hostGraph});}));
  render(<MemoryRouter><WebResults projectId={5}/></MemoryRouter>);
  await screen.findByRole('button',{name:'Example website'});
  expect(graphRequest).not.toHaveBeenCalled();
  await userEvent.click(screen.getByText('192.0.2.1'));
  const drawer=await screen.findByRole('dialog');
  expect(await within(drawer).findByText('alice')).toBeInTheDocument();
  expect(within(drawer).getByText('retail')).toBeInTheDocument();
  expect(within(drawer).getByRole('link',{name:'Example domain'})).toHaveAttribute('href','/projects/5/assets?view=domains&asset_id=8');
  expect(within(drawer).getByRole('link',{name:'查看来源任务 #11'})).toHaveAttribute('href','/projects/5/discovery?run_id=11');
  expect(within(drawer).getByRole('button',{name:/编辑/})).toBeInTheDocument();
  expect(within(drawer).queryByText('CNAME 证据')).not.toBeInTheDocument();
  expect(within(drawer).queryByText('a.cloudfront.net')).not.toBeInTheDocument();
  await openSource(drawer);
  expect(await within(drawer).findByText('a.cloudfront.net')).toBeInTheDocument();
 });
 it('names untitled sites by host and says why the title is missing',async()=>{
  server.use(http.get('/api/v1/projects/5/assets/web-results',()=>HttpResponse.json({data:{items:[
   {...item,url:'http://app.example.test:80',title:'',status_code:0,outcome:'unknown',fingerprints:[]},
   {...item,asset_id:2,url:'http://blank.example.test:8080',title:'',status_code:200}
  ],total:2,summary:{total:2,responded:1,titled:0,fingerprinted:1}}})));
  render(<MemoryRouter><WebResults projectId={5}/></MemoryRouter>);
  expect(await screen.findByRole('button',{name:'app.example.test'})).toBeInTheDocument();
  expect(screen.getByText('未获取到响应信息')).toBeInTheDocument();
  expect(screen.getByRole('button',{name:'blank.example.test:8080'})).toBeInTheDocument();
  expect(screen.getByText('页面无标题')).toBeInTheDocument();
  expect(screen.queryByText('未返回标题')).not.toBeInTheDocument();
 });
 it('shows the owner and switches to newest-first ordering',async()=>{
  const sorts:string[]=[];
  server.use(http.get('/api/v1/projects/5/assets/web-results',({request})=>{sorts.push(new URL(request.url).searchParams.get('sort')??'');return HttpResponse.json({data:{items:[{...item,owner:'alice',business_unit:'retail'},{...item,asset_id:2,url:'https://b.test',title:'B site',owner:''},{...item,asset_id:0,url:'https://c.test',title:'C site'}],total:3,summary:{total:3,responded:3,titled:3,fingerprinted:3}}});}));
  render(<MemoryRouter><WebResults projectId={5}/></MemoryRouter>);
  await screen.findByRole('button',{name:'Example website'});
  const rows=screen.getAllByRole('row');
  expect(within(rows[1]).getByText('alice')).toBeInTheDocument();
  expect(within(rows[2]).getByText('未设置')).toBeInTheDocument();
  expect(within(rows[3]).queryByText('未设置')).not.toBeInTheDocument();
  expect(sorts.at(-1)).toBe('');
  await userEvent.click(screen.getByRole('combobox',{name:'排序'}));
  await userEvent.click(await screen.findByTitle('最近观察'));
  await waitFor(()=>expect(sorts.at(-1)).toBe('recent'));
 });
 it('lists the asset risks in the website detail, open ones first',async()=>{
  const assetIds:string[]=[];
  server.use(http.get('/api/v1/projects/5/assets/web-results',()=>HttpResponse.json(pageFor(item))),http.get('/api/v1/projects/5/risks',({request})=>{assetIds.push(new URL(request.url).searchParams.get('asset_id')??'');return HttpResponse.json({data:{items:assetRisks,total:2,page_size:50,page_number:1}});}));
  render(<MemoryRouter><WebResults projectId={5}/></MemoryRouter>);
  await userEvent.click(await screen.findByRole('button',{name:'Example website'}));
  const drawer=await screen.findByRole('dialog');
  const list=await within(drawer).findByRole('list',{name:'关联风险'});
  expect(assetIds).toEqual(['1']);
  expect(within(drawer).getByText('开放 1 个 · 共 2 个')).toBeInTheDocument();
  const links=within(list).getAllByRole('link');
  expect(links.map(link=>link.textContent)).toEqual(['Admin login exposed','Fixed weak TLS']);
  expect(links[0]).toHaveAttribute('href','/projects/5/risks?risk_id=42');
 });
 it('labels search-engine crawls apart from live probes',async()=>{
  server.use(http.get('/api/v1/projects/5/assets/web-results',()=>HttpResponse.json({data:{items:[
   {...item,url:'http://crawled.example.test:80',title:'Crawled portal',status_code:0,outcome:'unknown',provider:'fofa',active_probe:false,fingerprints:['nginx']},
   {...item,asset_id:2,url:'http://crawled-blank.example.test:80',title:'',status_code:0,outcome:'unknown',provider:'fofa',active_probe:false},
   {...item,asset_id:3,provider:'active_api',active_probe:true}
  ],total:3,summary:{total:3,responded:1,titled:2,fingerprinted:3}}})));
  render(<MemoryRouter><WebResults projectId={5}/></MemoryRouter>);
  await screen.findByRole('button',{name:'Crawled portal'});
  const rows=screen.getAllByRole('row').slice(1);
  expect(within(rows[0]).getByText('FOFA 测绘')).toBeInTheDocument();
  expect(within(rows[0]).getByText('测绘未提供')).toBeInTheDocument();
  expect(within(rows[1]).getByText('测绘未记录标题')).toBeInTheDocument();
  expect(within(rows[2]).queryByText(/测绘/)).not.toBeInTheDocument();
  await userEvent.click(within(rows[0]).getByRole('button',{name:'Crawled portal'}));
  const drawer=await screen.findByRole('dialog');
  expect(within(drawer).getByText('FOFA 测绘数据')).toBeInTheDocument();
  expect(within(drawer).getByText('状态码未知')).toBeInTheDocument();
  expect(within(drawer).getByText(/来自 FOFA 的历史收录/)).toBeInTheDocument();
 });
 it('filters by a fingerprint and clears only website filters',async()=>{
  const keywords:string[]=[];
  server.use(http.get('/api/v1/projects/5/assets/web-results',({request})=>{keywords.push(new URL(request.url).searchParams.get('keyword')||'');return HttpResponse.json(pageFor(item));}));
  render(<MemoryRouter initialEntries={['/projects/5/assets?view=web']}><WebResults projectId={5}/></MemoryRouter>);
  await userEvent.click(await screen.findByRole('button',{name:'nginx'}));
  await waitFor(()=>expect(keywords.at(-1)).toBe('nginx'));
  expect(screen.getByText('搜索：nginx')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button',{name:'清除筛选'}));
  await waitFor(()=>expect(keywords.at(-1)).toBe(''));
  expect(screen.getByRole('searchbox',{name:'搜索网站'})).toHaveValue('');
 });

});
