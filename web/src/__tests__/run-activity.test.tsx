import { act, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '../test/server';
import { RunActivity } from '../pages/discovery/RunActivity';
const first={status:'running',stages:[{stage:'collect',provider:'subfinder',target:'example.com',status:'running',discovered:1,completed:0,total:0,failed:0,no_records:0}],recent:[{type:'subdomain',value:'a.example.com',provider:'subfinder',observed_at:'2026-09-18T01:00:00Z'}],asset_count:1,subdomain_count:1,ip_count:0,received_batches:2,processed_batches:2,failed_batches:0,truncated:false};
afterEach(()=>vi.restoreAllMocks());
describe('streaming run activity',()=>{
 it('shows discoveries while running and stops polling when complete',async()=>{
  const polls:Array<()=>void>=[];const original=globalThis.setTimeout;
  vi.spyOn(globalThis,'setTimeout').mockImplementation(((handler:()=>void,delay:number,...args:unknown[])=>{if(delay===4000){const id=original(()=>undefined,60000);polls.push(()=>{globalThis.clearTimeout(id);handler()});return id}return original(handler,delay,...args)}) as typeof globalThis.setTimeout);
  let count=0;server.use(http.get('/api/v1/projects/5/discovery/runs/8/activity',()=>{count++;return HttpResponse.json({data:count===1?first:{...first,status:'success',stages:[{...first.stages[0],status:'success',discovered:2}]}})}));
  render(<MemoryRouter><RunActivity projectId={5} runId={8}/></MemoryRouter>);
  expect(await screen.findByRole('link',{name:'a.example.com'})).toHaveAttribute('href','/projects/5/assets?view=domains&q=a.example.com');
  expect(screen.getByText('执行中')).toBeInTheDocument();expect(polls).toHaveLength(1);
  await act(async()=>{polls.shift()?.()});await screen.findByText('已完成');expect(screen.getByText('本次执行记录')).toBeInTheDocument();expect(polls).toHaveLength(0);
 });
 it('tells retrying batches apart from batches that exhausted their retries',async()=>{
  server.use(http.get('/api/v1/projects/5/discovery/runs/8/activity',()=>HttpResponse.json({data:{...first,status:'success',retrying_batches:2,failed_batches:1}})));
  render(<MemoryRouter><RunActivity projectId={5} runId={8}/></MemoryRouter>);
  expect(await screen.findByText('2 个批次入库暂时失败，正在自动重试，无需操作。')).toBeInTheDocument();
  expect(screen.getByText('1 个批次多次重试仍未入库，已成功入库的结果仍可查看。')).toBeInTheDocument();
 });
 it('shows no failure for a batch that is only retrying',async()=>{
  server.use(http.get('/api/v1/projects/5/discovery/runs/8/activity',()=>HttpResponse.json({data:{...first,status:'success',retrying_batches:1,failed_batches:0}})));
  render(<MemoryRouter><RunActivity projectId={5} runId={8}/></MemoryRouter>);
  expect(await screen.findByText(/正在自动重试/)).toBeInTheDocument();
  expect(screen.queryByText(/仍未入库/)).not.toBeInTheDocument();
 });
 it('does not retain discoveries after access is denied',async()=>{
  server.use(http.get('/api/v1/projects/5/discovery/runs/8/activity',()=>HttpResponse.json({error:{message:'无权限'}},{status:403})));
  render(<MemoryRouter><RunActivity projectId={5} runId={8}/></MemoryRouter>);
  await waitFor(()=>expect(screen.getByText('进度暂时无法更新')).toBeInTheDocument());expect(screen.queryByRole('link',{name:'a.example.com'})).not.toBeInTheDocument();
 });
});
