import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App as AntApp } from 'antd';
import { http, HttpResponse } from 'msw';
import { describe, expect, it, vi } from 'vitest';

import type { Scope } from '../api/discovery';
import { BlueprintCatalog } from '../pages/discovery/BlueprintCatalog';
import { server } from '../test/server';

const scope: Scope = {
  id: 1,
  project_id: 1,
  name: 'Production domains',
  status: 'active',
  authorized_by: 'CISO',
  valid_from: '2026-07-01T00:00:00Z',
  valid_until: '2099-08-01T00:00:00Z',
  is_default: true,
  targets: [{
    id: 1,
    target_type: 'domain',
    match_mode: 'include',
    coverage_mode: 'subdomains',
    value: 'example.com'
  }]
};

const blueprint = {
  key: 'domain_asset_inventory',
  version: '1.0.0',
  name: '域名资产盘点',
  description: '从授权根域名收集被动情报。',
  category: 'asset_inventory',
  risk_level: 'passive',
  required_target_types: ['domain'],
  steps: [
    {
      key: 'passive_intel',
      name: '被动子域名情报',
      description: '收集授权域名相关资产。',
      task_type: 'passive_intel',
      engine_route: 'passive',
      required_target_types: ['domain'],
      depends_on: [],
      defaults: { timeout_seconds: 1800, rate_limit: 200, concurrency: 10, retry_limit: 3 }
    }
  ]
};

describe('BlueprintCatalog', () => {
  it('previews a scenario and explicitly creates manual templates without dispatching', async () => {
    let previewScopeId: unknown;
    let materializedScopeId: unknown;
    let unexpectedDispatch = false;
    const onTemplatesCreated = vi.fn();
    server.use(
      http.get('/api/v1/projects/1/discovery/blueprints', () => HttpResponse.json({
        request_id: 'req-blueprints',
        data: { items: [blueprint], total: 1, page_size: 100, page_number: 1 }
      })),
      http.post('/api/v1/projects/1/discovery/blueprints/domain_asset_inventory/preview', async ({ request }) => {
        const body = await request.json() as { scope_id?: unknown };
        previewScopeId = body.scope_id;
        return HttpResponse.json({
          request_id: 'req-preview',
          data: {
            execution_mode: 'preview_only',
            blueprint,
            project_status: 'active',
            scope_selection: 'project_default',
            scope: {
              id: 1,
              name: 'Production domains',
              status: 'active',
              valid_from: '2026-07-01T00:00:00Z',
              valid_until: '2099-08-01T00:00:00Z',
              target_types: ['domain']
            },
            ready: true,
            // Older API processes serialized nil Go slices as null. The UI must
            // keep rendering while a rolling deployment still serves that shape.
            issues: null,
            steps: [{ step: { ...blueprint.steps[0], depends_on: null }, ready: true, issues: null }],
            notice: '预检本身不会创建任务模板、调用外部引擎或启动扫描；通过后可由操作人显式生成手动任务模板。'
          }
        });
      }),
      http.post('/api/v1/projects/1/discovery/blueprints/domain_asset_inventory/templates', async ({ request }) => {
        const body = await request.json() as { scope_id?: unknown };
        materializedScopeId = body.scope_id;
        return HttpResponse.json({
          request_id: 'req-materialize',
          data: {
            execution_mode: 'templates_only',
            blueprint_key: blueprint.key,
            version: blueprint.version,
            scope_id: 1,
            created_count: 1,
            existing_count: 0,
            templates: [],
            notice: '已生成手动任务模板；未创建运行记录，也未调用外部引擎。'
          }
        });
      }),
      http.post('/api/v1/projects/1/discovery/templates/:template_id/runs', () => {
        unexpectedDispatch = true;
        return HttpResponse.json({}, { status: 500 });
      })
    );

    render(
      <AntApp>
        <BlueprintCatalog
          projectId={1}
          scopes={[scope]}
          canCreateTemplates
          onTemplatesCreated={onTemplatesCreated}
        />
      </AntApp>
    );

    expect(await screen.findByText('域名资产盘点')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '预检 域名资产盘点' })).toBeEnabled();
    await userEvent.click(screen.getByRole('button', { name: '预检 域名资产盘点' }));

    expect(await screen.findByText('当前前置条件已满足')).toBeInTheDocument();
    expect(screen.getByText('自动 · 项目默认')).toBeInTheDocument();
    expect(screen.getByText('这是配置检查，不是实时连接检测。生成配置后仍需确认运行；启动时后端会重新校验授权。')).toBeInTheDocument();
    expect(previewScopeId).toBeUndefined();
    expect(unexpectedDispatch).toBe(false);

    await userEvent.click(screen.getByRole('button', { name: '创建任务模板' }));
    await waitFor(() => expect(onTemplatesCreated).toHaveBeenCalledTimes(1));
    expect(materializedScopeId).toBe(1);
    expect(unexpectedDispatch).toBe(false);
  });

  it('recognizes a subdomain-only URL rule and shows concrete target resolution', async () => {
    const webBlueprint={...blueprint,key:'web_exposure_baseline',name:'Web 暴露面基线',required_target_types:['url'],steps:[{...blueprint.steps[0],key:'web_probe',task_type:'web_probe',required_target_types:['url']}]};
    const webScope: Scope={...scope,targets:[{target_type:'url',value:'http://example.com',match_mode:'include',coverage_mode:'exact',url_rule:{protocol:'http',include_root:false,include_subdomains:true,ports:[]}}]};
    server.use(
      http.get('/api/v1/projects/1/discovery/blueprints',()=>HttpResponse.json({data:{items:[webBlueprint],total:1}})),
      http.post('/api/v1/projects/1/discovery/blueprints/web_exposure_baseline/preview',()=>HttpResponse.json({data:{
        execution_mode:'preview_only',blueprint:webBlueprint,project_status:'active',scope_selection:'only_compatible',
        scope:{...webScope,target_types:['url']},ready:true,issues:[],steps:[{step:webBlueprint.steps[0],ready:true,issues:[],target_count:1,target_examples:['http://api.example.com:80']}]
      }}))
    );
    render(<AntApp><BlueprintCatalog projectId={1} scopes={[webScope]} canCreateTemplates /></AntApp>);
    const preview=await screen.findByRole('button',{name:'预检 Web 暴露面基线'});
    expect(preview).toHaveTextContent('使用此方案');
    await userEvent.click(preview);
    expect(await screen.findByText('已解析 1 个具体网址')).toBeInTheDocument();
    expect(screen.getByText('http://api.example.com:80')).toBeInTheDocument();
    expect(screen.getByRole('button',{name:'准备全部批次'})).toBeEnabled();
  });

  it('shows a retryable permission-safe load state', async () => {
    server.use(
      http.get('/api/v1/projects/2/discovery/blueprints', () => HttpResponse.json({
        request_id: 'req-forbidden',
        error: { code: 'FORBIDDEN', message: 'forbidden' }
      }, { status: 403 }))
    );

    render(
      <AntApp>
        <BlueprintCatalog projectId={2} scopes={[]} canCreateTemplates={false} />
      </AntApp>
    );

    await waitFor(() => expect(screen.getByText('无权限访问')).toBeInTheDocument());
  });
  it('explains missing authorized targets and offers a repair action instead of a generic load failure', async () => {
    const onManageScopes = vi.fn();
    const activeBlueprint = { ...blueprint, key: 'ip_baseline', name: 'IP 暴露面基线', required_target_types: ['ip'] };
    server.use(
      http.get('/api/v1/projects/1/discovery/blueprints', () => HttpResponse.json({ data: { items: [activeBlueprint], total: 1 } })),
      http.post('/api/v1/projects/1/discovery/blueprints/ip_baseline/preview', () => HttpResponse.json({ error: { code: 'INVALID_SCOPE', message: '没有可用于该场景的有效授权范围' } }, { status: 422 }))
    );
    render(<AntApp><BlueprintCatalog projectId={1} scopes={[scope]} canCreateTemplates onManageScopes={onManageScopes} /></AntApp>);
    await userEvent.click(await screen.findByRole('button', { name: '预检 IP 暴露面基线' }));
    expect(await screen.findByText('尚不满足此方案的条件')).toBeInTheDocument();
    expect(screen.getByText('Production domains：还缺少已授权的IP')).toBeInTheDocument();
    expect(screen.queryByText('加载失败')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '创建任务模板' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: '管理授权范围' }));
    expect(onManageScopes).toHaveBeenCalledOnce();
  });

  it('hands a materialized step to run confirmation without dispatching it automatically', async () => {
    const onRunTemplate = vi.fn();
    const template = { id: 19, project_id: 1, name: '域名盘点步骤', task_type: 'passive_intel', scope_id: 1, enabled: true, config: { targets: [], options: {} } };
    server.use(
      http.get('/api/v1/projects/1/discovery/blueprints', () => HttpResponse.json({ data: { items: [blueprint], total: 1 } })),
      http.post('/api/v1/projects/1/discovery/blueprints/domain_asset_inventory/preview', () => HttpResponse.json({ data: {
        execution_mode: 'preview_only', blueprint, project_status: 'active', scope_selection: 'only_compatible',
        scope: { ...scope, target_types: ['domain'] }, ready: true, issues: [], steps: [{ step: blueprint.steps[0], ready: true, issues: [] }]
      } })),
      http.post('/api/v1/projects/1/discovery/blueprints/domain_asset_inventory/templates', () => HttpResponse.json({ data: {
        execution_mode: 'templates_only', blueprint_key: blueprint.key, scope_id: 1, created_count: 1, existing_count: 0,
        templates: [{ step_key: 'passive_intel', created: true, template }]
      } }))
    );
    render(<AntApp><BlueprintCatalog projectId={1} scopes={[scope]} canCreateTemplates onRunTemplate={onRunTemplate} /></AntApp>);
    await userEvent.click(await screen.findByRole('button', { name: '预检 域名资产盘点' }));
    await userEvent.click(await screen.findByRole('button', { name: '创建任务模板' }));
    expect(await screen.findByText('执行配置已准备好')).toBeInTheDocument();
    expect(onRunTemplate).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: '确认并运行' }));
    expect(onRunTemplate).toHaveBeenCalledWith(template);
  });

  it('opens a full Web preview from a domain scope and prepares every batch without dispatching', async () => {
    const webBlueprint={...blueprint,key:'web_exposure_baseline',name:'Web 暴露面基线',required_target_types:['url'],steps:[{...blueprint.steps[0],key:'web_probe',task_type:'web_probe',required_target_types:['url']}]};
    const created=vi.fn();const dispatched=vi.fn();let chosenScope=0;
    const templates=[1,2,3].map((id)=>({step_key:'web_probe',batch_index:id,batch_count:3,target_count:id===3?2:1000,created:true,template:{id,project_id:1,scope_id:1,name:`Web batch ${id}`,task_type:'web_probe',enabled:true,config:{targets:[],options:{target_selection:'project_assets_snapshot_v2'}}}}));
    server.use(
      http.get('/api/v1/projects/1/discovery/blueprints',()=>HttpResponse.json({data:{items:[webBlueprint],total:1}})),
      http.post('/api/v1/projects/1/discovery/blueprints/web_exposure_baseline/preview',async({request})=>{chosenScope=(await request.json() as {scope_id:number}).scope_id;return HttpResponse.json({data:{execution_mode:'preview_only',blueprint:webBlueprint,project_status:'active',scope_selection:'explicit',scope:{...scope,target_types:['domain']},ready:true,issues:[],steps:[{step:webBlueprint.steps[0],ready:true,issues:[],target_count:2002,batch_count:3,target_examples:['https://example.com:443']}]}})}),
      http.post('/api/v1/projects/1/discovery/blueprints/web_exposure_baseline/templates',()=>HttpResponse.json({data:{execution_mode:'templates_only',blueprint_key:webBlueprint.key,scope_id:1,created_count:3,existing_count:0,target_count:2002,templates}})),
      http.post('/api/v1/projects/1/discovery/templates/:id/runs',()=>{dispatched();return HttpResponse.json({data:{}})})
    );
    render(<AntApp><BlueprintCatalog projectId={1} scopes={[scope]} canCreateTemplates requestedPreview={{key:webBlueprint.key,scopeId:1,nonce:1}} onTemplatesCreated={created}/></AntApp>);
    expect(await screen.findByText('已解析 2002 个具体网址')).toBeInTheDocument();
    expect(screen.getByText(/自动准备 3 个执行批次/)).toBeInTheDocument();expect(chosenScope).toBe(1);
    expect(screen.queryByText(/缺少已授权的网址/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button',{name:'准备全部批次'}));
    await waitFor(()=>expect(created).toHaveBeenCalled());expect(created.mock.calls[0][0].templates).toHaveLength(3);expect(dispatched).not.toHaveBeenCalled();
  });

});
