import {
  Alert,
  App as AntApp,
  Button,
  Modal,
  Select,
  Space,
  Tag,
  Typography
} from 'antd';
import { CheckCircle2, CircleAlert, SearchCheck } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import {
  createBlueprintTemplates,
  listDiscoveryBlueprints,
  previewDiscoveryBlueprint,
  type BlueprintTemplateMaterialization,
  type BlueprintRiskLevel,
  type DiscoveryBlueprint,
  type DiscoveryBlueprintPreview,
  type TaskTemplate,
  type Scope,
  type ScopeTarget
} from '../../api/discovery';
import { errorMessage } from '../../api/errorMessage';
import { ApiError } from '../../api/http';
import { PageSection } from '../../components/PageSection';
import { StateView } from '../../components/StateView';

type BlueprintCatalogProps = {
  projectId: number;
  requestedPreview?: { key: string; scopeId?: number; nonce: number };
  scopes: Scope[];
  canCreateTemplates: boolean;
  onManageScopes?: () => void;
  onRunTemplate?: (template: TaskTemplate) => void;
  onTemplatesCreated?: (result: BlueprintTemplateMaterialization) => void;
  onViewTemplates?: () => void;
};

type LoadError = {
  message: string;
  status?: number;
} | null;

const riskMeta: Record<BlueprintRiskLevel, { label: string; color: string }> = {
  passive: { label: '被动', color: 'blue' },
  active: { label: '主动', color: 'orange' },
  mixed: { label: '混合', color: 'purple' }
};

const targetTypeLabel: Record<ScopeTarget['target_type'], string> = {
  domain: '域名',
  ip: 'IP',
  cidr: 'CIDR',
  url: '网址',
  company: '企业主体'
};

const taskTypeLabel: Record<string, string> = {
  passive_intel: '被动情报',
  dns: 'DNS 解析',
  org_intel: '企业情报',
  port_probe: '端口发现',
  web_probe: 'Web 探测',
  fingerprint: '指纹识别'
};

function parseLoadError(error: unknown): LoadError {
  return {
    message: errorMessage(error),
    status: error instanceof ApiError ? error.status : undefined
  };
}

function scopeTargetTypes(scope: Scope) {
  return Array.from(new Set(
    scope.targets
      .filter((target) => target.match_mode === 'include')
      .map((target) => target.target_type)
  ));
}

function scopeSupports(scope: Scope, type: ScopeTarget['target_type']) {
  const types = scopeTargetTypes(scope);
  return types.includes(type) || (type === 'url' && types.includes('domain'));
}

function scopeOptionLabel(scope: Scope) {
  const types = scopeTargetTypes(scope).map((type) => targetTypeLabel[type]).join(' / ');
  const status = scope.status === 'active' ? '' : ' · 未启用';
  const defaultLabel = scope.is_default ? ' · 项目默认' : '';
  return `${scope.name}${defaultLabel}${types ? ` · ${types}` : ''}${status}`;
}

export function BlueprintCatalog({ projectId, requestedPreview, scopes, canCreateTemplates, onTemplatesCreated, onManageScopes, onRunTemplate, onViewTemplates }: BlueprintCatalogProps) {
  const { message } = AntApp.useApp();
  const [blueprints, setBlueprints] = useState<DiscoveryBlueprint[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<LoadError>(null);
  const [selectedScopeId, setSelectedScopeId] = useState<number>();
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [preview, setPreview] = useState<DiscoveryBlueprintPreview | null>(null);
  const [selectedBlueprint, setSelectedBlueprint] = useState<DiscoveryBlueprint | null>(null);
  const [materialized, setMaterialized] = useState<BlueprintTemplateMaterialization | null>(null);
  const [previewErrorStatus, setPreviewErrorStatus] = useState<number>();
  const [creatingTemplates, setCreatingTemplates] = useState(false);
  const creatingTemplatesRef = useRef(false);
  const [materializeError, setMaterializeError] = useState('');
  const listRequestRef = useRef<globalThis.AbortController | null>(null);
  const previewRequestSequence = useRef(0);
  const handledPreview = useRef<number>();

  const loadBlueprints = useCallback(async () => {
    listRequestRef.current?.abort();
    const controller = new globalThis.AbortController();
    listRequestRef.current = controller;
    setLoading(true);
    try {
      const result = await listDiscoveryBlueprints(projectId, { pageSize: 100, signal: controller.signal });
      if (controller.signal.aborted) return;
      setBlueprints(result.items);
      setLoadError(null);
    } catch (error) {
      if (controller.signal.aborted) return;
      setLoadError(parseLoadError(error));
    } finally {
      if (listRequestRef.current === controller) setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    previewRequestSequence.current += 1;
    setBlueprints([]);
    handledPreview.current = undefined;
    setSelectedScopeId(undefined);
    setPreview(null);
    setMaterialized(null);
    setSelectedBlueprint(null);
    setPreviewOpen(false);
    setCreatingTemplates(false);
    creatingTemplatesRef.current = false;
    setMaterializeError('');
    void loadBlueprints();
    return () => { listRequestRef.current?.abort(); previewRequestSequence.current += 1; };
  }, [loadBlueprints]);

  useEffect(() => {
    if (selectedScopeId && !scopes.some((scope) => scope.id === selectedScopeId)) {
      setSelectedScopeId(undefined);
    }
  }, [scopes, selectedScopeId]);

  const scopeOptions = useMemo(
    () => [
      { value: 0, label: '自动匹配授权范围' },
      ...scopes.map((scope) => ({ value: scope.id, label: scopeOptionLabel(scope) }))
    ],
    [scopes]
  );

  const openPreview = useCallback(async (blueprint: DiscoveryBlueprint, scopeOverride?: number) => {
    const sequence = previewRequestSequence.current + 1;
    previewRequestSequence.current = sequence;
    setPreview(null);
    setSelectedBlueprint(blueprint);
    setMaterialized(null);
    setPreviewErrorStatus(undefined);
    setPreviewError(null);
    setMaterializeError('');
    setPreviewOpen(true);
    setPreviewLoading(true);
    try {
      const result = await previewDiscoveryBlueprint(projectId, blueprint.key, scopeOverride ?? selectedScopeId);
      if (previewRequestSequence.current !== sequence) return;
      setPreview(result);
    } catch (error) {
      if (previewRequestSequence.current !== sequence) return;
      setPreviewError(errorMessage(error));
      setPreviewErrorStatus(error instanceof ApiError ? error.status : undefined);
    } finally {
      if (previewRequestSequence.current === sequence) setPreviewLoading(false);
    }
  }, [projectId, selectedScopeId]);

  useEffect(() => {
    if (!requestedPreview || handledPreview.current === requestedPreview.nonce) return;
    const blueprint = blueprints.find(item => item.key === requestedPreview.key);
    if (!blueprint) return;
    handledPreview.current = requestedPreview.nonce;
    setSelectedScopeId(requestedPreview.scopeId);
    void openPreview(blueprint, requestedPreview.scopeId ?? 0);
  }, [requestedPreview, blueprints, openPreview]);

  async function materializeTemplates() {
    if (!preview?.ready || creatingTemplatesRef.current) return;
    creatingTemplatesRef.current = true;
    setMaterializeError('');
    setCreatingTemplates(true);
    const sequence = previewRequestSequence.current;
    try {
      const result = await createBlueprintTemplates(projectId, preview.blueprint.key, preview.scope.id);
      if (previewRequestSequence.current !== sequence) return;
      if (result.created_count > 0) {
        message.success(`已创建 ${result.created_count} 个任务模板`);
      } else {
        message.info(`该场景的 ${result.existing_count} 个任务模板已存在`);
      }
      setMaterialized(result);
      if (onTemplatesCreated) setPreviewOpen(false);
      onTemplatesCreated?.(result);
    } catch (error) {
      if (previewRequestSequence.current === sequence) {
        setMaterializeError(errorMessage(error));
        message.error(errorMessage(error));
      }
    } finally {
      if (previewRequestSequence.current === sequence) {
        creatingTemplatesRef.current = false;
        setCreatingTemplates(false);
      }
    }
  }

  function closePreview() {
    if (creatingTemplatesRef.current) return;
    previewRequestSequence.current += 1;
    setPreviewOpen(false);
    setPreviewLoading(false);
  }

  return (
    <Space direction="vertical" size={18} className="full-width">
      <Typography.Paragraph type="secondary" className="discovery-intro">
        按发现目的选择方案。Web 识别会从项目已发现的域名和网站准备完整目标，沿用授权规则并自动分批，确认一次即可运行全部批次。
      </Typography.Paragraph>

      <div className="page-heading discovery-section-heading">
        <div>
          <Typography.Title level={4} style={{ margin: 0 }}>ASM 场景方案</Typography.Title>
          <Typography.Text type="secondary">
            已有唯一兼容范围时自动带入，不必重复选择。
          </Typography.Text>
        </div>
        <Select
          aria-label="预检授权范围"
          showSearch
          optionFilterProp="label"
          placeholder={scopes.length ? '自动匹配授权范围' : '请先创建授权范围'}
          value={selectedScopeId ?? 0}
          options={scopeOptions}
          onChange={(value) => setSelectedScopeId(value || undefined)}
          style={{ width: 360, maxWidth: '100%' }}
          disabled={!scopes.length}
        />
      </div>

      <StateView
        loading={loading}
        error={loadError?.message}
        permissionDenied={loadError?.status === 403}
        onRetry={loadBlueprints}
        empty={!blueprints.length}
        emptyText="暂无可用场景方案"
      >
        <div className="blueprint-list">
          {blueprints.map((blueprint) => {
            const risk = riskMeta[blueprint.risk_level];
            const candidates = scopes.filter(scope => (!selectedScopeId || scope.id === selectedScopeId) && scope.status === 'active' && Date.parse(scope.valid_from) <= Date.now() && Date.parse(scope.valid_until) >= Date.now());
            const compatible = candidates.some(scope => blueprint.required_target_types.every(type => scopeSupports(scope, type)));
            return <PageSection key={blueprint.key}
              title={<Space wrap><span>{blueprint.name}</span><Tag color={risk.color}>{risk.label}</Tag></Space>}
              extra={<Button icon={<SearchCheck size={15} />} onClick={() => void openPreview(blueprint)} aria-label={`预检 ${blueprint.name}`}>{compatible ? '使用此方案' : '查看所需条件'}</Button>}
            >
              <Typography.Paragraph type="secondary">{blueprint.description}</Typography.Paragraph>
              <div className="blueprint-meta">{compatible ? '已有兼容授权范围' : '需要补齐授权条件'} · 需要的目标：{blueprint.required_target_types.map((type) => targetTypeLabel[type]).join('、')}</div>
              <details className="inline-disclosure">
                <summary>查看 {blueprint.steps.length} 个步骤</summary>
                <ol>{blueprint.steps.map((step) => <li key={step.key}>{step.name}</li>)}</ol>
              </details>
            </PageSection>;
          })}
        </div>
      </StateView>

      <Modal
        className="discovery-task-modal"
        centered
        title={selectedBlueprint?.name ?? '场景预检'}
        open={previewOpen}
        width={760}
        footer={(
          <Space>
            <Button disabled={creatingTemplates} onClick={closePreview}>关闭</Button>
            {canCreateTemplates && !materialized ? (
              <Button
                type="primary"
                loading={creatingTemplates}
                disabled={creatingTemplates || !preview?.ready || previewLoading || Boolean(previewError)}
                onClick={() => void materializeTemplates()}
              >
                {creatingTemplates ? '正在创建…' : materializeError ? '重试创建任务模板' : preview?.blueprint.key === 'web_exposure_baseline' ? '准备全部批次' : '创建任务模板'}
              </Button>
            ) : null}
          </Space>
        )}
        destroyOnHidden
        onCancel={closePreview}
      >
        {materializeError && <Alert type="error" showIcon message="未能确认模板创建结果" description={materializeError + '。请先查看任务模板确认结果，再决定是否重试。'}
          action={onViewTemplates && <Button onClick={() => { closePreview(); onViewTemplates(); }}>查看任务模板</Button>} />}
        {previewError && <Alert showIcon type={previewErrorStatus === 403 ? 'error' : 'warning'}
          message={previewErrorStatus === 403 ? '没有权限检查此方案' : [400, 409, 422].includes(previewErrorStatus ?? 0) ? '尚不满足此方案的条件' : '暂时无法检查方案'}
          description={<Space direction="vertical" className="full-width">
            <span>{previewError}</span>
            <span>此方案需要：{selectedBlueprint?.required_target_types.map(type => targetTypeLabel[type]).join('、')}。</span>
            {scopes.filter(scope => !selectedScopeId || scope.id === selectedScopeId).map(scope => {
              const missing = selectedBlueprint?.required_target_types.filter(type => !scopeSupports(scope, type)) ?? [];
              return <span key={scope.id}>{scope.name}：{missing.length ? `还缺少已授权的${missing.map(type => targetTypeLabel[type]).join('、')}` : '请确认启用状态、有效期及引擎配置'}</span>;
            })}
            <Space wrap>{onManageScopes && <Button onClick={() => { closePreview(); onManageScopes(); }}>管理授权范围</Button>}
              {selectedBlueprint && <Button onClick={() => void openPreview(selectedBlueprint)}>重新检查</Button>}</Space>
          </Space>} />}
        {materialized && <div className="discovery-generated-steps">
          <Alert type="success" showIcon message="执行配置已准备好" description="尚未启动任务。选择下面的步骤查看目标并确认运行。" />
          {materialized.templates.map(item => <div className="discovery-step-row" key={item.template.id}>
            <div><Typography.Text strong>{item.template.name}</Typography.Text><br /><Typography.Text type="secondary">{taskTypeLabel[item.template.task_type] ?? item.template.task_type} · {item.created ? '新建配置' : '复用已有配置'}</Typography.Text></div>
            {onRunTemplate && <Button onClick={() => { closePreview(); onRunTemplate(item.template); }}>确认并运行</Button>}
          </div>)}
          {!materialized.templates.length && <Typography.Paragraph>请前往任务模板查看生成的配置。</Typography.Paragraph>}
        </div>}
        <StateView loading={previewLoading}>
          {preview && !materialized ? (
            <Space direction="vertical" size={16} className="full-width">
              <Alert
                type={preview.ready ? 'success' : 'warning'}
                showIcon
                icon={preview.ready ? <CheckCircle2 size={18} /> : <CircleAlert size={18} />}
                message={preview.ready ? '当前前置条件已满足' : '存在阻塞条件'}
                description="这是配置检查，不是实时连接检测。生成配置后仍需确认运行；启动时后端会重新校验授权。"
              />

              <div>
                <Typography.Text strong>授权范围：</Typography.Text>
                <Typography.Text>{preview.scope.name}</Typography.Text>
                <Space size={[4, 4]} wrap style={{ marginLeft: 8 }}>
                  {preview.scope_selection === 'project_default' && <Tag color="blue">自动 · 项目默认</Tag>}
                  {preview.scope_selection === 'only_compatible' && <Tag color="cyan">自动 · 唯一兼容</Tag>}
                  {(preview.scope.target_types ?? []).map((type) => <Tag key={type}>{targetTypeLabel[type]}</Tag>)}
                </Space>
              </div>

              {preview.blueprint.key === 'web_exposure_baseline' && (() => {
                const scope = scopes.find(value => value.id === preview.scope.id);
                const exactOnly = scope?.targets.some(target => target.match_mode === 'include' && target.target_type === 'domain' && target.coverage_mode !== 'subdomains') && !scope?.targets.some(target => target.match_mode === 'include' && ((target.target_type === 'domain' && target.coverage_mode === 'subdomains') || target.url_rule?.include_subdomains));
                return exactOnly ? <Alert type="info" showIcon message="当前域名授权仅覆盖域名本身" description="子域名不会自动获得授权。如需覆盖子域，请一次性调整父授权的覆盖方式；系统会重新检查目标，不必逐条添加 URL。" action={onManageScopes && <Button onClick={() => { closePreview(); onManageScopes(); }}>调整覆盖范围</Button>} /> : null;
              })()}
              {(preview.issues ?? []).length > 0 && (
                <Alert
                  type="error"
                  showIcon
                  message="需要处理"
                  description={(
                    <ul style={{ margin: '8px 0 0', paddingLeft: 20 }}>
                      {(preview.issues ?? []).map((issue, index) => (
                        <li key={`${issue.code}-${issue.step_key ?? 'global'}-${index}`}>{issue.message}
                          {issue.code === 'URL_TARGETS_EMPTY' && <Button type="link" href={'/projects/' + projectId + '/assets'}>查看或导入项目资产</Button>}
                        </li>
                      ))}
                      {onManageScopes && <li><Button type="link" onClick={() => { closePreview(); onManageScopes(); }}>管理授权范围</Button></li>}
                    </ul>
                  )}
                />
              )}

              <div>
                <Typography.Title level={5}>步骤预览</Typography.Title>
                <Space direction="vertical" size={10} className="full-width">
                  {(preview.steps ?? []).map((item, index) => (
                    <div
                      key={item.step.key}
                      style={{
                        borderTop: '1px solid var(--asm-border)',
                        padding: '12px 0'
                      }}
                    >
                      <Space direction="vertical" size={6} className="full-width">
                        <Space wrap>
                          <Typography.Text strong>{index + 1}. {item.step.name}</Typography.Text>
                          <Tag color={item.step.engine_route === 'active' ? 'orange' : 'blue'}>
                            {item.step.engine_route === 'active' ? '主动引擎' : '被动引擎'}
                          </Tag>
                          <Tag color={item.ready ? 'success' : 'error'}>{item.ready ? '配置检查通过' : '需要处理'}</Tag>
                        </Space>
                        <Typography.Text type="secondary">{item.step.description}</Typography.Text>
                        {item.target_count !== undefined && <div className="blueprint-url-targets">
                          <Typography.Text strong>已解析 {item.target_count} 个具体网址</Typography.Text>
                          <Typography.Paragraph type="secondary">从项目已有域名和网址中匹配，沿用域名及 URL 授权；更严格的 URL 协议、端口规则与排除项仍然生效。</Typography.Paragraph>
                          {(item.target_examples ?? []).map(value => <div key={value}>{value}</div>)}
                          {item.batch_count !== undefined && <Typography.Paragraph type="secondary">自动准备 {item.batch_count} 个执行批次，覆盖以上全部目标。批次上限仅控制单次下发大小，不截断总量。</Typography.Paragraph>}
                        </div>}
                        <Typography.Text type="secondary">输入：所选范围中已授权的{item.step.required_target_types.map(type => targetTypeLabel[type]).join('、')}。{item.step.depends_on.length > 0 ? '当前使用模板自身的输入，不自动接收前序结果。' : ''}</Typography.Text>
                        <details className="inline-disclosure"><summary>查看默认执行限制</summary>
                          <Typography.Text type="secondary">{taskTypeLabel[item.step.task_type] ?? item.step.task_type} · 最长 {Math.round(item.step.defaults.timeout_seconds / 60)} 分钟 · 并发 {item.step.defaults.concurrency} · 重试上限 {item.step.defaults.retry_limit}。{item.step.engine_route === 'passive' ? `每秒操作上限 ${item.step.defaults.rate_limit}。` : '实际速率由主动引擎节点控制。'}</Typography.Text>
                        </details>
                        {(item.issues ?? []).map((issue) => (
                          <Typography.Text type="danger" key={`${item.step.key}-${issue.code}`}>
                            {issue.message}
                          </Typography.Text>
                        ))}
                      </Space>
                    </div>
                  ))}
                </Space>
              </div>
            </Space>
          ) : <span />}
        </StateView>
      </Modal>
    </Space>
  );
}
