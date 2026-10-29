import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Alert, Button, Form, Input, InputNumber, Modal, Popconfirm, Progress, Select, Space, Switch, Tabs, Tag, Tooltip, Typography, App as AntApp, Row, Col, Divider, DatePicker } from 'antd';
import { Play, Plus, Square, Shield, FileText, Database, Activity, Target, Trash2 } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import dayjs, { type Dayjs } from 'dayjs';
import { useSearchParams } from 'react-router-dom';
import { WebResults } from '../../components/WebResults';

import { listAssets, type Asset } from '../../api/assets';
import {
  cancelTaskRun,
  createScope,
  createTemplate,
  deleteTemplate,
  listExposures,
  listScopes,
  listTaskRuns,
  listTaskTemplates,
  toggleTemplate,
  triggerTaskRun,
  updateScope,
  updateScopeStatus,
  updateTemplate,
  type Exposure,
  type Scope,
  type ScopeInput,
  type ScopeTarget,
  type TaskRun,
  type TaskTemplate
} from '../../api/discovery';
import { errorMessage } from '../../api/errorMessage';
import { ApiError } from '../../api/http';
import {
  listProjectDomains,
  listProjectSubjects,
  type ProjectDomain,
  type ProjectSubject
} from '../../api/projects';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { ProjectActiveGate } from '../../components/ProjectStatusGate';
import { EnumChip, StatusChip } from '../../components/StatusChip';
import { runStatusMeta, scopeStatusMeta } from '../../utils/taxonomy';
import { PageHeader } from '../../components/PageHeader';
import { StateView } from '../../components/StateView';
import { Link } from 'react-router-dom';
import { getDiscoveryEngines, type EngineManagementOverview } from '../../api/engineManagement';
import { ExecutionSummary, discoveryPurpose } from './ExecutionSummary';
import { RunDetails } from './RunDetails';
import { WebBatchRunDialog } from './WebBatchRunDialog';
import { DerivedTargets } from './DerivedTargets';
import { URLRuleEditor } from './URLRuleEditor';
import { parseURLAuthorization, scopeTargetInputs, validateURLRule } from './urlAuthorization';
import { useProjectId } from '../../projects/ProjectContext';
import { BlueprintCatalog } from './BlueprintCatalog';

const exposureLabels: Record<string, string> = { port: '端口', service: '服务', web: '网站', certificate: '证书', cloud_config: '云配置' };

const DEFAULT_PAGE_SIZE = 20;
const IDLE_POLL_INTERVAL_MS = 30_000;
const ACTIVE_POLL_INTERVAL_MS = 4_000;
const ERROR_POLL_INTERVAL_MS = 8_000;
const PASSIVE_SOURCE_OPTIONS = [{ value: 'auto', label: '自动使用已配置来源（推荐）' }, { value: 'subfinder', label: 'Subfinder' }, { value: 'fofa', label: 'FOFA' }, { value: 'quake', label: 'Quake' }, { value: 'hunter', label: 'Hunter' }, { value: 'certificate_transparency', label: '证书透明度服务' }];
const MAX_SCOPE_WINDOW_MS = 365 * 24 * 60 * 60 * 1000;

type TemplateFormValues = {
  name: string;
  task_type: 'passive_intel' | 'dns' | 'port_probe' | 'web_probe' | 'fingerprint';
  scope_id: number;
  max_results: number;
  sources: string[];
  record_types: string[];
  ports: string;
  node_id?: string;
  schedule?: string;
  timeout_seconds: number;
  rate_limit: number;
  concurrency: number;
  retry_limit: number;
};

const taskTypeLabels: Record<string, string> = { passive_intel: '被动子域发现', dns: 'DNS 发现', port_probe: '端口探测', web_probe: 'Web 探测', fingerprint: '指纹识别', org_intel: '企业情报', dirscan: '目录扫描' };

type ScopeFormValues = Omit<ScopeInput, 'valid_from' | 'valid_until'> & {
  valid_from: string | Dayjs;
  valid_until: string | Dayjs;
};

function scopeDateValue(value?: string | Dayjs) {
  if (!value) return Number.NaN;
  return typeof value === 'string' ? Date.parse(value) : value.valueOf();
}

type ScopeSourceCandidate = {
  key: string;
  group: 'subject' | 'managed_domain' | 'asset';
  label: string;
  target: ScopeTarget;
};

function isActiveTemplateType(taskType?: TaskTemplate['task_type']): taskType is 'port_probe' | 'web_probe' | 'fingerprint' {
  return taskType === 'port_probe' || taskType === 'web_probe' || taskType === 'fingerprint';
}

function requiredTargetType(taskType?: TaskTemplate['task_type']) {
  if (taskType === 'port_probe') return 'ip';
  if (taskType === 'web_probe' || taskType === 'fingerprint') return 'url';
  if (taskType === 'org_intel') return 'company';
  if (taskType === 'passive_intel' || taskType === 'dns') return 'domain';
  return null;
}

function requiredTargetLabel(taskType?: TaskTemplate['task_type']) {
  const targetType = requiredTargetType(taskType);
  if (targetType === 'ip') return 'IP';
  if (taskType === 'web_probe') return '域名或 URL';
  if (targetType === 'url') return 'URL';
  if (targetType === 'company') return '企业主体';
  if (targetType === 'domain') return '域名';
  return '授权目标';
}

function scopeUnavailableReason(scope: Scope, now = Date.now(), taskType?: TaskTemplate['task_type'], concreteURLs = false) {
  if (scope.status !== 'active') return '未启用';
  const validFrom = Date.parse(scope.valid_from);
  const validUntil = Date.parse(scope.valid_until);
  if (!Number.isFinite(validFrom) || !Number.isFinite(validUntil)) return '有效期无效';
  if (now < validFrom) return '尚未生效';
  if (now > validUntil) return '已过期';
  const targetType = requiredTargetType(taskType);
  if (targetType === 'url' && taskType !== 'web_probe' && !concreteURLs && scope.targets.some(target => target.target_type === 'url') &&
      !scope.targets.some(target => target.match_mode === 'include' && target.target_type === 'url' && scopeTargetInputs(target).length)) {
    return '仅有子域通配规则，请从发现结果继承具体网址';
  }
  if (!scope.targets.some((target) => target.match_mode === 'include' && (!targetType || target.target_type === targetType || (taskType === 'web_probe' && target.target_type === 'domain')))) {
    return `缺少已授权的${requiredTargetLabel(taskType)}目标`;
  }
  return null;
}

function replaceItem<T extends { id: number }>(items: T[], updated: T) {
  return items.map((item) => item.id === updated.id ? { ...item, ...updated } : item);
}

function replaceScope(items: Scope[], updated: Scope) {
  return replaceItem(
    updated.is_default
      ? items.map((item) => item.id === updated.id ? item : { ...item, is_default: false })
      : items,
    updated
  );
}

function isEditableTaskType(taskType: TaskTemplate['task_type']): taskType is TemplateFormValues['task_type'] {
  return taskType === 'passive_intel' || taskType === 'dns' || isActiveTemplateType(taskType);
}

function validatePortSpec(value?: string) {
  const spec = value?.trim() ?? '';
  if (!spec || spec === 'all') return '请输入端口，例如 80,443,8000-8100';
  let total = 0;
  for (const item of spec.split(',')) {
    if (!item || item !== item.trim() || !/^\d+(?:-\d+)?$/.test(item)) return '端口格式不正确';
    const [startText, endText] = item.split('-');
    const start = Number(startText);
    const end = endText === undefined ? start : Number(endText);
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start || end > 65535) {
      return '端口必须在 1-65535，且范围起点不能大于终点';
    }
    total += end - start + 1;
    if (total > 1000) return '单个任务最多展开 1000 个端口';
  }
  return null;
}

function validateNodeId(value?: string) {
  const nodeId = value?.trim() ?? '';
  return !nodeId || (nodeId.length <= 128 && /^[A-Za-z0-9_.:-]+$/.test(nodeId))
    ? null
    : '节点 ID 仅支持字母、数字、点、下划线、冒号和短横线';
}

function isValidDomain(value: string) {
  const normalized = value.trim().toLowerCase().replace(/\.$/, '');
  if (!normalized || normalized.length > 253 || normalized.includes('..')) return false;
  return normalized.split('.').every((label) => (
    label.length > 0 &&
    label.length <= 63 &&
    /^[a-z0-9-]+$/.test(label) &&
    !label.startsWith('-') &&
    !label.endsWith('-')
  ));
}

function parseIPv4(value: string) {
  const parts = value.trim().split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
  const octets = parts.map(Number);
  if (octets.some((octet) => octet < 0 || octet > 255)) return null;
  return octets;
}

function isDangerousIPv4(octets: number[]) {
  const [a, b] = octets;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168);
}

function validateIPAddress(value: string) {
  const normalized = value.trim().toLowerCase();
  const ipv4 = parseIPv4(normalized);
  if (ipv4) return isDangerousIPv4(ipv4) ? '禁止使用内网、回环或保留地址' : null;
  if (!normalized.includes(':') || !/^[0-9a-f:]+$/.test(normalized)) return '请输入有效的 IP 地址';
  if (normalized === '::' || normalized === '::1' || normalized.startsWith('fe8') || normalized.startsWith('fe9') ||
      normalized.startsWith('fea') || normalized.startsWith('feb') || normalized.startsWith('fc') ||
      normalized.startsWith('fd') || normalized.startsWith('ff')) {
    return '禁止使用内网、回环、链路本地或组播地址';
  }
  return null;
}

function scopeTargetValidationError(targetType: ScopeTarget['target_type'] | undefined, value?: string) {
  const normalized = value?.trim() ?? '';
  if (!normalized) return '请输入授权目标';
  if (targetType === 'domain') return isValidDomain(normalized) ? null : '请输入有效的域名';
  if (targetType === 'company') {
    const hasControlCharacter = Array.from(value ?? '').some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint < 0x20 || codePoint === 0x7f;
    });
    if (hasControlCharacter || normalized.startsWith('-') || Array.from(normalized).length > 200) {
      return '请输入 1-200 个字符的合法主体名称';
    }
    return null;
  }
  if (targetType === 'ip') return validateIPAddress(normalized);
  if (targetType === 'cidr') {
    const slash = normalized.lastIndexOf('/');
    if (slash <= 0) return '请输入有效的 CIDR';
    const address = normalized.slice(0, slash);
    const prefix = Number(normalized.slice(slash + 1));
    const addressError = validateIPAddress(address);
    if (addressError) return addressError;
    const maxPrefix = address.includes(':') ? 128 : 32;
    return Number.isInteger(prefix) && prefix >= 0 && prefix <= maxPrefix ? null : '请输入有效的 CIDR 前缀';
  }
  if (targetType === 'url') {
    try {
      const parsed = new URL(normalized);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return 'URL 仅支持 HTTP 或 HTTPS';
      if (!parsed.hostname) return '请输入有效的 URL';
      const hostError = parseIPv4(parsed.hostname) || parsed.hostname.includes(':')
        ? validateIPAddress(parsed.hostname.replace(/^\[|\]$/g, ''))
        : (isValidDomain(parsed.hostname) ? null : '请输入有效的 URL 主机名');
      return hostError;
    } catch {
      return '请输入有效的 URL';
    }
  }
  return '请选择目标类型';
}

function scopeTargetPlaceholder(targetType: ScopeTarget['target_type'] | undefined) {
  if (targetType === 'company') return '示例科技有限公司';
  if (targetType === 'ip') return '8.8.8.8';
  if (targetType === 'cidr') return '8.8.8.0/24';
  if (targetType === 'url') return 'https://example.com 或 https://*.example.com';
  return 'example.com';
}

function assetScopeTarget(asset: Asset): ScopeTarget | null {
  const value = asset.value.trim();
  let target: ScopeTarget | null = null;
  if (asset.asset_type === 'domain' || asset.asset_type === 'subdomain') {
    target = { target_type: 'domain', match_mode: 'include', coverage_mode: 'exact', value };
  } else if (asset.asset_type === 'ip') {
    target = { target_type: 'ip', match_mode: 'include', coverage_mode: 'exact', value };
  } else if (asset.asset_type === 'web') {
    target = { target_type: 'url', match_mode: 'include', coverage_mode: 'exact', value };
  }
  return target && scopeTargetValidationError(target.target_type, target.value) === null ? target : null;
}

function buildScopeSourceCandidates(
  subjects: ProjectSubject[],
  domains: ProjectDomain[],
  assets: Asset[]
) {
  const candidates: ScopeSourceCandidate[] = [];
  const managedDomains = new Set(domains.map((domain) => domain.domain.trim().toLowerCase()));
  for (const subject of subjects) {
    if (subject.subject_type !== 'company') continue;
    const value = subject.subject_name.trim();
    if (scopeTargetValidationError('company', value) !== null) continue;
    candidates.push({
      key: `subject:${subject.id}`,
      group: 'subject',
      label: `${value}${subject.is_primary ? ' · 主主体' : ''}`,
      target: { target_type: 'company', match_mode: 'include', coverage_mode: 'exact', value }
    });
  }
  for (const domain of domains) {
    const value = domain.domain.trim().toLowerCase();
    if (scopeTargetValidationError('domain', value) !== null) continue;
    candidates.push({
      key: `managed-domain:${domain.id}`,
      group: 'managed_domain',
      label: `${value}${domain.is_primary ? ' · 主域名' : ''}`,
      target: { target_type: 'domain', match_mode: 'include', coverage_mode: 'subdomains', value }
    });
  }
  for (const asset of assets) {
    const target = assetScopeTarget(asset);
    if (!target) continue;
    if (target.target_type === 'domain' && managedDomains.has(target.value.toLowerCase())) continue;
    const displayName = asset.display_name.trim() || target.value;
    const typeLabel = target.target_type === 'domain' ? '域名资产'
      : target.target_type === 'ip' ? 'IP 资产'
        : 'Web 资产';
    candidates.push({
      key: `asset:${asset.id}`,
      group: 'asset',
      label: `${displayName} · ${typeLabel}`,
      target
    });
  }
  return candidates;
}

function scopeTargetIdentity(target: Pick<ScopeTarget, 'target_type' | 'match_mode' | 'value'>) {
  return `${target.target_type}|${target.match_mode}|${target.value.trim().toLowerCase()}`;
}

function updatePendingIds(current: Set<number>, id: number, pending: boolean) {
  const next = new Set(current);
  if (pending) next.add(id);
  else next.delete(id);
  return next;
}

function isFormValidationError(error: unknown) {
  return Boolean(error && typeof error === 'object' && 'errorFields' in error);
}

type PageError = { message: string; status?: number } | null;
function parseError(err: unknown): PageError {
  return {
    message: errorMessage(err),
    status: err instanceof ApiError ? err.status : undefined
  };
}

export function DiscoveryPage() {
  const [resultQuery,setResultQuery] = useSearchParams();
  const resultRunId = Number(resultQuery.get('run_id')) || 0;
  const { can } = usePermission();
  const projectId = useProjectId();
  const { message } = AntApp.useApp();

  const [scopes, setScopes] = useState<Scope[]>([]);
  const [scopeCatalog, setScopeCatalog] = useState<Scope[]>([]);
  const [scopesLoading, setScopesLoading] = useState(true);
  const [scopesError, setScopesError] = useState<PageError>(null);
  const [scopePageNumber, setScopePageNumber] = useState(1);
  const [scopePageSize, setScopePageSize] = useState(DEFAULT_PAGE_SIZE);
  const [scopesTotal, setScopesTotal] = useState(0);

  const [templates, setTemplates] = useState<TaskTemplate[]>([]);
  const [templatesLoading, setTemplatesLoading] = useState(true);
  const [templatesError, setTemplatesError] = useState<PageError>(null);
  const [templatePageNumber, setTemplatePageNumber] = useState(1);
  const [templatePageSize, setTemplatePageSize] = useState(DEFAULT_PAGE_SIZE);
  const [templatesTotal, setTemplatesTotal] = useState(0);
  const templateItemsRef = useRef<TaskTemplate[]>([]);
  templateItemsRef.current = templates;
  const [templateCreationNotice, setTemplateCreationNotice] = useState('');
  const templateNoticeRef = useRef<HTMLDivElement>(null);

  const [runs, setRuns] = useState<TaskRun[]>([]);
  const [runsLoading, setRunsLoading] = useState(true);
  const [runsError, setRunsError] = useState<PageError>(null);
  const [pollTrigger, setPollTrigger] = useState(0);
  const [runPageNumber, setRunPageNumber] = useState(1);
  const [runPageSize, setRunPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [runsTotal, setRunsTotal] = useState(0);

  const [exposures, setExposures] = useState<Exposure[]>([]);
  const [exposuresLoading, setExposuresLoading] = useState(true);
  const [exposuresError, setExposuresError] = useState<PageError>(null);
  const [exposurePageNumber, setExposurePageNumber] = useState(1);
  const [exposurePageSize, setExposurePageSize] = useState(DEFAULT_PAGE_SIZE);
  const [exposuresTotal, setExposuresTotal] = useState(0);

  const [activeTab, setActiveTab] = useState('runs');
  useEffect(() => {
    if (activeTab === 'tasks' && templateCreationNotice) templateNoticeRef.current?.scrollIntoView?.({block:'nearest'});
  }, [activeTab, templateCreationNotice]);
  const [scopeNow, setScopeNow] = useState(() => Date.now());

  // Scope form
  const [scopeOpen, setScopeOpen] = useState(false);
  const [editScopeId, setEditScopeId] = useState<number | null>(null);
  const [scopeStatusPendingIds, setScopeStatusPendingIds] = useState<Set<number>>(() => new Set());
  const [scopeSubmitting, setScopeSubmitting] = useState(false);
  const scopeSubmittingRef = useRef(false);
  const [scopeForm] = Form.useForm<ScopeFormValues>();
  const watchScopeStatus = Form.useWatch('status', scopeForm);
  const [scopeSourceCandidates, setScopeSourceCandidates] = useState<ScopeSourceCandidate[]>([]);
  const [selectedScopeSourceKeys, setSelectedScopeSourceKeys] = useState<string[]>([]);
  const [scopeSourcesLoading, setScopeSourcesLoading] = useState(false);
  const [scopeSourcesError, setScopeSourcesError] = useState('');
  const [scopeSourcesTruncated, setScopeSourcesTruncated] = useState(false);
  const scopeSourceRequestSequenceRef = useRef(0);

  // Template form
  const [templateOpen, setTemplateOpen] = useState(false);
  const [editTemplateId, setEditTemplateId] = useState<number | null>(null);
  const [templateStatusPendingIds, setTemplateStatusPendingIds] = useState<Set<number>>(() => new Set());
  const [templateDeletePendingIds, setTemplateDeletePendingIds] = useState<Set<number>>(() => new Set());
  const [templateRunPendingId, setTemplateRunPendingId] = useState<number | null>(null);
  const [runCancelPendingIds, setRunCancelPendingIds] = useState<Set<number>>(() => new Set());
  const [templateSubmitting, setTemplateSubmitting] = useState(false);
  const templateSubmittingRef = useRef(false);
  const templateNameEditedRef = useRef(false);
  const dirtyURLInputs = useRef(new Set<number>());
  const [templateForm] = Form.useForm<TemplateFormValues>();
  const watchTaskType = Form.useWatch('task_type', templateForm);
  const activeTemplateSelected = isActiveTemplateType(watchTaskType);
  const watchScopeId = Form.useWatch('scope_id', templateForm);
  const [createAndRun, setCreateAndRun] = useState(false);
  const [templateReview, setTemplateReview] = useState(false);
  const [templateDraft, setTemplateDraft] = useState<{ values: TemplateFormValues; runImmediately: boolean } | null>(null);
  const [confirmRun, setConfirmRun] = useState<TaskTemplate | null>(null);
  const [runError, setRunError] = useState('');
  const [webPreviewRequest, setWebPreviewRequest] = useState<{key:string;scopeId?:number;nonce:number}>();
  const [webBatchTemplates, setWebBatchTemplates] = useState<TaskTemplate[] | null>(null);
  const [batchRunNotice, setBatchRunNotice] = useState('');
  const [derivedRunId, setDerivedRunId] = useState<number | null>(null);
  const [detailRunId, setDetailRunId] = useState<number | null>(null);
  const [engineOverview, setEngineOverview] = useState<EngineManagementOverview>();
  const [engineError, setEngineError] = useState('');
  const canManageEngines = can(Permission.AdminManage);
  const prepareFullWeb = useCallback((scopeId?: number) => {
    setDetailRunId(null); setDerivedRunId(null); setTemplateOpen(false);
    setActiveTab('blueprints');
    setWebPreviewRequest(current => ({key:'web_exposure_baseline',scopeId,nonce:(current?.nonce ?? 0)+1}));
  }, []);
  useEffect(() => { setWebPreviewRequest(undefined); setWebBatchTemplates(null); setBatchRunNotice(''); }, [projectId]);

  useEffect(() => {
    if ((!templateOpen && !confirmRun) || !canManageEngines) return;
    let cancelled = false;
    setEngineOverview(undefined);
    setEngineError('');
    getDiscoveryEngines().then(value => {
      if (!cancelled) setEngineOverview(value);
    }).catch(err => {
      if (!cancelled) setEngineError(errorMessage(err));
    });
    return () => { cancelled = true; };
  }, [templateOpen, confirmRun, canManageEngines, projectId]);

  function openNewTemplate(runImmediately = false) {
    templateNameEditedRef.current = false;
    setEditTemplateId(null);
    setCreateAndRun(runImmediately);
    setTemplateReview(false);
    templateForm.resetFields();
    templateForm.setFieldsValue({
      task_type: 'passive_intel', max_results: 1000, concurrency: 10, rate_limit: 200,
      timeout_seconds: 1800, retry_limit: 3, schedule: '', sources: ['auto'],
      record_types: ['A', 'AAAA', 'CNAME'], ports: '80,443', node_id: ''
    });
    setTemplateOpen(true);
  }

  function resumeTemplateDraft() {
    if (!templateDraft) return;
    templateNameEditedRef.current = true;
    setEditTemplateId(null);
    setCreateAndRun(templateDraft.runImmediately);
    setTemplateReview(false);
    templateForm.setFieldsValue(templateDraft.values);
    setTemplateDraft(null);
    setTemplateOpen(true);
  }

  async function reviewNewTask() {
    try {
      const onlyWebScope = !editTemplateId && templateForm.getFieldValue('task_type') === 'web_probe';
      const values = await templateForm.validateFields(onlyWebScope ? ['task_type', 'scope_id'] : undefined);
      if (!editTemplateId && values.task_type === 'web_probe') { prepareFullWeb(values.scope_id); return; }
      setTemplateReview(true);
    } catch {
      message.warning('请补齐标出的信息后继续');
    }
  }


  const currentProjectIdRef = useRef(projectId);
  currentProjectIdRef.current = projectId;
  const scopeRequestRef = useRef<globalThis.AbortController | null>(null);
  const scopeCatalogRequestRef = useRef<globalThis.AbortController | null>(null);
  const templateRequestRef = useRef<globalThis.AbortController | null>(null);
  const exposureRequestRef = useRef<globalThis.AbortController | null>(null);

  const loadScopeSourceCandidates = useCallback(async () => {
    const sequence = scopeSourceRequestSequenceRef.current + 1;
    scopeSourceRequestSequenceRef.current = sequence;
    setScopeSourcesLoading(true);
    setScopeSourcesError('');
    setScopeSourcesTruncated(false);

    const results = await Promise.allSettled([
      listProjectSubjects(projectId),
      listProjectDomains(projectId),
      listAssets({ projectId, category: 'domains', status: 'active', pageNumber: 1, pageSize: 50 }),
      listAssets({ projectId, category: 'ips', status: 'active', pageNumber: 1, pageSize: 50 }),
      listAssets({ projectId, category: 'web', status: 'active', pageNumber: 1, pageSize: 50 })
    ]);
    if (scopeSourceRequestSequenceRef.current !== sequence || currentProjectIdRef.current !== projectId) return;

    const [subjectResult, domainResult, ...assetResults] = results;
    const subjects = subjectResult.status === 'fulfilled' ? subjectResult.value.items : [];
    const domains = domainResult.status === 'fulfilled' ? domainResult.value.items : [];
    const assets = assetResults.flatMap((result) => result.status === 'fulfilled' ? result.value.items : []);
    const failedSources = [
      subjectResult.status === 'rejected' ? '项目主体' : '',
      domainResult.status === 'rejected' ? '受管域名' : '',
      assetResults.some((result) => result.status === 'rejected') ? '资产' : ''
    ].filter(Boolean);

    setScopeSourceCandidates(buildScopeSourceCandidates(subjects, domains, assets));
    setScopeSourcesError(failedSources.length ? `${failedSources.join('、')}候选加载失败，仍可手工添加目标。` : '');
    setScopeSourcesTruncated(assetResults.some((result) => (
      result.status === 'fulfilled' && result.value.total > result.value.items.length
    )));
    setScopeSourcesLoading(false);
  }, [projectId]);

  const scopeSourceOptions = useMemo(() => {
    const groups: Array<{ label: string; options: Array<{ label: string; value: string }> }> = [];
    const groupLabels: Record<ScopeSourceCandidate['group'], string> = {
      subject: '项目主体',
      managed_domain: '受管域名',
      asset: '已有资产'
    };
    for (const group of ['subject', 'managed_domain', 'asset'] as const) {
      const options = scopeSourceCandidates
        .filter((candidate) => candidate.group === group)
        .map((candidate) => ({ value: candidate.key, label: candidate.label }));
      if (options.length) groups.push({ label: groupLabels[group], options });
    }
    return groups;
  }, [scopeSourceCandidates]);

  const appendSelectedScopeSources = useCallback(() => {
    const selectedTargets = selectedScopeSourceKeys
      .map((key) => scopeSourceCandidates.find((candidate) => candidate.key === key)?.target)
      .filter((target): target is ScopeTarget => Boolean(target));
    if (!selectedTargets.length) return;

    const currentTargets = (scopeForm.getFieldValue('targets') ?? []) as ScopeTarget[];
    const onlyBlankDefaultTarget = currentTargets.length === 1 && !currentTargets[0]?.value?.trim();
    const nextTargets = onlyBlankDefaultTarget ? [] : currentTargets.map((target) => ({ ...target }));
    const seen = new Set(nextTargets.filter((target) => target.value?.trim()).map(scopeTargetIdentity));
    let added = 0;
    for (const target of selectedTargets) {
      const identity = scopeTargetIdentity(target);
      if (seen.has(identity)) continue;
      seen.add(identity);
      nextTargets.push({ ...target });
      added += 1;
    }
    scopeForm.setFieldValue('targets', nextTargets);
    setSelectedScopeSourceKeys([]);
    if (added) message.success(`已添加 ${added} 个授权目标，Scope 仍保持草稿状态。`);
    else message.info('所选目标已经存在。');
  }, [message, scopeForm, scopeSourceCandidates, selectedScopeSourceKeys]);

  const fetchScopes = useCallback(async (showLoading = false) => {
    scopeRequestRef.current?.abort();
    const controller = new window.AbortController();
    scopeRequestRef.current = controller;
    if (showLoading) setScopesLoading(true);
    try {
      const res = await listScopes(projectId, { pageNumber: scopePageNumber, pageSize: scopePageSize, signal: controller.signal });
      if (controller.signal.aborted || currentProjectIdRef.current !== projectId) return;
      setScopes(res.items);
      setScopesTotal(res.total);
      setScopesError(null);
    } catch (err) {
      if (controller.signal.aborted || currentProjectIdRef.current !== projectId) return;
      setScopesError(parseError(err));
    } finally {
      if (scopeRequestRef.current === controller) setScopesLoading(false);
    }
  }, [projectId, scopePageNumber, scopePageSize]);

  const fetchScopeCatalog = useCallback(async () => {
    scopeCatalogRequestRef.current?.abort();
    const controller = new window.AbortController();
    scopeCatalogRequestRef.current = controller;
    try {
      const allScopes: Scope[] = [];
      let pageNumber = 1;
      let total = 0;
      do {
        const page = await listScopes(projectId, { pageNumber, pageSize: 100, signal: controller.signal });
        allScopes.push(...page.items);
        total = page.total;
        pageNumber += 1;
      } while (allScopes.length < total);
      if (controller.signal.aborted || currentProjectIdRef.current !== projectId) return;
      setScopeCatalog(allScopes);
    } catch (err) {
      if (controller.signal.aborted || currentProjectIdRef.current !== projectId) return;
      setScopeCatalog([]);
      message.error(`授权 Scope 选项加载失败：${errorMessage(err)}`);
    }
  }, [message, projectId]);

  const fetchTemplates = useCallback(async (showLoading = false, page = templatePageNumber) => {
    templateRequestRef.current?.abort();
    const controller = new window.AbortController();
    templateRequestRef.current = controller;
    if (showLoading) setTemplatesLoading(true);
    try {
      const res = await listTaskTemplates(projectId, { pageNumber: page, pageSize: templatePageSize, signal: controller.signal });
      if (controller.signal.aborted || currentProjectIdRef.current !== projectId) return;
      setTemplates(res.items);
      setTemplatesTotal(res.total);
      setTemplatesError(null);
    } catch (err) {
      if (controller.signal.aborted || currentProjectIdRef.current !== projectId) return;
      setTemplatesError(parseError(err));
    } finally {
      if (templateRequestRef.current === controller) setTemplatesLoading(false);
    }
  }, [projectId, templatePageNumber, templatePageSize]);

  const fetchExposures = useCallback(async (showLoading = false) => {
    exposureRequestRef.current?.abort();
    const controller = new window.AbortController();
    exposureRequestRef.current = controller;
    if (showLoading) setExposuresLoading(true);
    try {
      const res = await listExposures(projectId, undefined, { pageNumber: exposurePageNumber, pageSize: exposurePageSize, signal: controller.signal });
      if (controller.signal.aborted || currentProjectIdRef.current !== projectId) return;
      setExposures(res.items);
      setExposuresTotal(res.total);
      setExposuresError(null);
    } catch (err) {
      if (controller.signal.aborted || currentProjectIdRef.current !== projectId) return;
      setExposuresError(parseError(err));
    } finally {
      if (exposureRequestRef.current === controller) setExposuresLoading(false);
    }
  }, [exposurePageNumber, exposurePageSize, projectId]);

  useEffect(() => {
    setScopePageNumber(1);
    setTemplateCreationNotice('');
    setTemplatePageNumber(1);
    setRunPageNumber(1);
    setExposurePageNumber(1);
    setScopeCatalog([]);
    setScopeOpen(false);
    setEditScopeId(null);
    setScopeSourceCandidates([]);
    setSelectedScopeSourceKeys([]);
    setScopeSourcesLoading(false);
    setScopeSourcesError('');
    setScopeSourcesTruncated(false);
    scopeSourceRequestSequenceRef.current += 1;
    setTemplateOpen(false);
    setEditTemplateId(null);
    setConfirmRun(null);
    setTemplateDraft(null);
    setDetailRunId(null);
    setDerivedRunId(null);
    setTemplateReview(false);
    setEngineOverview(undefined);
    setRunError('');
  }, [projectId]);

  useEffect(() => {
    if (!scopeOpen || editScopeId !== null) return;
    void loadScopeSourceCandidates();
    return () => {
      scopeSourceRequestSequenceRef.current += 1;
    };
  }, [editScopeId, loadScopeSourceCandidates, scopeOpen]);

  useEffect(() => {
    void fetchScopes(true);
  }, [fetchScopes]);

  useEffect(() => {
    void fetchScopeCatalog();
  }, [fetchScopeCatalog]);

  useEffect(() => {
    void fetchTemplates(true);
  }, [fetchTemplates]);

  useEffect(() => {
    void fetchExposures(true);
  }, [fetchExposures]);

  useEffect(() => () => {
    scopeRequestRef.current?.abort();
    scopeCatalogRequestRef.current?.abort();
    templateRequestRef.current?.abort();
    exposureRequestRef.current?.abort();
    scopeSourceRequestSequenceRef.current += 1;
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => setScopeNow(Date.now()), 60_000);
    return () => window.clearInterval(timer);
  }, []);

  // Polling runs
  useEffect(() => {
    let timer: number | undefined;
    let active = true;
    let inFlight = false;
    const controller = new window.AbortController();

    const scheduleNext = (delay: number) => {
      if (!active) return;
      if (timer) window.clearTimeout(timer);
      timer = window.setTimeout(() => void poll(), delay);
    };

    const poll = async () => {
      if (!active || inFlight) return;
      if (document.visibilityState === 'hidden') {
        scheduleNext(IDLE_POLL_INTERVAL_MS);
        return;
      }
      inFlight = true;
      try {
        const res = await listTaskRuns(projectId, { pageNumber: runPageNumber, pageSize: runPageSize, signal: controller.signal });
        if (!active || currentProjectIdRef.current !== projectId) return;
        setRuns(res.items);
        setRunsTotal(res.total);
        setRunsError(null);
        setRunsLoading(false);
        const hasActive = res.items.some(r => r.status === 'pending' || r.status === 'running');
        scheduleNext(hasActive ? ACTIVE_POLL_INTERVAL_MS : IDLE_POLL_INTERVAL_MS);
      } catch (err) {
        if (!active || controller.signal.aborted || currentProjectIdRef.current !== projectId) return;
        setRunsError(parseError(err));
        setRunsLoading(false);
        if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
          return;
        }
        scheduleNext(ERROR_POLL_INTERVAL_MS);
      } finally {
        inFlight = false;
      }
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        if (timer) window.clearTimeout(timer);
        timer = undefined;
        void poll();
      }
    };

    setRunsLoading(true);
    void poll();
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      active = false;
      controller.abort();
      if (timer) window.clearTimeout(timer);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [projectId, pollTrigger, runPageNumber, runPageSize]);


  const scopeColumns = useMemo<ProColumns<Scope>[]>(() => [
    {
      title: '授权范围',
      dataIndex: 'name',
      render: (_, row) => (
        <Space size={4}>
          <span>{row.name}</span>
          {row.is_default && <Tag color="blue">项目默认</Tag>}
        </Space>
      )
    },
    {
      title: '状态',
      dataIndex: 'status',
      render: (_, row) => {
        const unavailableReason = scopeUnavailableReason(row, scopeNow);
        return (
          <Space size={4}>
            <EnumChip map={scopeStatusMeta} value={row.status} />
            {row.status === 'active' && unavailableReason && <Tag color="warning">{unavailableReason}</Tag>}
          </Space>
        );
      }
    },
    { title: '授权人', dataIndex: 'authorized_by' },
    { title: '生效时间', dataIndex: 'valid_from', valueType: 'dateTime' },
    { title: '失效时间', dataIndex: 'valid_until', valueType: 'dateTime' },
    {
      title: '目标',
      search: false,
      render: (_, row) => (
        <Space wrap>
          {row.targets.map((target) => (
            <Tag key={target.id || `${target.match_mode}:${target.value}`} color={target.match_mode === 'exclude' ? 'red' : 'blue'}>
              {target.match_mode === 'exclude' ? '排除' : '包含'}：{target.value}
              {target.coverage_mode === 'subdomains' ? '（含子域名）' : ''}
              {target.url_rule && '（' + (target.url_rule.protocol === 'both' ? 'HTTP/HTTPS' : target.url_rule.protocol.toUpperCase()) + '；' + (target.url_rule.include_root ? '当前主机' : '') + (target.url_rule.include_subdomains ? '及子域名' : '') + '；端口 ' + (target.url_rule.ports.join(',') || '默认') + '；整个站点）'}
            </Tag>
          ))}
        </Space>
      )
    },
    {
      title: '操作',
      valueType: 'option',
      render: (_, row) => can(Permission.ScopeWrite) ? [
        <Button
          key="edit"
          aria-label={`编辑 ${row.name}`}
          size="small"
          type="link"
          onClick={() => {
            setEditScopeId(row.id);
            scopeForm.setFieldsValue({
              name: row.name,
              status: row.status,
              authorized_by: row.authorized_by,
              valid_from: dayjs(row.valid_from),
              valid_until: dayjs(row.valid_until),
              is_default: row.is_default,
              targets: row.targets.map(({ target_type, match_mode, coverage_mode, value, url_rule }) => ({
                url_rule,
                target_type,
                match_mode,
                coverage_mode: coverage_mode ?? 'exact',
                value
              }))
            });
            setScopeOpen(true);
          }}
        >
          编辑
        </Button>,
        <Popconfirm
          key="status"
          title={`确认${row.status === 'active' ? '停用' : '启用'} Scope？`}
          description={row.status === 'active' ? '停用后，使用该 Scope 的新任务将无法下发。' : '启用后，该授权范围可用于发现任务。'}
          okText="确定"
          cancelText="取消"
          onConfirm={async () => {
            if (scopeStatusPendingIds.has(row.id)) return;
            const operationProjectId = projectId;
            const nextStatus = row.status === 'active' ? 'inactive' : 'active';
            setScopeStatusPendingIds((current) => updatePendingIds(current, row.id, true));
            try {
              const updated = await updateScopeStatus(projectId, row.id, nextStatus);
              if (currentProjectIdRef.current !== operationProjectId) return;
              setScopes((current) => replaceScope(current, updated));
              setScopeCatalog((current) => replaceScope(current, updated));
              message.success(`Scope 已${nextStatus === 'active' ? '启用' : '停用'}`);
            } catch (err) {
              if (currentProjectIdRef.current === operationProjectId) message.error(errorMessage(err));
            } finally {
              setScopeStatusPendingIds((current) => updatePendingIds(current, row.id, false));
            }
          }}
        >
          <Button
            aria-label={`${row.status === 'active' ? '停用' : '启用'} ${row.name}`}
            size="small"
            type="link"
            danger={row.status === 'active'}
            loading={scopeStatusPendingIds.has(row.id)}
          >
            {row.status === 'active' ? '停用' : '启用'}
          </Button>
        </Popconfirm>
      ] : []
    }
  ], [can, message, projectId, scopeForm, scopeNow, scopeStatusPendingIds]);

  const availableScopes = useMemo(() => {
    const byId = new Map(scopeCatalog.map((scope) => [scope.id, scope]));
    scopes.forEach((scope) => byId.set(scope.id, scope));
    return Array.from(byId.values());
  }, [scopeCatalog, scopes]);

  const scopeOptions = useMemo(() => availableScopes.map((scope) => {
    const reason = scopeUnavailableReason(scope, scopeNow, watchTaskType);
    return {
      value: scope.id,
      label: reason ? `${scope.name}（${reason}）` : scope.name,
      disabled: Boolean(reason)
    };
  }), [availableScopes, scopeNow, watchTaskType]);

  useEffect(() => {
    if (!templateOpen || editTemplateId || templateReview) return;
    const compatible = availableScopes.filter(scope => !scopeUnavailableReason(scope, scopeNow, watchTaskType));
    const current = compatible.find(scope => scope.id === watchScopeId);
    const defaults = compatible.filter(scope => scope.is_default);
    const selected = current ?? (defaults.length === 1 ? defaults[0] : compatible.length === 1 ? compatible[0] : undefined);
    if (selected?.id !== watchScopeId) templateForm.setFieldValue('scope_id', selected?.id);
    if (!templateNameEditedRef.current) {
      templateForm.setFieldValue('name', `${discoveryPurpose[watchTaskType] ?? '发现任务'}${selected ? ` · ${selected.name}` : ''}`.slice(0, 64));
    }
  }, [availableScopes, editTemplateId, scopeNow, templateForm, templateOpen, templateReview, watchScopeId, watchTaskType]);

  const scopesById = useMemo(() => new Map(availableScopes.map((scope) => [scope.id, scope])), [availableScopes]);

  const templateColumns = useMemo<ProColumns<TaskTemplate>[]>(() => [
    { title: '模板', dataIndex: 'name', fixed: 'left', width: 180 },
    { title: '类型', dataIndex: 'task_type', render: (_, row) => (taskTypeLabels[row.task_type] ?? row.task_type) },
    {
      title: '授权范围',
      dataIndex: 'scope_id',
      render: (_, row) => {
        const scope = scopesById.get(row.scope_id);
        const reason = scope ? scopeUnavailableReason(scope, scopeNow, row.config?.inheritance ? undefined : row.task_type, row.config?.targets?.some(target => target.type === 'url')) : '不存在';
        return (
          <Space size={4}>
            <span>{scope?.name ?? `#${row.scope_id}`}</span>
            {reason && <Tag color="warning">{reason}</Tag>}
          </Space>
        );
      }
    },
    { title: '执行方式', dataIndex: 'schedule', render: (_, row) => row.schedule ? <Tooltip title={`原配置：${row.schedule}。定时执行尚未接入，目前需手动运行。`}>手动 · 有历史周期配置</Tooltip> : '手动运行' },
    { title: '状态', dataIndex: 'enabled', render: (_, row) => <StatusChip label={row.enabled ? '已启用' : '已停用'} tone={row.enabled ? 'success' : 'neutral'} /> },
    {
      title: '操作', fixed: 'right', width: 160,
      valueType: 'option',
      render: (_, row) => {
        const canRun = can(Permission.DiscoveryRun);
        const scope = scopesById.get(row.scope_id);
        const scopeReason = scope ? scopeUnavailableReason(scope, scopeNow, row.config?.inheritance ? undefined : row.task_type, row.config?.targets?.some(target => target.type === 'url')) : '关联 Scope 不存在';
        const triggerReason = !row.enabled ? '模板未启用' : scopeReason;
        const editable = isEditableTaskType(row.task_type) && !row.config?.inheritance;
        return [
          canRun && row.task_type === 'web_probe' && <Button key="full-web" type="link" size="small" disabled={templateRunPendingId !== null} onClick={() => prepareFullWeb(row.scope_id)}>按最新资产重新准备</Button>,
          canRun && (
            <Tooltip key="run" title={triggerReason || undefined}>
              <span>
                <ProjectActiveGate actionLabel={`触发任务 ${row.name}`}>
                  <Button
                    aria-label={`触发 ${row.name}`}
                    icon={<Play size={14} />}
                    size="small"
                    type="link"
                    disabled={Boolean(triggerReason) || templateRunPendingId !== null}
                    loading={templateRunPendingId === row.id}
                    onClick={() => { setRunError(''); setConfirmRun(row); }}
                  >
                    运行
                  </Button>
                </ProjectActiveGate>
              </span>
            </Tooltip>
          ),
          canRun && (
            <Tooltip key="edit" title={editable ? undefined : row.config?.inheritance ? '派生目标快照保持不变，请从来源任务重新生成接续配置' : `暂不支持编辑 ${row.task_type} 类型`}>
              <span>
                <Button
                  aria-label={`编辑 ${row.name}`}
                  size="small"
                  type="link"
                  disabled={!editable}
                  onClick={() => {
                    if (!isEditableTaskType(row.task_type)) return;
                    setEditTemplateId(row.id);
                    setCreateAndRun(false);
                    setTemplateReview(false);
                    templateForm.setFieldsValue({
                      name: row.name,
                      task_type: row.task_type,
                      scope_id: row.scope_id,
                      max_results: row.config?.options?.max_results ?? 1000,
                      sources: row.config?.options?.sources?.filter((source) => PASSIVE_SOURCE_OPTIONS.some(option => option.value === source)).length
                        ? row.config.options.sources.filter((source) => PASSIVE_SOURCE_OPTIONS.some(option => option.value === source))
                        : ['fofa'],
                      record_types: row.config?.options?.record_types || ['A', 'AAAA', 'CNAME'],
                      ports: row.config?.options?.ports ?? '80,443',
                      node_id: row.config?.options?.node_id ?? '',
                      schedule: row.schedule,
                      timeout_seconds: row.timeout_seconds,
                      rate_limit: row.rate_limit,
                      concurrency: row.concurrency,
                      retry_limit: row.retry_limit
                    });
                    setTemplateOpen(true);
                  }}
                >
                  编辑
                </Button>
              </span>
            </Tooltip>
          ),
          canRun && (
            <Popconfirm
              key="toggle"
              title={`确认${row.enabled ? '禁用' : '启用'}模板？`}
              okText="确定"
              cancelText="取消"
              onConfirm={async () => {
                if (templateStatusPendingIds.has(row.id)) return;
                const operationProjectId = projectId;
                const liveScope = scopesById.get(row.scope_id);
                const liveScopeReason = liveScope ? scopeUnavailableReason(liveScope, Date.now(), row.config?.inheritance ? undefined : row.task_type, row.config?.targets?.some(target => target.type === 'url')) : '关联 Scope 不存在';
                if (!row.enabled && liveScopeReason) {
                  message.error(`当前模板不可启用：${liveScopeReason}`);
                  return;
                }
                setTemplateStatusPendingIds((current) => updatePendingIds(current, row.id, true));
                try {
                  const updated = await toggleTemplate(projectId, row.id, !row.enabled);
                  if (currentProjectIdRef.current !== operationProjectId) return;
                  setTemplates((current) => replaceItem(current, updated));
                  message.success('已切换状态');
                } catch (err) {
                  if (currentProjectIdRef.current === operationProjectId) message.error(errorMessage(err));
                } finally {
                  setTemplateStatusPendingIds((current) => updatePendingIds(current, row.id, false));
                }
              }}
            >
              <Button
                aria-label={`${row.enabled ? '禁用' : '启用'} ${row.name}`}
                size="small"
                type="link"
                disabled={!row.enabled && Boolean(scopeReason)}
                loading={templateStatusPendingIds.has(row.id)}
                title={!row.enabled && scopeReason ? `无法启用：${scopeReason}` : undefined}
              >
                {row.enabled ? '禁用' : '启用'}
              </Button>
            </Popconfirm>
          ),
          canRun && (
            <Popconfirm
              key="delete"
              title="确认删除模板？"
              description="删除后无法在界面中恢复。"
              okText="确定"
              cancelText="取消"
              onConfirm={async () => {
                if (templateDeletePendingIds.has(row.id)) return;
                const operationProjectId = projectId;
                setTemplateDeletePendingIds((current) => updatePendingIds(current, row.id, true));
                try {
                  await deleteTemplate(projectId, row.id);
                  if (currentProjectIdRef.current !== operationProjectId) return;
                  setTemplates((current) => current.filter((item) => item.id !== row.id));
                  setTemplatesTotal((current) => Math.max(0, current - 1));
                  if (templates.length === 1 && templatePageNumber > 1) {
                    setTemplatePageNumber((current) => Math.max(1, current - 1));
                  } else if (templatesTotal > templates.length) {
                    void fetchTemplates(false);
                  }
                  message.success('已删除模板');
                } catch (err) {
                  if (currentProjectIdRef.current === operationProjectId) message.error(errorMessage(err));
                } finally {
                  setTemplateDeletePendingIds((current) => updatePendingIds(current, row.id, false));
                }
              }}
            >
              <Button
                aria-label={`删除 ${row.name}`}
                danger
                size="small"
                type="link"
                loading={templateDeletePendingIds.has(row.id)}
              >
                删除
              </Button>
            </Popconfirm>
          )
        ];
      }
    }
  ], [can, fetchTemplates, message, prepareFullWeb, projectId, scopeNow, scopesById, templateDeletePendingIds, templateForm, templatePageNumber, templateRunPendingId, templates.length, templatesTotal, templateStatusPendingIds]);

  const runColumns = useMemo<ProColumns<TaskRun>[]>(() => [
    { title: '任务', dataIndex: 'id', fixed: 'left', width: 175, render: (_, row) => <Button type="link" aria-label={`查看任务 ${row.id}`} onClick={() => setDetailRunId(row.id)}>#{row.id} {discoveryPurpose[row.task_type] ?? taskTypeLabels[row.task_type]}</Button> },
    { title: '状态', dataIndex: 'status', render: (_, row) => <EnumChip map={runStatusMeta} value={row.status} /> },
    { title: '进度', dataIndex: 'progress', width: 140, render: (_, row) => ['passive_intel','dns'].includes(row.task_type) && ['pending','running'].includes(row.status) ? <Typography.Text type="secondary">{row.status==='pending'?'等待执行':row.last_callback_at?'分批回传中':'等待引擎回传'}</Typography.Text> : <Progress percent={row.progress} size="small" status={row.status === 'success' ? 'success' : row.status === 'failed' ? 'exception' : 'normal'} strokeColor={row.status === 'partial_success' ? 'var(--asm-high)' : undefined} format={percent => `${percent}%`} /> },
    { title: '结果', dataIndex: 'result_count', render: (_, row) => ['web_probe','fingerprint'].includes(row.task_type) && can(Permission.AssetRead) ? <Link to={`?run_id=${row.id}`}>查看网站结果</Link> : row.result_count, tooltip: '网站任务按目标查看；其他任务的数字是记录数量，不等于新增资产数。' },
    { title: '最后回调', dataIndex: 'last_callback_at', valueType: 'dateTime' },
    { title: '执行说明', dataIndex: 'error_summary', ellipsis: true, render: (_, row) => row.error_summary || (row.status === 'partial_success' ? '部分完成 · 查看阶段详情' : '—') },
    {
      title: '操作', fixed: 'right', width: 110,
      valueType: 'option',
      render: (_, row) => {
        const detail = <Button key="detail" type="link" onClick={() => setDetailRunId(row.id)}>{['passive_intel','dns'].includes(row.task_type) ? '发现进度' : '详情'}</Button>;
        if (!can(Permission.DiscoveryRun) || !['pending', 'running'].includes(row.status)) return [detail];
        if (row.status === 'running' && isActiveTemplateType(row.task_type)) {
          return [detail,
            <Tooltip key="cancel-unavailable" title="主动引擎当前不支持取消已下发任务">
              <span>
                <Button
                  aria-label={`取消 run ${row.id}`}
                  danger
                  disabled
                  icon={<Square size={14} />}
                  size="small"
                  type="link"
                >
                  取消
                </Button>
              </span>
            </Tooltip>
          ];
        }
        return [detail,
          <Popconfirm
            key="cancel"
            title="确认取消该任务？"
            okText="确定"
            cancelText="取消"
            onConfirm={async () => {
              if (runCancelPendingIds.has(row.id)) return;
              const operationProjectId = projectId;
              setRunCancelPendingIds((current) => updatePendingIds(current, row.id, true));
              try {
                const updated = await cancelTaskRun(projectId, row.id);
                if (currentProjectIdRef.current !== operationProjectId) return;
                setRuns((current) => replaceItem(current, updated));
                message.success('任务已取消');
              } catch (err) {
                if (currentProjectIdRef.current === operationProjectId) message.error(errorMessage(err));
              } finally {
                setRunCancelPendingIds((current) => updatePendingIds(current, row.id, false));
              }
            }}
          >
            <Button
              aria-label={`取消 run ${row.id}`}
              danger
              icon={<Square size={14} />}
              size="small"
              type="link"
              loading={runCancelPendingIds.has(row.id)}
            >
              取消
            </Button>
          </Popconfirm>
        ];
      }
    }
  ], [can, message, projectId, runCancelPendingIds]);

  const exposureColumns = useMemo<ProColumns<Exposure>[]>(() => [
    { title: '暴露面', dataIndex: 'name' },
    { title: '类型', dataIndex: 'exposure_type', valueType: 'select', valueEnum: exposureLabels },
    { title: '端点', dataIndex: 'url', render: (_, row) => row.url || row.value || `${row.protocol}://${row.port}`, ellipsis: true },
    { title: '来源', dataIndex: 'source' },
    { title: '最近发现', dataIndex: 'last_seen', valueType: 'dateTime' }
  ], []);

  const exposureStats = useMemo(
    () => ['port', 'service', 'web', 'certificate', 'cloud_config'].map((type) => ({ type, count: exposures.filter((item) => item.exposure_type === type).length })),
    [exposures]
  );

  async function startConfirmedRun() {
    if (!confirmRun || templateRunPendingId !== null) return;
    const operationProjectId = projectId;
    const scope = scopesById.get(confirmRun.scope_id);
    const reason = scope ? scopeUnavailableReason(scope, Date.now(), confirmRun.config?.inheritance ? undefined : confirmRun.task_type, confirmRun.config?.targets?.some(target => target.type === 'url')) : '授权范围不存在';
    if (reason || !confirmRun.enabled) { setRunError(reason || '模板未启用'); return; }
    setTemplateRunPendingId(confirmRun.id);
    setRunError('');
    try {
      const created = await triggerTaskRun(projectId, confirmRun.id);
      if (currentProjectIdRef.current !== operationProjectId) return;
      setConfirmRun(null);
      setActiveTab('runs');
      setRunPageNumber(1);
      setPollTrigger(value => value + 1);
      setDetailRunId(created.id);
      message.success('任务已提交');
    } catch (error) {
      if (currentProjectIdRef.current === operationProjectId) setRunError(`${errorMessage(error)}。请先检查执行记录，确认未启动后再重试。`);
    } finally { setTemplateRunPendingId(null); }
  }

  async function submitScope() {
    if (scopeSubmittingRef.current) return;
    scopeSubmittingRef.current = true;
    setScopeSubmitting(true);
    const operationProjectId = projectId;
    try {
      const values = await scopeForm.validateFields();
      const invalidTargetIndex = values.targets.findIndex(
        ({ target_type, value }) => scopeTargetValidationError(target_type, value) !== null
      );
      if (invalidTargetIndex >= 0) {
        const invalidTarget = values.targets[invalidTargetIndex];
        const validationError = scopeTargetValidationError(invalidTarget.target_type, invalidTarget.value) ?? '目标格式不正确';
        scopeForm.setFields([
          {
            name: ['targets', invalidTargetIndex, 'value'],
            errors: [validationError]
          }
        ]);
        return;
      }

      const data: ScopeInput = {
        name: values.name.trim(),
        status: values.status,
        authorized_by: values.authorized_by.trim(),
        valid_from: typeof values.valid_from === 'string' ? values.valid_from : values.valid_from.toISOString(),
        valid_until: typeof values.valid_until === 'string' ? values.valid_until : values.valid_until.toISOString(),
        is_default: values.is_default,
        targets: values.targets.map(({ target_type, match_mode, coverage_mode, value, url_rule }) => ({
          ...(target_type === 'url' && url_rule ? { url_rule } : {}),
          target_type,
          match_mode,
          coverage_mode: coverage_mode ?? 'exact',
          value: value.trim()
        }))
      };
      const wasEditing = editScopeId !== null;
      let savedScope: Scope;
      if (editScopeId) {
        savedScope = await updateScope(projectId, editScopeId, data);
        if (currentProjectIdRef.current !== operationProjectId) return;
        setScopes((current) => replaceScope(current, savedScope));
        setScopeCatalog((current) => replaceScope(current, savedScope));
      } else {
        savedScope = await createScope(projectId, data);
        if (currentProjectIdRef.current !== operationProjectId) return;
        setScopeCatalog((current) => [
          savedScope,
          ...current.map((item) => savedScope.is_default ? { ...item, is_default: false } : item)
        ]);
        setScopesTotal((current) => current + 1);
        if (scopePageNumber === 1) {
          setScopes((current) => [
            savedScope,
            ...current.map((item) => savedScope.is_default ? { ...item, is_default: false } : item)
          ].slice(0, scopePageSize));
        } else {
          setScopePageNumber(1);
        }
      }
      setScopeOpen(false);
      setEditScopeId(null);
      message.success(wasEditing ? 'Scope 已更新' : 'Scope 已创建');
    } catch (err) {
      if (!isFormValidationError(err) && currentProjectIdRef.current === operationProjectId) {
        message.error(errorMessage(err));
      }
    } finally {
      scopeSubmittingRef.current = false;
      setScopeSubmitting(false);
    }
  }

  async function submitTemplate() {
    if (templateSubmittingRef.current) return;
    templateSubmittingRef.current = true;
    const operationProjectId = projectId;
    try {
      const onlyWebScope = !editTemplateId && templateForm.getFieldValue('task_type') === 'web_probe';
      const values = await templateForm.validateFields(onlyWebScope ? ['task_type', 'scope_id'] : undefined);
      if (!editTemplateId && values.task_type === 'web_probe') { prepareFullWeb(values.scope_id); return; }
      setTemplateSubmitting(true);

      const selectedScope = availableScopes.find(s => s.id === values.scope_id);
      const targetType = requiredTargetType(values.task_type);
      const includeTargets = selectedScope?.targets.filter(
        (target) => target.match_mode === 'include' && (!targetType || target.target_type === targetType)
      ) ?? [];
      const editedTemplate = editTemplateId ? templates.find((template) => template.id === editTemplateId) : undefined;

      if (!editTemplateId && selectedScope) {
        const unavailableReason = scopeUnavailableReason(selectedScope, Date.now(), values.task_type);
        if (unavailableReason) {
          message.error(`选中的 Scope ${unavailableReason}，不能用于新任务`);
          return;
        }
      }
      if (!selectedScope) {
        message.error('请选择有效的授权 Scope');
        return;
      }
      if (editTemplateId && !editedTemplate) {
        message.error('待编辑模板不存在，请刷新后重试');
        return;
      }

      // Always resnapshot include targets from the bound Scope when saving.
      // Otherwise a Scope edit can leave a template pointing at removed targets
      // until dispatch rejects it, with no UI path to repair the stale config.
      const preserveWebSnapshot = editedTemplate?.config?.options?.blueprint_key && ['web_probe','fingerprint'].includes(values.task_type);
      const configTargets = preserveWebSnapshot ? editedTemplate.config.targets : includeTargets.flatMap(scopeTargetInputs);
      if (configTargets.length === 0) {
        message.error(`模板缺少可用的 ${requiredTargetLabel(values.task_type)} 授权目标`);
        return;
      }

      const passiveOptions = {
        profile: values.task_type === 'dns' ? ('resolve' as const) : ('subdomain_passive' as const),
        max_results: values.max_results,
        ...(values.task_type === 'dns' && values.record_types ? { record_types: values.record_types as Array<'A' | 'AAAA' | 'CNAME'> } : {}),
        ...(values.task_type === 'passive_intel' && values.sources ? { sources: values.sources } : {})
      };
      const activeOptions = {
        ...(values.task_type === 'port_probe' ? { ports: values.ports.trim() } : {}),
        ...(values.node_id?.trim() ? { node_id: values.node_id.trim() } : {})
      };
      const config: TaskTemplate['config'] = {
        targets: configTargets,
        options: {
          ...(editedTemplate?.config?.options?.blueprint_key ? {
            blueprint_key: editedTemplate.config.options.blueprint_key,
            blueprint_version: editedTemplate.config.options.blueprint_version,
            blueprint_step_key: editedTemplate.config.options.blueprint_step_key,
            blueprint_scope_id: editedTemplate.config.options.blueprint_scope_id,
            depends_on: editedTemplate.config.options.depends_on,
            target_selection: editedTemplate.config.options.target_selection
          } : {}),
          ...(isActiveTemplateType(values.task_type) ? activeOptions : passiveOptions)
        }
      };

      if (editTemplateId) {
        const savedTemplate = await updateTemplate(projectId, editTemplateId, {
          name: values.name.trim(),
          config,
          schedule: values.schedule?.trim() || '',
          timeout_seconds: values.timeout_seconds,
          rate_limit: values.rate_limit,
          concurrency: values.concurrency,
          retry_limit: values.retry_limit,
        });
        if (currentProjectIdRef.current !== operationProjectId) return;
        setTemplateOpen(false);
        setEditTemplateId(null);
        setTemplates((current) => replaceItem(current, savedTemplate));
        message.success('模板已更新');
      } else {
        const savedTemplate = await createTemplate(projectId, {
          name: values.name.trim(),
          task_type: values.task_type,
          scope_id: values.scope_id,
          config,
          schedule: values.schedule?.trim() || '',
          enabled: true,
          timeout_seconds: values.timeout_seconds,
          rate_limit: values.rate_limit,
          concurrency: values.concurrency,
          retry_limit: values.retry_limit
        });
        if (currentProjectIdRef.current !== operationProjectId) return;
        setEditTemplateId(null);
        setTemplatesTotal((current) => current + 1);
        if (templatePageNumber === 1) {
          setTemplates((current) => [savedTemplate, ...current].slice(0, templatePageSize));
        } else {
          setTemplatePageNumber(1);
        }
        if (createAndRun) {
          try {
            const created = await triggerTaskRun(projectId, savedTemplate.id);
            if (currentProjectIdRef.current !== operationProjectId) return;
            setActiveTab('runs');
            setRunPageNumber(1);
            setPollTrigger(value => value + 1);
            setDetailRunId(created.id);
            message.success('任务已提交，执行配置已保留，可再次运行');
          } catch (error) {
            if (currentProjectIdRef.current !== operationProjectId) return;
            setActiveTab('tasks');
            message.error(`配置已保存为“${savedTemplate.name}”，但未能确认任务启动：${errorMessage(error)}。请先检查执行记录，再决定是否重试。`, 10);
          }
        } else {
          message.success('模板已创建，可从列表确认并运行');
        }
        setTemplateOpen(false);
      }
    } catch (err) {
      if (!isFormValidationError(err) && currentProjectIdRef.current === operationProjectId) {
        message.error(errorMessage(err));
      }
    } finally {
      templateSubmittingRef.current = false;
      setTemplateSubmitting(false);
    }
  }

  if (resultRunId > 0) return <section className="page-surface"><PageHeader title={`任务 #${resultRunId} · 网站结果`} subtitle="查看本次观察，定位网站资产" actions={<Button onClick={()=>setResultQuery({})}>返回发现任务</Button>} /><WebResults key={`${projectId}:${resultRunId}`} projectId={projectId} runId={resultRunId} /></section>;
  return (
    <section className="page-surface">
      <PageHeader
        title="暴露发现"
        subtitle="授权范围、被动与主动任务编排及结果追踪"
        actions={can(Permission.DiscoveryRun) && <ProjectActiveGate actionLabel="新建发现任务"><Button type="primary" icon={<Plus size={16} />} disabled={templateSubmitting || templateRunPendingId !== null} onClick={() => templateDraft ? resumeTemplateDraft() : openNewTemplate(true)}>{templateDraft ? '继续配置任务' : '新建发现任务'}</Button></ProjectActiveGate>}
        summary={<div className="discovery-summary-line">
          <span>可用授权范围 <strong>{availableScopes.filter(scope => !scopeUnavailableReason(scope, scopeNow)).length}</strong></span>
          <span>执行记录 <strong>{runsTotal}</strong></span>
          <span>项目暴露面 <strong>{exposuresTotal}</strong></span>
        </div>}

      />
      <div className="discovery-content">
      {templateDraft && <Alert className="discovery-draft-notice" type="info" showIcon message="任务配置已暂存" description="补齐授权范围后，点击“继续配置任务”返回，已填内容会保留。" />}
      <Tabs
        activeKey={activeTab}
        onChange={(tab) => { setActiveTab(tab); if (tab === 'tasks') void fetchTemplates(false); }}
        className="beautiful-tabs"
        items={[
          { key: 'runs', label: <span className="discovery-tab-label"><Activity size={16} /> 发现任务</span>, children: <>                <StateView loading={runsLoading} error={runsError?.message} permissionDenied={runsError?.status === 403} onRetry={() => setPollTrigger((current) => current + 1)}>
                  <Typography.Title level={4} style={{ margin: 0, marginBottom: 8 }}>执行记录</Typography.Title>{batchRunNotice && <Alert type="info" showIcon message={batchRunNotice} closable onClose={() => setBatchRunNotice('')} />}
                  <Typography.Paragraph type="secondary">查看任务状态与发现产物。点击任务名称查看详情、结果口径和异常原因。</Typography.Paragraph>
                  <ProTable<TaskRun>
                    className="surface-table"
                    rowKey="id"
                    columns={runColumns}
                    dataSource={runs}
                    locale={{ emptyText: <div className="discovery-empty"><Typography.Paragraph>还没有发现任务。从新建任务开始，或使用场景方案选择适合的发现方式。</Typography.Paragraph><Button onClick={() => setActiveTab('blueprints')}>查看场景方案</Button></div> }}
                    search={false}
                    options={false}
                    pagination={{
                      current: runPageNumber,
                      pageSize: runPageSize,
                      total: runsTotal,
                      showSizeChanger: true,
                      pageSizeOptions: [10, 20, 50, 100],
                      onChange: (page, pageSize) => {
                        setRunPageNumber(pageSize === runPageSize ? page : 1);
                        setRunPageSize(pageSize);
                      }
                    }}
                    scroll={{ x: 'max-content' }}
                  />
                </StateView></> },
          {
            key: 'scope',
            label: <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Shield size={16} /> 授权范围</span>,
            children: (
              <StateView loading={scopesLoading} error={scopesError?.message} permissionDenied={scopesError?.status === 403} onRetry={() => fetchScopes(true)}>
                <div className="page-heading" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                  <Typography.Title level={4} style={{ margin: 0 }}>授权范围</Typography.Title>
                  {can(Permission.ScopeWrite) && (
                    <Button icon={<Plus size={16} />} type="primary" onClick={() => {
                      setEditScopeId(null);
                      setSelectedScopeSourceKeys([]);
                      setScopeSourceCandidates([]);
                      setScopeSourcesError('');
                      setScopeSourcesTruncated(false);
                      scopeForm.resetFields();
                      scopeForm.setFieldsValue({
                        status: 'inactive',
                        is_default: false,
                        targets: [{
                          target_type: 'domain',
                          match_mode: 'include',
                          coverage_mode: 'exact',
                          value: ''
                        }]
                      });
                      setScopeOpen(true);
                    }}>
                      新建授权范围
                    </Button>
                  )}
                </div>
                <ProTable<Scope>
                  className="surface-table"
                  rowKey="id"
                  columns={scopeColumns}
                  dataSource={scopes}
                  search={false}
                  options={false}
                  pagination={{
                    current: scopePageNumber,
                    pageSize: scopePageSize,
                    total: scopesTotal,
                    showSizeChanger: true,
                    pageSizeOptions: [10, 20, 50, 100],
                    onChange: (page, pageSize) => {
                      setScopePageNumber(pageSize === scopePageSize ? page : 1);
                      setScopePageSize(pageSize);
                    }
                  }}
                />
              </StateView>
            )
          },
          {
            key: 'blueprints',
            label: <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Target size={16} /> 场景方案</span>,
            children: (
              <BlueprintCatalog
                key={projectId}
                projectId={projectId}
                requestedPreview={webPreviewRequest}
                scopes={availableScopes}
                canCreateTemplates={can(Permission.DiscoveryRun)}
                onManageScopes={() => setActiveTab('scope')}
                onViewTemplates={() => { setTemplatePageNumber(1); setActiveTab('tasks'); void fetchTemplates(false,1); }}
                onRunTemplate={(template) => { setRunError(''); setConfirmRun(template); }}
                onTemplatesCreated={(result) => {
                  templateRequestRef.current?.abort();
                  templateRequestRef.current = null;
                  const received = result.templates.map(item => item.template);
                  const ids = new Set(received.map(item => item.id));
                  const known = new Set(templateItemsRef.current.map(item => item.id));
                  setTemplates(current => [...received, ...(templatePageNumber === 1 ? current.filter(item => !ids.has(item.id)) : [])].slice(0, templatePageSize));
                  setTemplatesTotal(total => Math.max(received.length, total + result.templates.filter(item => item.created && !known.has(item.template.id)).length));
                  setTemplatesLoading(false);
                  setTemplatesError(null);
                  setTemplateCreationNotice('已创建 ' + result.created_count + ' 个任务模板，复用 ' + result.existing_count + ' 个已有模板。可在下方确认并运行。');
                  setTemplatePageNumber(1);
                  setActiveTab('tasks');
                  if (received.length && received.every(item => item.task_type === 'web_probe')) setWebBatchTemplates(received);
                  void fetchTemplates(false, 1);
                }}
              />
            )
          },
          {
            key: 'tasks',
            label: <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><FileText size={16} /> 任务模板</span>,
            children: (
              <Space direction="vertical" size={18} className="full-width">
                {templateCreationNotice && <div ref={templateNoticeRef} style={{scrollMarginTop:130}}><Alert type="success" showIcon message={templateCreationNotice} closable onClose={() => setTemplateCreationNotice('')} /></div>}
                {templatesError && templatesError.status !== 403 && templates.length > 0 && <Alert type="warning" showIcon message="列表刷新失败，已保留当前模板" description={templatesError.message} action={<Button onClick={() => void fetchTemplates(false)}>重试刷新</Button>} />}
                <StateView loading={templatesLoading && !templates.length} error={!templates.length ? templatesError?.message : undefined} permissionDenied={templatesError?.status === 403} onRetry={() => fetchTemplates(true)}>
                  <div className="page-heading" style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <Typography.Title level={4} style={{ margin: 0 }}>任务模板</Typography.Title>
                    {can(Permission.DiscoveryRun) && (
                      <Button icon={<Plus size={16} />} type="primary" disabled={templateSubmitting || templateRunPendingId !== null} onClick={() => openNewTemplate(false)}>
                        新建模板
                      </Button>
                    )}
                  </div>
                  <ProTable<TaskTemplate>
                    className="surface-table"
                    rowKey="id"
                    columns={templateColumns}
                    scroll={{ x: 'max-content' }}
                    dataSource={templates}
                    search={false}
                    options={false}
                    pagination={{
                      current: templatePageNumber,
                      pageSize: templatePageSize,
                      total: templatesTotal,
                      showSizeChanger: true,
                      pageSizeOptions: [10, 20, 50, 100],
                      onChange: (page, pageSize) => {
                        setTemplatePageNumber(pageSize === templatePageSize ? page : 1);
                        setTemplatePageSize(pageSize);
                      }
                    }}
                  />
                </StateView>


              </Space>
            )
          },
          {
            key: 'exposures',
            label: <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Database size={16} /> 暴露结果</span>,
            children: (
              <StateView loading={exposuresLoading} error={exposuresError?.message} permissionDenied={exposuresError?.status === 403} onRetry={() => fetchExposures(true)}>
                <Space direction="vertical" size={18} className="full-width">
                  <Typography.Paragraph type="secondary">这里展示端口、服务、网站等暴露信息。域名和解析结果请前往{can(Permission.AssetRead) ? <Link to={`/projects/${projectId}/assets`}>资产管理</Link> : '资产管理（需要资产查看权限）'}。引擎结果数与暴露面数量采用不同口径。</Typography.Paragraph>
                  {can(Permission.AssetRead)&&<WebResults key={`exposures:${projectId}`} projectId={projectId} />}
                  <details className="full-width"><summary>查看全部暴露事实（端口、服务及网站记录）</summary>
                  {exposures.length > 0 && <div className="discovery-summary-line">{exposureStats.map(item => <span key={item.type}>{exposureLabels[item.type]} <strong>{item.count}</strong></span>)}<span>以上为当前页数量</span></div>}
                  <ProTable<Exposure>
                    className="surface-table"
                    rowKey="id"
                    columns={exposureColumns}
                    dataSource={exposures}
                    locale={{ emptyText: <div className="discovery-empty"><Typography.Paragraph>当前项目暂无暴露面。被动域名发现可能只产生资产，不一定产生端口或网站暴露信息。</Typography.Paragraph><Button onClick={() => setActiveTab('runs')}>查看执行记录</Button></div> }}
                    search={false}
                    options={false}
                    pagination={{
                      current: exposurePageNumber,
                      pageSize: exposurePageSize,
                      total: exposuresTotal,
                      showSizeChanger: true,
                      pageSizeOptions: [10, 20, 50, 100],
                      onChange: (page, pageSize) => {
                        setExposurePageNumber(pageSize === exposurePageSize ? page : 1);
                        setExposurePageSize(pageSize);
                      }
                    }}
                  />
                  </details>
                </Space>
              </StateView>
            )
          },
          {
            key: 'changes',
            label: <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Activity size={16} /> 变化监控</span>,
            children: (
              <div style={{ textAlign: 'center', padding: '64px 0', color: '#888' }}>
                变化事件查询接口待接入
              </div>
            )
          }
        ]}
      />
      </div>

      <Modal
        className="surface-card"
        title={editScopeId ? '编辑 Scope' : '新建授权范围'}
        width={760}
        open={scopeOpen}
        confirmLoading={scopeSubmitting}
        okButtonProps={{ disabled: scopeSubmitting }}
        cancelButtonProps={{ disabled: scopeSubmitting }}
        maskClosable={!scopeSubmitting}
        onCancel={() => {
          if (scopeSubmitting) return;
          setScopeOpen(false);
          setEditScopeId(null);
        }}
        afterClose={() => {
          scopeSourceRequestSequenceRef.current += 1;
          setScopeSourcesLoading(false);
          setSelectedScopeSourceKeys([]);
          scopeForm.resetFields();
        }}
        destroyOnHidden
        onOk={submitScope}
        okText="保存"
      >
        <Form form={scopeForm} layout="vertical" disabled={scopeSubmitting}>
          <Form.Item name="name" label="名称" rules={[{ required: true, max: 128 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="authorized_by" label="授权人" rules={[{ required: true, max: 64 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="status" label="创建状态" rules={[{ required: true }]}>
            <Select
              onChange={(status: Scope['status']) => {
                if (status !== 'active') scopeForm.setFieldValue('is_default', false);
              }}
              options={[
              { value: 'inactive', label: '暂不启用（推荐）' },
              { value: 'active', label: '创建后立即启用' }
              ]}
            />
          </Form.Item>
          <Form.Item
            name="is_default"
            label="项目默认 Scope"
            valuePropName="checked"
            extra={watchScopeStatus === 'active'
              ? '场景预检未指定 Scope 时优先使用；同一项目只能有一个默认 Scope。'
              : '只有已启用的 Scope 才能设为项目默认。'}
          >
            <Switch disabled={watchScopeStatus !== 'active'} />
          </Form.Item>
          <Form.Item name="valid_from" label="生效时间" rules={[
            { required: true }
          ]}>
            <DatePicker showTime format="YYYY-MM-DDTHH:mm:ssZ" style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="valid_until"
            label="失效时间"
            extra="授权有效期最长 365 天；到期后需要重新确认授权。"
            rules={[
            { required: true },
            ({ getFieldValue }) => ({
              validator(_, value) {
                if (!value || !getFieldValue('valid_from')) return Promise.resolve();
                const fromTime = scopeDateValue(getFieldValue('valid_from'));
                const untilTime = scopeDateValue(value);
                if (untilTime <= fromTime) {
                  return Promise.reject(new Error('失效时间必须晚于生效时间'));
                }
                if (untilTime - fromTime > MAX_SCOPE_WINDOW_MS) {
                  return Promise.reject(new Error('授权有效期最长 365 天，请缩短失效时间'));
                }
                return Promise.resolve();
              },
            })
          ]}>
            <DatePicker showTime format="YYYY-MM-DDTHH:mm:ssZ" style={{ width: '100%' }} />
          </Form.Item>
          {!editScopeId ? (
            <Space direction="vertical" size={8} className="full-width">
              <Alert
                type="info"
                showIcon
                message="从现有资料生成 Scope 草稿"
                description="可复用项目主主体、受管域名和已有资产。候选只会复制到当前表单，不会自动保存、启用或扩大主动扫描权限。"
              />
              <Space.Compact block>
                <Select
                  aria-label="Scope 来源候选"
                  mode="multiple"
                  allowClear
                  showSearch
                  optionFilterProp="label"
                  placeholder={scopeSourcesLoading ? '正在加载候选…' : '选择项目主体、受管域名或已有资产'}
                  loading={scopeSourcesLoading}
                  value={selectedScopeSourceKeys}
                  options={scopeSourceOptions}
                  onChange={setSelectedScopeSourceKeys}
                  style={{ flex: 1 }}
                />
                <Button
                  aria-label="添加到 Scope 草稿"
                  icon={<Plus size={15} />}
                  disabled={!selectedScopeSourceKeys.length || scopeSourcesLoading}
                  onClick={appendSelectedScopeSources}
                >
                  添加到草稿
                </Button>
              </Space.Compact>
              {scopeSourcesError ? <Alert type="warning" showIcon message={scopeSourcesError} /> : null}
              {!scopeSourcesLoading && !scopeSourcesError && scopeSourceCandidates.length === 0
                ? <Typography.Text type="secondary">暂无可复用候选，可继续手工添加授权目标。</Typography.Text>
                : null}
              {scopeSourcesTruncated
                ? <Typography.Text type="secondary">每类资产最多展示前 50 条；未显示的目标仍可手工添加。</Typography.Text>
                : null}
            </Space>
          ) : null}
          <Divider orientation="left" plain>授权目标</Divider>
          <Typography.Text type="secondary">
            CIDR 仅为历史 Scope 兼容保留；当前主动引擎只支持单 IP，新建目标时不可选择 CIDR。
          </Typography.Text>
          <Form.List
            name="targets"
            rules={[{
              validator: async (_, targets) => {
                if (!targets || targets.length === 0) throw new Error('至少需要一个授权目标');
                const seen = new Set<string>();
                for (const target of targets) {
                  const key = `${target?.target_type ?? ''}|${target?.match_mode ?? ''}|${target?.value?.trim().toLowerCase() ?? ''}`;
                  if (seen.has(key)) throw new Error('授权目标不能重复');
                  seen.add(key);
                }
              }
            }]}
          >
            {(fields, { add, remove }, { errors }) => (
              <Space direction="vertical" className="full-width" size={8}>
                {fields.map((field, index) => (
                  <div key={field.key} className="scope-target-editor">
                  <Space.Compact className="full-width">
                    <Form.Item name={[field.name, 'target_type']} rules={[{ required: true }]} style={{ width: 120 }}>
                      <Select
                        aria-label={`目标类型 ${index + 1}`}
                        onChange={(type) => {
                          scopeForm.setFieldValue(['targets', field.name, 'coverage_mode'], 'exact');
                          scopeForm.setFieldValue(['targets', field.name, 'url_rule'], type === 'url' ? {protocol:'https',include_root:true,include_subdomains:false,ports:[]} : undefined);
                        }}
                        options={[
                          { value: 'domain', label: 'Domain' },
                          { value: 'company', label: '企业主体' },
                          { value: 'ip', label: 'IP' },
                          { value: 'url', label: 'URL' },
                          { value: 'cidr', label: 'CIDR（当前主动引擎暂不支持）', disabled: true }
                        ]}
                      />
                    </Form.Item>
                    <Form.Item noStyle shouldUpdate={(previous, current) => (
                      previous.targets?.[field.name]?.target_type !== current.targets?.[field.name]?.target_type
                    )}>
                      {({ getFieldValue }) => {
                        const targetType = getFieldValue(['targets', field.name, 'target_type']) as ScopeTarget['target_type'] | undefined;
                        return (
                          <Form.Item
                            name={[field.name, 'coverage_mode']}
                            rules={[{ required: true }]}
                            style={{ width: 145 }}
                          >
                            <Select
                              aria-label={`覆盖范围 ${index + 1}`}
                              options={targetType === 'domain'
                                ? [
                                  { value: 'exact', label: '仅当前域名' },
                                  { value: 'subdomains', label: '包含子域名' }
                                ]
                                : [{ value: 'exact', label: targetType === 'url' ? '按下方 URL 规则' : '精确匹配' }]}
                              disabled={targetType !== 'domain'}
                            />
                          </Form.Item>
                        );
                      }}
                    </Form.Item>
                    <Form.Item name={[field.name, 'match_mode']} rules={[{ required: true }]} style={{ width: 120 }}>
                      <Select
                        aria-label={`匹配模式 ${index + 1}`}
                        options={[
                          { value: 'include', label: 'Include' },
                          { value: 'exclude', label: 'Exclude' }
                        ]}
                      />
                    </Form.Item>
                    <Form.Item noStyle shouldUpdate={(previous, current) => (
                      previous.targets?.[field.name]?.target_type !== current.targets?.[field.name]?.target_type
                    )}>
                      {({ getFieldValue }) => {
                        const targetType = getFieldValue(['targets', field.name, 'target_type']) as ScopeTarget['target_type'] | undefined;
                        return (
                          <Form.Item
                            name={[field.name, 'value']}
                            dependencies={[['targets', field.name, 'target_type']]}
                            rules={[
                              { required: true, max: 512 },
                              {
                                validator(_, value?: string) {
                                  const validationError = scopeTargetValidationError(targetType, value);
                                  return validationError ? Promise.reject(new Error(validationError)) : Promise.resolve();
                                }
                              }
                            ]}
                            style={{ flex: 1 }}
                          >
                            <Input
                              aria-label={`目标值 ${index + 1}`}
                              placeholder={scopeTargetPlaceholder(targetType)}
                              onChange={() => { if(targetType === 'url') dirtyURLInputs.current.add(field.name); }}
                              onBlur={(event) => {
                                if (targetType !== 'url' || !dirtyURLInputs.current.delete(field.name) || !event.target.value.trim()) return;
                                try {
                                  const previousRule = scopeForm.getFieldValue(['targets',field.name,'url_rule']);
                                  if (!previousRule && !event.target.value.includes('*.')) return;
                                  const parsed = parseURLAuthorization(event.target.value, event.target.value.includes('://') ? undefined : previousRule);
                                  scopeForm.setFieldValue(['targets',field.name,'value'], parsed.value);
                                  scopeForm.setFieldValue(['targets',field.name,'url_rule'], parsed.rule);
                                  if(parsed.discardedPath) message.warning('已转换为整个站点授权，路径和查询参数不作为限制', 6);
                                } catch { /* The field validator displays invalid host syntax. */ }
                              }}
                            />
                          </Form.Item>
                        );
                      }}
                    </Form.Item>
                    <Button
                      aria-label={`删除目标 ${index + 1}`}
                      icon={<Trash2 size={15} />}
                      disabled={fields.length === 1}
                      onClick={() => remove(field.name)}
                    />
                  </Space.Compact>
                  <Form.Item noStyle shouldUpdate>
                    {({getFieldValue}) => getFieldValue(['targets',field.name,'target_type']) === 'url' ? (
                      <div className="url-authorization-options">
                        {getFieldValue(['targets',field.name,'url_rule']) ? <Form.Item
                          name={[field.name,'url_rule']} label="URL 匹配规则"
                          rules={[{validator:(_,rule) => {const error=validateURLRule(rule);return error ? Promise.reject(new Error(error)) : Promise.resolve();}}]}>
                          <URLRuleEditor onChange={(rule) => {
                            try {
                              const parsed = parseURLAuthorization(getFieldValue(['targets',field.name,'value']), rule);
                              scopeForm.setFieldValue(['targets',field.name,'value'], parsed.value);
                            } catch { /* Keep incomplete host input available for correction. */ }
                          }} />
                        </Form.Item> : <Space direction="vertical">
                          <Typography.Text type="secondary">已有规则：按协议、主机及显式端口匹配整个站点，路径和参数不参与限制。</Typography.Text>
                          <Button onClick={() => {
                            try {
                              const parsed=parseURLAuthorization(getFieldValue(['targets',field.name,'value']));
                              scopeForm.setFieldValue(['targets',field.name,'value'],parsed.value);
                              scopeForm.setFieldValue(['targets',field.name,'url_rule'],parsed.rule);
                            } catch { message.warning('请先填写有效 URL'); }
                          }}>设置协议和通配范围</Button>
                        </Space>}
                      </div>
                    ) : null}
                  </Form.Item>
                  </div>
                ))}
                <Button
                  block
                  icon={<Plus size={15} />}
                  type="dashed"
                  onClick={() => add({
                    target_type: 'domain',
                    match_mode: 'include',
                    coverage_mode: 'exact',
                    value: ''
                  })}
                >
                  添加目标
                </Button>
                <Form.ErrorList errors={errors} />
              </Space>
            )}
          </Form.List>
        </Form>
      </Modal>

      <Modal
        className="discovery-task-modal"
        centered
        title={editTemplateId ? '编辑模板' : createAndRun ? (templateReview ? '确认发现任务' : '新建发现任务') : '新建发现模板'}
        width={720}
        open={templateOpen}
        confirmLoading={templateSubmitting}
        okButtonProps={{ disabled: templateSubmitting }}
        cancelButtonProps={{ disabled: templateSubmitting }}
        maskClosable={!templateSubmitting}
        onCancel={() => {
          if (templateSubmitting) return;
          setTemplateOpen(false);
          setEditTemplateId(null);
        }}
        afterClose={() => templateForm.resetFields()}
        destroyOnHidden
        onOk={createAndRun && !templateReview ? reviewNewTask : submitTemplate}
        okText={!editTemplateId && watchTaskType === 'web_probe' ? '预览全部网站目标' : createAndRun ? (templateReview ? '创建并运行' : '下一步：确认执行') : '保存模板'}
      >
        {templateReview && <Space direction="vertical" size={16} className="full-width">
          <ExecutionSummary scope={scopesById.get(watchScopeId)} taskType={watchTaskType} overview={engineOverview} overviewError={engineError}
            sources={templateForm.getFieldValue('sources')} ports={templateForm.getFieldValue('ports')} nodeId={templateForm.getFieldValue('node_id')} />
          <Typography.Text type="secondary">点击“创建并运行”后提交一次任务。执行配置会保存到任务模板，方便下次复用。</Typography.Text>
          <Button disabled={templateSubmitting} onClick={() => setTemplateReview(false)}>返回修改</Button>
        </Space>}
        <Form
          form={templateForm}
          layout="vertical"
          style={{ display: templateReview ? 'none' : undefined }}
          disabled={templateSubmitting}
          initialValues={{
            max_results: 1000,
            concurrency: 10,
            rate_limit: 200,
            timeout_seconds: 1800,
            retry_limit: 3,
            schedule: '',
            ports: '80,443',
            node_id: ''
          }}
        >
          <Typography.Paragraph type="secondary">选择发现目的和已授权目标，其余设置可使用默认值。</Typography.Paragraph>
          {!editTemplateId && watchTaskType === 'web_probe' && <Alert type="info" showIcon message="将从项目已有资产准备全部网站" description="下一步会显示域名和 URL 授权覆盖的全部网址，自动拆分批次；不需要逐条填写 URL。" />}
          <Row gutter={20}>
            <Col xs={24} sm={12}>
              <Form.Item name="task_type" label="发现目的" rules={[{ required: true, message: '请选择发现目的' }]}>
                <Select disabled={!!editTemplateId} onChange={(taskType: TemplateFormValues['task_type']) => {
                  templateForm.setFieldValue('scope_id', undefined);
                  templateForm.setFieldsValue({
                    concurrency: Math.min(templateForm.getFieldValue('concurrency') || 10, isActiveTemplateType(taskType) ? 20 : 50),
                    rate_limit: isActiveTemplateType(taskType) ? Math.min(templateForm.getFieldValue('rate_limit') || 50, 100) : 200
                  });
                }} options={Object.entries(discoveryPurpose).filter(([value]) => value !== 'org_intel').map(([value, label]) => ({ value, label }))} />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item name="scope_id" label="授权范围" rules={[{ required: true, message: '请选择兼容且有效的授权范围' }]}
                extra={scopeOptions.some(option => !option.disabled) ? '默认选择项目默认或唯一兼容范围。' : '当前没有兼容范围，请补充所需的已授权目标。'}>
                <Select disabled={!!editTemplateId} options={scopeOptions} placeholder="选择已授权目标" />
              </Form.Item>
            </Col>
          </Row>
          {!scopeOptions.some(option => !option.disabled) && <Button type="link" onClick={() => { setTemplateDraft({ values: templateForm.getFieldsValue(true), runImmediately: createAndRun }); setTemplateOpen(false); setActiveTab('scope'); }}>管理授权范围</Button>}
          <Form.Item hidden={!editTemplateId && watchTaskType === 'web_probe'} name="name" label="任务名称" rules={[{ required: true, max: 64, whitespace: true, message: '请输入 1–64 个字符的任务名称' }]} extra="已按发现目的自动命名，也可以改成便于识别的名称。">
            <Input placeholder="例如：每次上线前检查" onChange={() => { templateNameEditedRef.current = true; }} />
          </Form.Item>
          {watchScopeId && <details className="inline-disclosure"><summary>目标、引擎与执行说明</summary>
            <ExecutionSummary scope={scopesById.get(watchScopeId)} taskType={watchTaskType} overview={engineOverview} overviewError={engineError}
              inputTargets={editTemplateId ? templates.find(template => template.id === editTemplateId)?.config?.targets : undefined}
              sources={templateForm.getFieldValue('sources')} ports={templateForm.getFieldValue('ports')} nodeId={templateForm.getFieldValue('node_id')} />
          </details>}
          <Divider orientation="left" plain>发现内容</Divider>
          {watchTaskType === 'passive_intel' && <Form.Item name="sources" label="数据来源"
            extra="自动模式使用当前配置可用的来源；结果分批回传，不必等全部来源和 DNS 完成。也可手动指定来源。"
            rules={[{ required: true, type: 'array', min: 1, message: '请至少选择一个数据来源' }, { validator: (_, sources?: string[]) => sources?.every(source => PASSIVE_SOURCE_OPTIONS.some(option => option.value === source)) && !(sources.includes('auto') && sources.length > 1) ? Promise.resolve() : Promise.reject(new Error('请选择支持的来源，自动模式不能与指定来源同时选择')) }]}>
            <Select mode="multiple" options={PASSIVE_SOURCE_OPTIONS} />
          </Form.Item>}
          {watchTaskType === 'dns' && <Form.Item name="record_types" label="解析记录" extra="A：IPv4 地址；AAAA：IPv6 地址；CNAME：域名别名。通常保留全部。" rules={[{ required: true, type: 'array', min: 1, message: '请选择至少一种记录类型' }]}>
            <Select mode="multiple" options={['A', 'AAAA', 'CNAME'].map(value => ({ value, label: value }))} />
          </Form.Item>}
          {(watchTaskType === 'passive_intel' || watchTaskType === 'dns') && <Form.Item name="max_results" label="最大结果数" extra="限制本次任务获取的结果，不等于新增资产数量；来源服务可能应用更低的上限。" rules={[{ required: true }]}>
            <InputNumber min={1} max={10000} style={{ width: '100%' }} />
          </Form.Item>}
          {watchTaskType === 'port_probe' && <Form.Item name="ports" label="端口范围" extra="默认检查 HTTP / HTTPS 常用端口 80、443。自定义最多 1000 个端口。"
            rules={[{ required: true }, { validator: (_, value?: string) => { const error = validatePortSpec(value); return error ? Promise.reject(new Error(error)) : Promise.resolve(); } }]}>
            <Input placeholder="例如 80,443,8000-8100" />
          </Form.Item>}
          {activeTemplateSelected && (editTemplateId || watchTaskType !== 'web_probe') && <Typography.Paragraph type="secondary">仅检查范围中已授权的{requiredTargetLabel(watchTaskType)}目标。执行节点默认自动分配，更多选项见高级设置。</Typography.Paragraph>}
          <Typography.Paragraph><Typography.Text strong>执行方式：</Typography.Text>手动运行一次</Typography.Paragraph>
          <Typography.Paragraph type="secondary">定时执行尚未接入，当前无需填写调度表达式。</Typography.Paragraph>
          <Form.Item name="schedule" hidden><Input /></Form.Item>
          {editTemplateId && templateForm.getFieldValue('schedule') && <Alert type="warning" showIcon message="此模板保留了历史周期配置，但不会自动运行" description={`原配置：${templateForm.getFieldValue('schedule')}。本次编辑保留该值，目前请手动运行。`} />}
          <details className="inline-disclosure" hidden={!editTemplateId && watchTaskType === 'web_probe'}><summary>高级设置：执行节点、并发与超时</summary>
            <Typography.Paragraph type="secondary">通常无需修改。以下是本任务的限制，实际执行仍受引擎配置与平台策略约束。</Typography.Paragraph>
            {activeTemplateSelected && <Form.Item name="node_id" label="执行节点（可选）" extra="默认自动分配。列表来自最近一次连接检测，节点可能已发生变化。"
              rules={[{ validator: (_, value?: string) => { const error = validateNodeId(value); return error ? Promise.reject(new Error(error)) : Promise.resolve(); } }]}>
              <Select allowClear placeholder="自动分配" options={[
                ...(engineOverview?.items.find(item => item.route === 'active')?.nodes ?? []).map(node => ({ value: node.node_id, label: `${node.node_id}${node.capabilities?.length ? ` · ${node.capabilities.join(' / ')}` : ''}` })),
                ...(templateForm.getFieldValue('node_id') && !engineOverview?.items.find(item => item.route === 'active')?.nodes?.some(node => node.node_id === templateForm.getFieldValue('node_id')) ? [{ value: templateForm.getFieldValue('node_id'), label: `${templateForm.getFieldValue('node_id')}（已有配置，当前未确认）` }] : [])
              ]} notFoundContent="暂无可选节点，可保留自动分配或请管理员检测引擎" />
            </Form.Item>}
            <Row gutter={20}>
              <Col xs={24} sm={12}><Form.Item name="concurrency" label="并发数" extra="同时处理的工作数量。较低值可以减小负载。" rules={[{ required: true }]}><InputNumber min={1} max={activeTemplateSelected ? 20 : 50} style={{ width: '100%' }} /></Form.Item></Col>
              <Col xs={24} sm={12}><Form.Item name="rate_limit" label="平台速率上限" extra={activeTemplateSelected ? '主动引擎不接收逐任务速率，实际速度由节点配置控制。此值仅用于平台限制校验。' : '每秒操作数的上限；数据来源自身仍可能限流。'} rules={[{ required: true }]}><InputNumber min={1} max={activeTemplateSelected ? 100 : 2000} style={{ width: '100%' }} /></Form.Item></Col>
              <Col xs={24} sm={12}><Form.Item name="timeout_seconds" label="超时（秒）" extra="1800 秒为 30 分钟；到期后按平台超时策略处理。" rules={[{ required: true }]}><InputNumber min={60} max={10800} style={{ width: '100%' }} /></Form.Item></Col>
              <Col xs={24} sm={12}><Form.Item name="retry_limit" label="重试次数" extra="失败后的重试上限。增加重试可能消耗更多来源额度。" rules={[{ required: true }]}><InputNumber min={0} max={100} style={{ width: '100%' }} /></Form.Item></Col>
            </Row>
          </details>
        </Form>
      </Modal>
      <Modal title="确认运行任务" destroyOnHidden open={confirmRun !== null} width={680} confirmLoading={templateRunPendingId !== null}
        okText="开始运行" onOk={startConfirmedRun} okButtonProps={{ disabled: templateRunPendingId !== null || !confirmRun || !scopesById.has(confirmRun.scope_id) || Boolean(confirmRun && scopesById.get(confirmRun.scope_id) && scopeUnavailableReason(scopesById.get(confirmRun.scope_id)!, scopeNow, confirmRun.config?.inheritance ? undefined : confirmRun.task_type, confirmRun.config?.targets?.some(target => target.type === 'url'))) || !confirmRun.enabled }}
        onCancel={() => { if (templateRunPendingId === null) setConfirmRun(null); }}>
        {confirmRun && <Space direction="vertical" size={16} className="full-width">
          <Typography.Text strong>{confirmRun.name}</Typography.Text>
          {confirmRun.config?.inheritance && <Alert type="info" showIcon message={`继承自任务 #${confirmRun.config.inheritance.source_run_id}`} description="目标来自已保存的发现证据；继续沿用父授权，下发前再次校验。" />}
          <ExecutionSummary scope={scopesById.get(confirmRun.scope_id)} taskType={confirmRun.task_type} overview={engineOverview} overviewError={engineError}
            sources={confirmRun.config?.options?.sources} ports={confirmRun.config?.options?.ports} nodeId={confirmRun.config?.options?.node_id} inputTargets={confirmRun.config?.targets} />
          {confirmRun.config?.options?.depends_on?.length ? <Alert type="warning" showIcon message="这是方案中的独立步骤" description="当前不会自动使用上一步的发现结果；请确认所需输入已在授权范围与模板配置中。" /> : null}
          {confirmRun?.task_type === 'web_probe' && <Alert type="info" showIcon message={`此模板保存了 ${confirmRun.config.targets.length} 个网址的目标快照`} description="直接运行会使用这份快照。如需覆盖最新发现的全部域名，请重新准备全量目标。" action={<Button disabled={templateRunPendingId !== null} onClick={() => { const scopeId=confirmRun.scope_id;setConfirmRun(null);prepareFullWeb(scopeId); }}>按最新资产重新准备</Button>} />}
          {runError && <Alert type="error" showIcon message="未能确认任务启动" description={<><div>{runError}</div><Button type="link" onClick={() => { setConfirmRun(null); setActiveTab('runs'); setPollTrigger(value => value + 1); }}>检查执行记录</Button></>} />}
        </Space>}
      </Modal>
      <WebBatchRunDialog projectId={projectId} templates={webBatchTemplates} onClose={() => setWebBatchTemplates(null)} onSubmitted={(submitted) => {
        setWebBatchTemplates(null); setActiveTab('runs'); setRunPageNumber(1); setPollTrigger(value => value + 1);
        setBatchRunNotice(submitted.length === webBatchTemplates?.length ? `已提交全部 ${submitted.length} 个 Web 批次。各批次独立显示状态，网站结果汇总到资产中心。` : `已确认提交 ${submitted.length} 个 Web 批次，其余提交结果请先核对执行记录，避免重复运行。`);
      }} />
      <RunDetails onPrepareWeb={prepareFullWeb} onContinue={(runId) => {setDetailRunId(null);setDerivedRunId(runId);}} projectId={projectId} runId={detailRunId} onClose={() => setDetailRunId(null)} onExposures={() => { setDetailRunId(null); setActiveTab('exposures'); }} />

      <DerivedTargets onPrepareWeb={prepareFullWeb} projectId={projectId} runId={derivedRunId} onClose={() => setDerivedRunId(null)} onScopeUpdated={() => { void fetchScopes(true);void fetchScopeCatalog(); }}
        onCreated={(template) => { setDerivedRunId(null);setRunError('');setConfirmRun(template);void fetchTemplates(true); }} />
    </section>
  );
}
