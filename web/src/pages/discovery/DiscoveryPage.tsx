import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Button, Form, Input, InputNumber, Modal, Popconfirm, Progress, Select, Space, Tabs, Tag, Tooltip, Typography, App as AntApp, Row, Col, Divider, DatePicker } from 'antd';
import { Globe, Network, Play, Plus, Server, Square, ShieldCheck, Settings, Shield, FileText, Database, Activity, Target, Trash2 } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import dayjs, { type Dayjs } from 'dayjs';

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
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StatCard } from '../../components/StatCard';
import { StateView } from '../../components/StateView';
import { useProjectId } from '../../projects/ProjectContext';

const exposureIcon: Record<string, ReactNode> = {
  port: <Network size={18} />,
  service: <Server size={18} />,
  web: <Globe size={18} />,
  certificate: <ShieldCheck size={18} />,
  cloud_config: <Settings size={18} />
};

const DEFAULT_PAGE_SIZE = 20;
const IDLE_POLL_INTERVAL_MS = 30_000;
const ACTIVE_POLL_INTERVAL_MS = 4_000;
const ERROR_POLL_INTERVAL_MS = 8_000;
const PASSIVE_SOURCE_OPTIONS = [{ value: 'fofa', label: 'FOFA' }];

type TemplateFormValues = {
  name: string;
  task_type: 'passive_intel' | 'dns';
  scope_id: number;
  max_results: number;
  sources: string[];
  record_types: string[];
  schedule?: string;
  timeout_seconds: number;
  rate_limit: number;
  concurrency: number;
  retry_limit: number;
};

type ScopeFormValues = Omit<ScopeInput, 'valid_from' | 'valid_until'> & {
  valid_from: string | Dayjs;
  valid_until: string | Dayjs;
};

function scopeUnavailableReason(scope: Scope, now = Date.now()) {
  if (scope.status !== 'active') return '未启用';
  const validFrom = Date.parse(scope.valid_from);
  const validUntil = Date.parse(scope.valid_until);
  if (!Number.isFinite(validFrom) || !Number.isFinite(validUntil)) return '有效期无效';
  if (now < validFrom) return '尚未生效';
  if (now > validUntil) return '已过期';
  if (!scope.targets.some((target) => target.target_type === 'domain' && target.match_mode === 'include')) {
    return '缺少 include domain';
  }
  return null;
}

function runColor(status: TaskRun['status']) {
  if (status === 'success') return 'green';
  if (status === 'failed') return 'red';
  if (status === 'cancelled') return 'default';
  if (status === 'partial_success') return 'gold';
  return 'blue';
}

function replaceItem<T extends { id: number }>(items: T[], updated: T) {
  return items.map((item) => item.id === updated.id ? { ...item, ...updated } : item);
}

function isEditableTaskType(taskType: TaskTemplate['task_type']): taskType is TemplateFormValues['task_type'] {
  return taskType === 'passive_intel' || taskType === 'dns';
}

function isValidSchedule(value?: string) {
  const schedule = value?.trim() ?? '';
  if (!schedule) return true;
  if (/^@every\s+\d+(ms|s|m|h)$/i.test(schedule)) return true;
  if (/^@(yearly|annually|monthly|weekly|daily|midnight|hourly)$/i.test(schedule)) return true;
  const fields = schedule.split(/\s+/);
  return fields.length === 5 && fields.every((field) => /^[\dA-Za-z*?,/#L-]+$/.test(field));
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

  const [activeTab, setActiveTab] = useState('scope');
  const [scopeNow, setScopeNow] = useState(() => Date.now());

  // Scope form
  const [scopeOpen, setScopeOpen] = useState(false);
  const [editScopeId, setEditScopeId] = useState<number | null>(null);
  const [scopeStatusPendingIds, setScopeStatusPendingIds] = useState<Set<number>>(() => new Set());
  const [scopeSubmitting, setScopeSubmitting] = useState(false);
  const scopeSubmittingRef = useRef(false);
  const [scopeForm] = Form.useForm<ScopeFormValues>();

  // Template form
  const [templateOpen, setTemplateOpen] = useState(false);
  const [editTemplateId, setEditTemplateId] = useState<number | null>(null);
  const [templateStatusPendingIds, setTemplateStatusPendingIds] = useState<Set<number>>(() => new Set());
  const [templateDeletePendingIds, setTemplateDeletePendingIds] = useState<Set<number>>(() => new Set());
  const [templateRunPendingId, setTemplateRunPendingId] = useState<number | null>(null);
  const [runCancelPendingIds, setRunCancelPendingIds] = useState<Set<number>>(() => new Set());
  const [templateSubmitting, setTemplateSubmitting] = useState(false);
  const templateSubmittingRef = useRef(false);
  const [templateForm] = Form.useForm<TemplateFormValues>();
  const watchTaskType = Form.useWatch('task_type', templateForm);

  const currentProjectIdRef = useRef(projectId);
  currentProjectIdRef.current = projectId;
  const scopeRequestRef = useRef<globalThis.AbortController | null>(null);
  const scopeCatalogRequestRef = useRef<globalThis.AbortController | null>(null);
  const templateRequestRef = useRef<globalThis.AbortController | null>(null);
  const exposureRequestRef = useRef<globalThis.AbortController | null>(null);

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

  const fetchTemplates = useCallback(async (showLoading = false) => {
    templateRequestRef.current?.abort();
    const controller = new window.AbortController();
    templateRequestRef.current = controller;
    if (showLoading) setTemplatesLoading(true);
    try {
      const res = await listTaskTemplates(projectId, { pageNumber: templatePageNumber, pageSize: templatePageSize, signal: controller.signal });
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
    setTemplatePageNumber(1);
    setRunPageNumber(1);
    setExposurePageNumber(1);
    setScopeCatalog([]);
    setScopeOpen(false);
    setEditScopeId(null);
    setTemplateOpen(false);
    setEditTemplateId(null);
  }, [projectId]);

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
    { title: 'Scope', dataIndex: 'name' },
    {
      title: '状态',
      dataIndex: 'status',
      render: (_, row) => {
        const unavailableReason = scopeUnavailableReason(row, scopeNow);
        return (
          <Space size={4}>
            <Tag color={row.status === 'active' ? 'green' : 'default'}>{row.status}</Tag>
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
              {target.match_mode}:{target.value}
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
              targets: row.targets.map(({ target_type, match_mode, value }) => ({ target_type, match_mode, value }))
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
              setScopes((current) => replaceItem(current, updated));
              setScopeCatalog((current) => replaceItem(current, updated));
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
    const reason = scopeUnavailableReason(scope, scopeNow);
    return {
      value: scope.id,
      label: reason ? `${scope.name}（${reason}）` : scope.name,
      disabled: Boolean(reason)
    };
  }), [availableScopes, scopeNow]);

  const scopesById = useMemo(() => new Map(availableScopes.map((scope) => [scope.id, scope])), [availableScopes]);

  const templateColumns = useMemo<ProColumns<TaskTemplate>[]>(() => [
    { title: '模板', dataIndex: 'name' },
    { title: '类型', dataIndex: 'task_type' },
    {
      title: 'Scope',
      dataIndex: 'scope_id',
      render: (_, row) => {
        const scope = scopesById.get(row.scope_id);
        const reason = scope ? scopeUnavailableReason(scope, scopeNow) : '不存在';
        return (
          <Space size={4}>
            <span>{scope?.name ?? `#${row.scope_id}`}</span>
            {reason && <Tag color="warning">{reason}</Tag>}
          </Space>
        );
      }
    },
    { title: '调度', dataIndex: 'schedule', render: (_, row) => row.schedule || '手动' },
    { title: '并发', dataIndex: 'concurrency' },
    { title: '速率/分钟', dataIndex: 'rate_limit' },
    { title: '重试', dataIndex: 'retry_limit' },
    { title: '状态', dataIndex: 'enabled', render: (_, row) => <Tag color={row.enabled ? 'green' : 'default'}>{row.enabled ? 'enabled' : 'disabled'}</Tag> },
    {
      title: '操作',
      valueType: 'option',
      render: (_, row) => {
        const canRun = can(Permission.DiscoveryRun);
        const scope = scopesById.get(row.scope_id);
        const scopeReason = scope ? scopeUnavailableReason(scope, scopeNow) : '关联 Scope 不存在';
        const triggerReason = !row.enabled ? '模板未启用' : scopeReason;
        const editable = isEditableTaskType(row.task_type);
        return [
          canRun && (
            <Tooltip key="run" title={triggerReason || undefined}>
              <span>
                <Button
                  aria-label={`触发 ${row.name}`}
                  icon={<Play size={14} />}
                  size="small"
                  type="link"
                  disabled={Boolean(triggerReason) || templateRunPendingId !== null}
                  loading={templateRunPendingId === row.id}
                  onClick={async () => {
                    const operationProjectId = projectId;
                    const liveScope = scopesById.get(row.scope_id);
                    const liveScopeReason = liveScope ? scopeUnavailableReason(liveScope) : '关联 Scope 不存在';
                    if (!row.enabled || liveScopeReason) {
                      message.error(`当前模板不可触发：${!row.enabled ? '模板未启用' : liveScopeReason}`);
                      return;
                    }
                    if (templateRunPendingId !== null) return;
                    setTemplateRunPendingId(row.id);
                    try {
                      const created = await triggerTaskRun(projectId, row.id);
                      if (currentProjectIdRef.current !== operationProjectId) return;
                      setRunPageNumber(1);
                      if (runPageNumber === 1) {
                        setRuns((current) => [created, ...current.filter((item) => item.id !== created.id)].slice(0, runPageSize));
                      }
                      setRunsTotal((current) => current + 1);
                      message.success('任务已触发');
                      setPollTrigger(v => v + 1);
                    } catch (err) {
                      if (currentProjectIdRef.current === operationProjectId) message.error(errorMessage(err));
                    } finally {
                      setTemplateRunPendingId(null);
                    }
                  }}
                >
                  触发
                </Button>
              </span>
            </Tooltip>
          ),
          canRun && (
            <Tooltip key="edit" title={editable ? undefined : `暂不支持编辑 ${row.task_type} 类型`}>
              <span>
                <Button
                  aria-label={`编辑 ${row.name}`}
                  size="small"
                  type="link"
                  disabled={!editable}
                  onClick={() => {
                    if (!isEditableTaskType(row.task_type)) return;
                    setEditTemplateId(row.id);
                    templateForm.setFieldsValue({
                      name: row.name,
                      task_type: row.task_type,
                      scope_id: row.scope_id,
                      max_results: row.config?.options?.max_results || 1000,
                      sources: row.config?.options?.sources?.filter((source) => source === 'fofa').length
                        ? row.config.options.sources.filter((source) => source === 'fofa')
                        : ['fofa'],
                      record_types: row.config?.options?.record_types || ['A', 'AAAA', 'CNAME'],
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
                const liveScopeReason = liveScope ? scopeUnavailableReason(liveScope) : '关联 Scope 不存在';
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
  ], [can, fetchTemplates, message, projectId, runPageNumber, runPageSize, scopeNow, scopesById, templateDeletePendingIds, templateForm, templatePageNumber, templateRunPendingId, templates.length, templatesTotal, templateStatusPendingIds]);

  const runColumns = useMemo<ProColumns<TaskRun>[]>(() => [
    { title: 'Run ID', dataIndex: 'id' },
    { title: '引擎 Job', dataIndex: 'engine_job_id' },
    { title: '类型', dataIndex: 'task_type' },
    { title: '状态', dataIndex: 'status', render: (_, row) => <Tag color={runColor(row.status)}>{row.status}</Tag> },
    { title: '进度', dataIndex: 'progress', render: (_, row) => <Progress percent={row.progress} size="small" /> },
    { title: '结果数', dataIndex: 'result_count' },
    { title: '最后回调', dataIndex: 'last_callback_at', valueType: 'dateTime' },
    { title: '错误摘要', dataIndex: 'error_summary', ellipsis: true },
    {
      title: '操作',
      valueType: 'option',
      render: (_, row) =>
        can(Permission.DiscoveryRun) && ['pending', 'running'].includes(row.status) ? [
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
        ] : []
    }
  ], [can, message, projectId, runCancelPendingIds]);

  const exposureColumns = useMemo<ProColumns<Exposure>[]>(() => [
    { title: '暴露面', dataIndex: 'name' },
    { title: '类型', dataIndex: 'exposure_type', valueType: 'select', valueEnum: { port: 'Port', service: 'Service', web: 'Web', certificate: 'Certificate', cloud_config: 'Cloud Config' } },
    { title: '端点', dataIndex: 'url', render: (_, row) => row.url || row.value || `${row.protocol}://${row.port}`, ellipsis: true },
    { title: '来源', dataIndex: 'source' },
    { title: '最近发现', dataIndex: 'last_seen', valueType: 'dateTime' }
  ], []);

  const exposureStats = useMemo(
    () => ['port', 'service', 'web', 'certificate', 'cloud_config'].map((type) => ({ type, count: exposures.filter((item) => item.exposure_type === type).length })),
    [exposures]
  );

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
        targets: values.targets.map(({ target_type, match_mode, value }) => ({ target_type, match_mode, value: value.trim() }))
      };
      const wasEditing = editScopeId !== null;
      let savedScope: Scope;
      if (editScopeId) {
        savedScope = await updateScope(projectId, editScopeId, data);
        if (currentProjectIdRef.current !== operationProjectId) return;
        setScopes((current) => replaceItem(current, savedScope));
        setScopeCatalog((current) => replaceItem(current, savedScope));
      } else {
        savedScope = await createScope(projectId, data);
        if (currentProjectIdRef.current !== operationProjectId) return;
        setScopeCatalog((current) => [savedScope, ...current]);
        setScopesTotal((current) => current + 1);
        if (scopePageNumber === 1) {
          setScopes((current) => [savedScope, ...current].slice(0, scopePageSize));
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
    setTemplateSubmitting(true);
    const operationProjectId = projectId;
    try {
      const values = await templateForm.validateFields();

      const selectedScope = availableScopes.find(s => s.id === values.scope_id);
      const includeDomains = selectedScope?.targets.filter(t => t.target_type === 'domain' && t.match_mode === 'include') || [];
      const editedTemplate = editTemplateId ? templates.find((template) => template.id === editTemplateId) : undefined;

      if (!editTemplateId && selectedScope) {
        const unavailableReason = scopeUnavailableReason(selectedScope);
        if (unavailableReason) {
          message.error(`选中的 Scope ${unavailableReason}，不能用于新任务`);
          return;
        }
      }
      if (!editTemplateId && !selectedScope) {
        message.error('请选择有效的授权 Scope');
        return;
      }
      if (editTemplateId && !editedTemplate) {
        message.error('待编辑模板不存在，请刷新后重试');
        return;
      }

      const configTargets = editedTemplate?.config?.targets ?? includeDomains.map(t => ({ type: t.target_type, value: t.value }));
      if (configTargets.length === 0) {
        message.error('模板缺少可用的授权目标');
        return;
      }

      const config = {
        targets: configTargets,
        options: {
          profile: values.task_type === 'dns' ? ('resolve' as const) : ('subdomain_passive' as const),
          max_results: values.max_results,
          ...(values.task_type === 'dns' && values.record_types ? { record_types: values.record_types as Array<'A' | 'AAAA' | 'CNAME'> } : {}),
          ...(values.task_type === 'passive_intel' && values.sources ? { sources: values.sources } : {})
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
        setTemplateOpen(false);
        setEditTemplateId(null);
        setTemplatesTotal((current) => current + 1);
        if (templatePageNumber === 1) {
          setTemplates((current) => [savedTemplate, ...current].slice(0, templatePageSize));
        } else {
          setTemplatePageNumber(1);
        }
        message.success('模板已创建');
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

  return (
    <section className="page-surface">
      <PageHeader
        title="暴露发现"
        subtitle="授权范围、被动任务编排与结果追踪"
        summary={
          <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
            <Col xs={12} sm={6}>
              <div className="page-summary-stat" style={{ padding: '16px 20px', background: 'var(--asm-surface)', borderRadius: 8, border: '1px solid var(--asm-border)', boxShadow: 'var(--asm-shadow-soft)' }}>
                <Typography.Text type="secondary" style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                  <Shield size={14} /> 有效 Scope
                </Typography.Text>
                <Typography.Title level={3} style={{ margin: 0, color: 'var(--asm-primary)' }}>{availableScopes.filter((scope) => !scopeUnavailableReason(scope, scopeNow)).length}</Typography.Title>
              </div>
            </Col>
            <Col xs={12} sm={6}>
              <div className="page-summary-stat" style={{ padding: '16px 20px', background: 'var(--asm-surface)', borderRadius: 8, border: '1px solid var(--asm-border)', boxShadow: 'var(--asm-shadow-soft)' }}>
                <Typography.Text type="secondary" style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                  <Target size={14} /> 已启用模板
                </Typography.Text>
                <Typography.Title level={3} style={{ margin: 0, color: 'var(--asm-primary)' }}>{templates.filter(t => t.enabled).length}</Typography.Title>
              </div>
            </Col>
            <Col xs={12} sm={6}>
              <div className="page-summary-stat" style={{ padding: '16px 20px', background: 'var(--asm-surface)', borderRadius: 8, border: '1px solid var(--asm-border)', boxShadow: 'var(--asm-shadow-soft)' }}>
                <Typography.Text type="secondary" style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                  <Activity size={14} /> 运行中任务
                </Typography.Text>
                <Typography.Title level={3} style={{ margin: 0, color: 'var(--asm-high)' }}>{runs.filter(r => r.status === 'running').length}</Typography.Title>
              </div>
            </Col>
            <Col xs={12} sm={6}>
              <div className="page-summary-stat" style={{ padding: '16px 20px', background: 'var(--asm-surface)', borderRadius: 8, border: '1px solid var(--asm-border)', boxShadow: 'var(--asm-shadow-soft)' }}>
                <Typography.Text type="secondary" style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                  <Database size={14} /> 总暴露面数
                </Typography.Text>
                <Typography.Title level={3} style={{ margin: 0, color: 'var(--asm-good)' }}>{exposuresTotal}</Typography.Title>
              </div>
            </Col>
          </Row>
        }
      />
      <div style={{ padding: '0 24px 24px' }}>
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        className="beautiful-tabs"
        items={[
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
                      scopeForm.resetFields();
                      scopeForm.setFieldsValue({
                        status: 'inactive',
                        targets: [{ target_type: 'domain', match_mode: 'include', value: '' }]
                      });
                      setScopeOpen(true);
                    }}>
                      新建 Scope
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
            key: 'tasks',
            label: <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><FileText size={16} /> 任务模板</span>,
            children: (
              <Space direction="vertical" size={18} className="full-width">
                <StateView loading={templatesLoading} error={templatesError?.message} permissionDenied={templatesError?.status === 403} onRetry={() => fetchTemplates(true)}>
                  <div className="page-heading" style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <Typography.Title level={4} style={{ margin: 0 }}>任务模板</Typography.Title>
                    {can(Permission.DiscoveryRun) && (
                      <Button icon={<Plus size={16} />} type="primary" onClick={() => {
                        setEditTemplateId(null);
                        templateForm.resetFields();
                        templateForm.setFieldsValue({ max_results: 1000, concurrency: 10, rate_limit: 200, timeout_seconds: 1800, retry_limit: 3, schedule: '', sources: ['fofa'], record_types: ['A', 'AAAA', 'CNAME'] });
                        setTemplateOpen(true);
                      }}>
                        新建模板
                      </Button>
                    )}
                  </div>
                  <ProTable<TaskTemplate>
                    className="surface-table"
                    rowKey="id"
                    columns={templateColumns}
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

                <StateView loading={runsLoading} error={runsError?.message} permissionDenied={runsError?.status === 403} onRetry={() => setPollTrigger((current) => current + 1)}>
                  <Typography.Title level={4} style={{ margin: 0, marginTop: 16, marginBottom: 8 }}>执行记录</Typography.Title>
                  <ProTable<TaskRun>
                    className="surface-table"
                    rowKey="id"
                    columns={runColumns}
                    dataSource={runs}
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
                  <Row gutter={[16, 16]}>
                    {exposureStats.map((item) => (
                      <Col xs={12} sm={6} key={item.type}>
                        <StatCard
                          label={`${item.type}（当前页）`}
                          value={item.count}
                          icon={exposureIcon[item.type]}
                          tone="neutral"
                        />
                      </Col>
                    ))}
                  </Row>
                  <ProTable<Exposure>
                    className="surface-table"
                    rowKey="id"
                    columns={exposureColumns}
                    dataSource={exposures}
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
        title={editScopeId ? '编辑 Scope' : '新建 Scope'}
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
        afterClose={() => scopeForm.resetFields()}
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
            <Select options={[
              { value: 'inactive', label: '暂不启用（推荐）' },
              { value: 'active', label: '创建后立即启用' }
            ]} />
          </Form.Item>
          <Form.Item name="valid_from" label="生效时间" rules={[
            { required: true }
          ]}>
            <DatePicker showTime format="YYYY-MM-DDTHH:mm:ssZ" style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="valid_until" label="失效时间" rules={[
            { required: true },
            ({ getFieldValue }) => ({
              validator(_, value) {
                if (!value || !getFieldValue('valid_from')) return Promise.resolve();
                const from = getFieldValue('valid_from');
                const fromTime = typeof from === 'string' ? new Date(from).getTime() : (from?.valueOf ? from.valueOf() : new Date(from).getTime());
                const untilTime = typeof value === 'string' ? new Date(value).getTime() : (value?.valueOf ? value.valueOf() : new Date(value).getTime());
                if (untilTime <= fromTime) {
                  return Promise.reject(new Error('失效时间必须晚于生效时间'));
                }
                return Promise.resolve();
              },
            })
          ]}>
            <DatePicker showTime format="YYYY-MM-DDTHH:mm:ssZ" style={{ width: '100%' }} />
          </Form.Item>
          <Divider orientation="left" plain>授权目标</Divider>
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
                  <Space.Compact key={field.key} className="full-width">
                    <Form.Item name={[field.name, 'target_type']} rules={[{ required: true }]} style={{ width: 120 }}>
                      <Select
                        aria-label={`目标类型 ${index + 1}`}
                        options={[
                          { value: 'domain', label: 'Domain' },
                          { value: 'ip', label: 'IP' },
                          { value: 'cidr', label: 'CIDR' },
                          { value: 'url', label: 'URL' }
                        ]}
                      />
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
                    <Form.Item
                      name={[field.name, 'value']}
                      dependencies={[['targets', field.name, 'target_type']]}
                      rules={[
                        { required: true, max: 512 },
                        {
                          validator(_, value?: string) {
                            const targetType = scopeForm.getFieldValue(['targets', field.name, 'target_type']) as ScopeTarget['target_type'] | undefined;
                            const validationError = scopeTargetValidationError(targetType, value);
                            return validationError ? Promise.reject(new Error(validationError)) : Promise.resolve();
                          }
                        }
                      ]}
                      style={{ flex: 1 }}
                    >
                      <Input aria-label={`目标值 ${index + 1}`} placeholder="example.com" />
                    </Form.Item>
                    <Button
                      aria-label={`删除目标 ${index + 1}`}
                      icon={<Trash2 size={15} />}
                      disabled={fields.length === 1}
                      onClick={() => remove(field.name)}
                    />
                  </Space.Compact>
                ))}
                <Button
                  block
                  icon={<Plus size={15} />}
                  type="dashed"
                  onClick={() => add({ target_type: 'domain', match_mode: 'include', value: '' })}
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
        className="surface-card"
        title={editTemplateId ? '编辑模板' : '新建发现模板'}
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
        onOk={submitTemplate}
        okText="保存模板"
      >
        <Form form={templateForm} layout="vertical" disabled={templateSubmitting} initialValues={{ max_results: 1000, concurrency: 10, rate_limit: 200, timeout_seconds: 1800, retry_limit: 3, schedule: '' }}>
          <Divider orientation="left" plain style={{ margin: '0 0 16px' }}>基本信息</Divider>
          <Form.Item name="name" label="模板名称" rules={[{ required: true, max: 64 }]}>
            <Input placeholder="请输入模板名称" />
          </Form.Item>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="task_type" label="任务类型" rules={[{ required: true }]}>
                <Select disabled={!!editTemplateId} options={[
                  { value: 'passive_intel', label: '被动子域发现' },
                  { value: 'dns', label: 'DNS' }
                ]} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="scope_id" label="授权 Scope" rules={[{ required: true }]}>
                <Select disabled={!!editTemplateId} options={scopeOptions} />
              </Form.Item>
            </Col>
          </Row>

          <Divider orientation="left" plain style={{ margin: '8px 0 16px' }}>任务配置</Divider>
          {watchTaskType === 'passive_intel' && (
            <Form.Item
              name="sources"
              label="数据源 (sources)"
              rules={[
                { required: true },
                {
                  validator: (_, sources?: string[]) => sources?.every((source) => source === 'fofa')
                    ? Promise.resolve()
                    : Promise.reject(new Error('只能选择当前已配置的数据源'))
                }
              ]}
            >
              <Select mode="multiple" placeholder="选择已配置的数据源" options={PASSIVE_SOURCE_OPTIONS} />
            </Form.Item>
          )}

          {watchTaskType === 'dns' && (
            <Form.Item name="record_types" label="记录类型 (record_types)" rules={[{ required: true }]}>
              <Select mode="multiple" options={[{ value: 'A', label: 'A' }, { value: 'AAAA', label: 'AAAA' }, { value: 'CNAME', label: 'CNAME' }]} />
            </Form.Item>
          )}

          <Form.Item name="max_results" label="最大结果数" rules={[{ required: true }]}>
            <InputNumber min={1} max={10000} style={{ width: '100%' }} />
          </Form.Item>

          <Form.Item
            name="schedule"
            label="调度周期（可选）"
            rules={[
              { max: 255 },
              {
                validator: (_, value?: string) => isValidSchedule(value)
                  ? Promise.resolve()
                  : Promise.reject(new Error('请输入 5 段 cron、@hourly 等别名或 @every 30s 格式'))
              }
            ]}
          >
            <Input placeholder="例如 0 2 * * * 或 @every 30m" />
          </Form.Item>

          <Divider orientation="left" plain style={{ margin: '8px 0 16px' }}>调度与限制</Divider>
          <Row gutter={16}>
            <Col span={6}>
              <Form.Item name="concurrency" label="并发数" rules={[{ required: true }]}>
                <InputNumber min={1} max={50} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item name="rate_limit" label="速率 (次/分)" rules={[{ required: true }]}>
                <InputNumber min={10} max={2000} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item name="timeout_seconds" label="超时 (秒)" rules={[{ required: true }]}>
                <InputNumber min={60} max={10800} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item name="retry_limit" label="重试次数" rules={[{ required: true }]}>
                <InputNumber min={0} max={100} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Modal>
    </section>
  );
}
