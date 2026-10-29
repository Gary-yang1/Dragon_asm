import { Alert, Button } from 'antd';
import { Archive, LockKeyhole, PauseCircle } from 'lucide-react';
import { cloneElement, type ReactElement } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { Permission } from '../auth/permissions';
import { useProjectWorkspace } from '../projects/ProjectContext';

type GateChildProps = {
  disabled?: boolean;
  tabIndex?: number;
};

const onboardingLabels: Record<string, string> = {
  project_owner: '项目负责人',
  primary_subject: '主主体',
  primary_domain_or_seed_scope: '主域名或种子授权范围',
  valid_scope: '有效授权范围'
};

function activationTarget(projectId: number, pathname: string, search: string) {
  const params = new globalThis.URLSearchParams({ focus: 'activation' });
  const profilePath = `/projects/${projectId}/profile`;
  if (pathname !== profilePath) {
    params.set('returnTo', `${pathname}${search}`);
  }
  return `${profilePath}?${params.toString()}`;
}

function missingDescription(missing: string[]) {
  return missing.map((item) => onboardingLabels[item] ?? item).join('、');
}

export function ProjectStatusBanner() {
  const navigate = useNavigate();
  const location = useLocation();
  const { projectId, projectStatus, capabilities, loading, error } = useProjectWorkspace();

  if (!projectId || loading || error || !projectStatus || projectStatus === 'active') return null;
  if (location.pathname === `/projects/${projectId}/profile`) return null;

  const missing = capabilities?.onboarding_missing ?? [];
  const canWrite = capabilities?.permissions.includes(Permission.ProjectWrite) ?? false;
  const target = activationTarget(projectId, location.pathname, location.search);

  if (projectStatus === 'archived') {
    return (
      <div className="project-status-banner" role="status" aria-live="polite">
        <Alert
          type="info"
          showIcon
          icon={<Archive size={18} />}
          message="项目已归档"
          description="不能启动新的发现任务，历史资产、风险、工单和报表仍可查看。"
          action={<Button onClick={() => navigate(`/projects/${projectId}/profile`)}>查看项目资料</Button>}
        />
      </div>
    );
  }

  const suspended = projectStatus === 'suspended';
  const description = missing.length > 0
    ? `${suspended ? '恢复' : '激活'}前仍需完成：${missingDescription(missing)}。`
    : suspended
      ? '新发现任务不会下发；恢复项目后可以继续运行。'
      : '项目已满足激活条件，激活后可以启动发现任务。';
  const actionLabel = capabilities?.can_activate
    ? (suspended ? '前往恢复项目' : '前往激活项目')
    : canWrite
      ? '完成激活配置'
      : '查看激活条件';

  return (
    <div className="project-status-banner" role="status" aria-live="polite">
      <Alert
        type={suspended ? 'warning' : 'info'}
        showIcon
        icon={suspended ? <PauseCircle size={18} /> : <LockKeyhole size={18} />}
        message={suspended ? '项目已暂停' : '项目尚未激活'}
        description={description}
        action={<Button type="primary" onClick={() => navigate(target)}>{actionLabel}</Button>}
      />
    </div>
  );
}

export function ProjectActiveGate({
  children,
  actionLabel
}: {
  children: ReactElement<GateChildProps>;
  actionLabel: string;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const { projectId, projectStatus, loading, error } = useProjectWorkspace();

  if (projectStatus === 'active') return children;

  const lockedChild = cloneElement(children, { disabled: true, tabIndex: -1 });
  const canOpenActivation = !loading && !error && projectStatus !== null && projectStatus !== 'archived';
  const label = loading
    ? '检查状态'
    : error || projectStatus === null
      ? '状态不可用'
      : projectStatus === 'suspended'
        ? '需恢复'
        : projectStatus === 'archived'
          ? '已归档'
          : '需激活';
  const explanation = loading
    ? '正在检查项目状态'
    : error
      ? `项目状态加载失败：${error}`
      : projectStatus === null
        ? `项目状态不可用，暂时不能${actionLabel}`
        : projectStatus === 'archived'
          ? `项目已归档，不能${actionLabel}`
          : projectStatus === 'suspended'
            ? `项目已暂停，恢复后才能${actionLabel}`
            : `项目尚未激活，激活后才能${actionLabel}`;

  return (
    <span className="project-active-gate project-active-gate--compact" title={explanation}>
      <span className="project-active-gate-content" aria-hidden="true">{lockedChild}</span>
      {canOpenActivation ? (
        <button
          type="button"
          className="project-active-gate-overlay"
          aria-label={`${explanation}，前往项目资料`}
          onClick={() => navigate(activationTarget(projectId, location.pathname, location.search))}
        >
          <LockKeyhole size={12} aria-hidden="true" />
          <span>{label}</span>
        </button>
      ) : (
        <span className="project-active-gate-overlay project-active-gate-overlay--static" aria-label={explanation}>
          <LockKeyhole size={12} aria-hidden="true" />
          <span>{label}</span>
        </span>
      )}
    </span>
  );
}
