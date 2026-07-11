import { ProTable, type ActionType, type ProColumns } from '@ant-design/pro-components';
import { Alert, Button, Empty, Input, Modal, Progress, Space, Tag, Tooltip, Typography, message } from 'antd';
import { Archive, ArrowRight, Plus, Settings2 } from 'lucide-react';
import { useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import {
  getOnboardingStatus,
  getProjectCapabilities,
  listProjects,
  transitionProject,
  type OnboardingStatus,
  type Project,
  type ProjectCapabilities
} from '../../api/projects';
import { errorMessage } from '../../api/errorMessage';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';

type ProjectRow = Project & {
  onboarding?: OnboardingStatus;
  capabilities?: ProjectCapabilities;
};

const statusMeta: Record<Project['status'], { label: string; color: string }> = {
  draft: { label: '草稿', color: 'gold' },
  active: { label: '运行中', color: 'green' },
  suspended: { label: '已暂停', color: 'orange' },
  archived: { label: '已归档', color: 'default' }
};

function onboardingPercent(project: ProjectRow) {
  if (project.status === 'active') return 100;
  const status = project.onboarding;
  if (!status) return 0;
  return [status.owner_configured, status.primary_subject_configured, status.primary_domain_configured, status.valid_scope_configured]
    .filter(Boolean).length * 25;
}

export function ProjectsPage() {
  const navigate = useNavigate();
  const { can } = usePermission();
  const actionRef = useRef<ActionType>();
  const [archiveTarget, setArchiveTarget] = useState<Project | null>(null);
  const [archiveReason, setArchiveReason] = useState('');
  const [saving, setSaving] = useState(false);

  async function activate(project: Project) {
    setSaving(true);
    try {
      await transitionProject(project.id, 'active');
      message.success(`${project.name} 已激活`);
      actionRef.current?.reload();
      globalThis.dispatchEvent(new Event('asm:projects-changed'));
    } catch (err) {
      message.error(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  async function archive() {
    if (!archiveTarget || !archiveReason.trim()) return;
    setSaving(true);
    try {
      await transitionProject(archiveTarget.id, 'archived', archiveReason.trim());
      message.success(`${archiveTarget.name} 已归档`);
      setArchiveTarget(null);
      setArchiveReason('');
      actionRef.current?.reload();
      globalThis.dispatchEvent(new Event('asm:projects-changed'));
    } catch (err) {
      message.error(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  const columns = useMemo<ProColumns<ProjectRow>[]>(() => [
    {
      title: '项目', dataIndex: 'name',
      render: (_, row) => <Space direction="vertical" size={0}><Typography.Text strong>{row.name}</Typography.Text><Typography.Text type="secondary">{row.project_code}</Typography.Text></Space>
    },
    { title: '业务单元', dataIndex: 'business_unit' },
    { title: '负责人', dataIndex: 'owner_user_id', search: false },
    { title: '重要性', dataIndex: 'criticality', valueType: 'select', valueEnum: { low: '低', medium: '中', high: '高', critical: '关键' } },
    { title: '状态', dataIndex: 'status', valueType: 'select', render: (_, row) => <Tag color={statusMeta[row.status].color}>{statusMeta[row.status].label}</Tag> },
    {
      title: '配置完成度', search: false, width: 150,
      render: (_, row) => <Progress percent={onboardingPercent(row)} size="small" status={row.onboarding?.ready_to_activate || row.status === 'active' ? 'success' : 'normal'} />
    },
    { title: '更新时间', dataIndex: 'updated_at', valueType: 'dateTime', search: false },
    {
      title: '操作', valueType: 'option', width: 260,
      render: (_, row) => {
        const permissions = row.capabilities?.permissions ?? [];
        return <Space onClick={(event) => event.stopPropagation()}>
          <Button type="link" icon={<ArrowRight size={15} />} onClick={() => navigate(`/projects/${row.id}/overview`)}>进入</Button>
          {row.status === 'draft' ? <Button type="link" icon={<Settings2 size={15} />} onClick={() => navigate(`/projects/${row.id}/profile`)}>继续配置</Button> : null}
          {row.capabilities?.can_activate ? <Button type="link" loading={saving} onClick={() => void activate(row)}>激活</Button> : null}
          {row.status !== 'archived' && permissions.includes(Permission.ProjectArchive) ? <Button type="text" danger aria-label={`归档${row.name}`} icon={<Archive size={15} />} onClick={() => setArchiveTarget(row)} /> : null}
        </Space>;
      }
    }
  ], [navigate, saving]);

  const createButton = can(Permission.ProjectCreate)
    ? <Button type="primary" icon={<Plus size={16} />} onClick={() => navigate('/projects/new')}>创建项目</Button>
    : <Tooltip title="当前角色没有项目创建权限"><span><Button disabled icon={<Plus size={16} />}>创建项目</Button></span></Tooltip>;

  return (
    <section className="page-surface">
      <PageHeader title="项目管理" subtitle="以项目为边界组织主体、主域名、授权范围和风险闭环" actions={createButton} />
      {!can(Permission.ProjectCreate) ? <Alert className="project-permission-notice" type="info" showIcon message="当前为项目只读视图，项目创建由系统管理员或安全管理员执行。" /> : null}
      <ProTable<ProjectRow>
        actionRef={actionRef}
        rowKey="id"
        columns={columns}
        search={{ labelWidth: 72 }}
        options={false}
        request={async (params) => {
          const page = await listProjects(params.current ?? 1, params.pageSize ?? 20);
          const data = await Promise.all(page.items.map(async (project) => {
            const [onboarding, capabilities] = await Promise.all([
              project.status === 'archived' ? undefined : getOnboardingStatus(project.id).catch(() => undefined),
              getProjectCapabilities(project.id).catch(() => undefined)
            ]);
            return { ...project, onboarding, capabilities };
          }));
          return { data, total: page.total, success: true };
        }}
        pagination={{ pageSize: 20 }}
        onRow={(record) => ({ onClick: () => navigate(`/projects/${record.id}/overview`) })}
        toolBarRender={false}
        locale={{
          emptyText: <Empty description={can(Permission.ProjectCreate) ? '还没有项目' : '尚未分配可访问项目'}>
            {can(Permission.ProjectCreate) ? <Button type="primary" icon={<Plus size={16} />} onClick={() => navigate('/projects/new')}>创建第一个项目</Button> : null}
          </Empty>
        }}
      />
      <Modal
        title={`归档项目${archiveTarget ? `：${archiveTarget.name}` : ''}`}
        open={Boolean(archiveTarget)}
        okText="确认归档"
        okButtonProps={{ danger: true, disabled: !archiveReason.trim(), loading: saving }}
        onOk={() => void archive()}
        onCancel={() => { setArchiveTarget(null); setArchiveReason(''); }}
      >
        <Alert type="warning" showIcon message="归档后项目不能重新激活，现有资产和历史记录仍会保留。" />
        <Input.TextArea className="archive-reason-input" rows={3} maxLength={512} value={archiveReason} onChange={(event) => setArchiveReason(event.target.value)} placeholder="填写归档原因" />
      </Modal>
    </section>
  );
}
