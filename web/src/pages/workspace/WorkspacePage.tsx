import { Button, Empty, Progress, Space, Table, Tag } from 'antd';
import { ArrowRight, ClipboardList, FolderKanban, Plus, Server, ShieldAlert, TimerReset } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { getWorkspaceSummary, type WorkspaceSummary } from '../../api/workspace';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StateView } from '../../components/StateView';
import { StatCard } from '../../components/StatCard';

const statusColor = { draft: 'gold', active: 'green', suspended: 'orange', archived: 'default' } as const;

export function WorkspacePage() {
  const navigate = useNavigate();
  const { can } = usePermission();
  const [summary, setSummary] = useState<WorkspaceSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setSummary(await getWorkspaceSummary());
    } catch (err) {
      setError(err instanceof Error ? err.message : '工作台加载失败');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const activeRate = useMemo(() => {
    if (!summary?.projects.total) return 0;
    return Math.round((summary.projects.active / summary.projects.total) * 100);
  }, [summary]);

  return (
    <section className="page-surface">
      <StateView loading={loading} error={error} onRetry={load}>
        <PageHeader
          title="全局工作台"
          subtitle="跨项目查看暴露面规模、风险与处置状态"
          actions={<Space>
            <Button icon={<FolderKanban size={16} />} onClick={() => navigate('/projects')}>项目列表</Button>
            {can(Permission.ProjectCreate) ? <Button type="primary" icon={<Plus size={16} />} onClick={() => navigate('/projects/new')}>创建项目</Button> : null}
          </Space>}
        />
        {summary && summary.projects.total === 0 ? (
          <div className="workspace-empty">
            <Empty description={can(Permission.ProjectCreate) ? '还没有项目，先创建项目并配置授权范围。' : '尚未分配可访问项目。'}>
              {can(Permission.ProjectCreate) ? <Button type="primary" icon={<Plus size={16} />} onClick={() => navigate('/projects/new')}>创建第一个项目</Button> : null}
            </Empty>
          </div>
        ) : summary ? (
          <>
            <div className="metric-grid metric-grid--5">
              <StatCard label="可访问项目" value={summary.projects.total} icon={<FolderKanban size={18} />} tone="neutral" />
              <StatCard label="资产总量" value={summary.assets.total} icon={<Server size={18} />} tone="neutral" />
              <StatCard label="开放风险" value={summary.risks.open} icon={<ShieldAlert size={18} />} tone={summary.risks.open ? 'high' : 'good'} />
              <StatCard label="高危风险" value={summary.risks.critical_high} icon={<TimerReset size={18} />} tone={summary.risks.critical_high ? 'critical' : 'good'} />
              <StatCard label="开放工单" value={summary.tickets.open} icon={<ClipboardList size={18} />} tone={summary.tickets.overdue ? 'high' : 'neutral'} />
            </div>
            <div className="workspace-status-band">
              <div>
                <strong>项目运行状态</strong>
                <span>运行中 {summary.projects.active} · 草稿 {summary.projects.draft} · 已暂停 {summary.projects.suspended}</span>
              </div>
              <Progress percent={activeRate} strokeColor="#1677ff" trailColor="#e8eef7" />
              <div className="workspace-status-alerts">
                <span>超期风险 <strong>{summary.risks.overdue}</strong></span>
                <span>超期工单 <strong>{summary.tickets.overdue}</strong></span>
              </div>
            </div>
            <div className="workspace-section-head">
              <div><strong>最近项目</strong><span>按更新时间排列</span></div>
              <Button type="link" onClick={() => navigate('/projects')}>查看全部</Button>
            </div>
            <Table
              rowKey="id"
              size="middle"
              pagination={false}
              dataSource={summary.recent_projects}
              columns={[
                { title: '项目', dataIndex: 'name', render: (name, row) => <Space direction="vertical" size={0}><strong>{name}</strong><span className="secondary-text">{row.project_code}</span></Space> },
                { title: '业务单元', dataIndex: 'business_unit' },
                { title: '状态', dataIndex: 'status', render: (status) => <Tag color={statusColor[status as keyof typeof statusColor]}>{status}</Tag> },
                { title: '更新时间', dataIndex: 'updated_at', render: (value) => new Date(value).toLocaleString() },
                { title: '', width: 64, render: (_, row) => <Button type="text" aria-label={`进入${row.name}`} icon={<ArrowRight size={16} />} onClick={() => navigate(`/projects/${row.id}/overview`)} /> }
              ]}
            />
          </>
        ) : null}
      </StateView>
    </section>
  );
}
