import { Button, Space, Table, Tag } from 'antd';
import { ArrowRight, ClipboardCheck, ShieldAlert, TimerReset } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { listProjects, type Project } from '../../api/projects';
import { getWorkspaceSummary, type WorkspaceSummary } from '../../api/workspace';
import { PageHeader } from '../../components/PageHeader';
import { StateView } from '../../components/StateView';
import { StatCard } from '../../components/StatCard';

export function WorkItemsPage() {
  const navigate = useNavigate();
  const [summary, setSummary] = useState<WorkspaceSummary | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [workspace, projectPage] = await Promise.all([getWorkspaceSummary(), listProjects(1, 100)]);
      setSummary(workspace);
      setProjects(projectPage.items.filter((project) => project.status !== 'archived'));
    } catch (err) {
      setError(err instanceof Error ? err.message : '待办加载失败');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <section className="page-surface">
      <StateView loading={loading} error={error} empty={!loading && projects.length === 0} emptyText="尚未分配可处理项目" onRetry={load}>
        <PageHeader title="我的待办" subtitle="从可访问项目进入风险研判与工单处置" />
        {summary ? <div className="metric-grid metric-grid--4">
          <StatCard label="开放风险" value={summary.risks.open} icon={<ShieldAlert size={18} />} tone={summary.risks.open ? 'high' : 'good'} />
          <StatCard label="高危风险" value={summary.risks.critical_high} icon={<TimerReset size={18} />} tone={summary.risks.critical_high ? 'critical' : 'good'} />
          <StatCard label="开放工单" value={summary.tickets.open} icon={<ClipboardCheck size={18} />} tone="neutral" />
          <StatCard label="超期工单" value={summary.tickets.overdue} icon={<TimerReset size={18} />} tone={summary.tickets.overdue ? 'high' : 'good'} />
        </div> : null}
        <Table
          rowKey="id"
          dataSource={projects}
          pagination={{ pageSize: 10 }}
          columns={[
            { title: '项目', dataIndex: 'name', render: (name, row) => <Space direction="vertical" size={0}><strong>{name}</strong><span className="secondary-text">{row.project_code}</span></Space> },
            { title: '业务单元', dataIndex: 'business_unit' },
            { title: '状态', dataIndex: 'status', render: (status) => <Tag>{status}</Tag> },
            { title: '处理入口', render: (_, row) => <Space><Button onClick={() => navigate(`/projects/${row.id}/risks`)}>风险</Button><Button onClick={() => navigate(`/projects/${row.id}/tickets`)}>工单</Button><Button type="text" aria-label={`进入${row.name}`} icon={<ArrowRight size={16} />} onClick={() => navigate(`/projects/${row.id}/overview`)} /></Space> }
          ]}
        />
      </StateView>
    </section>
  );
}
