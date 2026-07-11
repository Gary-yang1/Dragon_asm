import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Badge, Button, Descriptions, Drawer, Space, Tag, Timeline, message } from 'antd';
import { ClipboardList, Clock, History, Inbox, RefreshCcw, ShieldCheck } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { getTicket, listTickets, submitRetest, transitionTicket, type Ticket, type TicketDetail } from '../../api/operations';
import { errorMessage } from '../../api/errorMessage';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StatCard } from '../../components/StatCard';
import { StateView } from '../../components/StateView';
import { useProjectId } from '../../projects/ProjectContext';

const statusColor: Record<string, string> = {
  open: 'blue',
  assigned: 'geekblue',
  in_progress: 'processing',
  pending_retest: 'warning',
  closed: 'green',
  rejected: 'default',
  cancelled: 'default'
};

export function TicketsPage() {
  const { can } = usePermission();
  const projectId = useProjectId();
  const [searchParams] = useSearchParams();
  const routeQuery = (searchParams.get('q') ?? '').trim();
  const [detail, setDetail] = useState<TicketDetail | null>(null);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [reloadKey, setReloadKey] = useState(0);
  const [totalTickets, setTotalTickets] = useState(0);
  const [ticketItems, setTicketItems] = useState<Ticket[]>([]);

  async function openDetail(row: Ticket) {
    setLoading(true);
    setDetailError('');
    setOpen(true);
    try {
      setDetail(await getTicket(projectId, row.id));
    } catch (error) {
      setDetail(null);
      setDetailError(errorMessage(error));
    } finally {
      setLoading(false);
    }
  }

  async function runAction(action: string) {
    if (!detail) return;
    setDetail(await transitionTicket(projectId, detail.id, action));
    setReloadKey((value) => value + 1);
    message.success('工单状态已更新');
  }

  async function retest() {
    if (!detail) return;
    setDetail(await submitRetest(projectId, detail.id));
    setReloadKey((value) => value + 1);
    message.success('已提交复测');
  }

  const columns = useMemo<ProColumns<Ticket>[]>(() => [
    { title: '工单', dataIndex: 'title' },
    { title: '状态', dataIndex: 'status', render: (_, row) => <Tag color={statusColor[row.status]}>{row.status}</Tag> },
    { title: '负责人', dataIndex: 'assignee' },
    { title: '风险数', dataIndex: 'risk_count', search: false, render: (_, row) => <Badge count={row.risk_count} style={{ backgroundColor: '#1677ff' }} /> },
    { title: 'SLA', dataIndex: 'sla_due_at', valueType: 'dateTime', search: false }
  ], []);

  const tableKey = routeQuery || 'tickets';

  function matchTicket(item: Ticket, keyword: string) {
    const normalized = keyword.toLowerCase();
    const candidate = `${item.title} ${item.assignee} ${item.status}`.toLowerCase();
    return candidate.includes(normalized);
  }

  const ticketKpis = useMemo(() => {
    const pendingRetest = ticketItems.filter((item) => item.status === 'pending_retest').length;
    const inProgress = ticketItems.filter((item) => ['open', 'assigned', 'in_progress'].includes(item.status)).length;
    return { total: totalTickets, pendingRetest, inProgress };
  }, [ticketItems, totalTickets]);

  return (
    <section className="page-surface">
      <PageHeader
        title="工单中心"
        subtitle="协同跟进风险修复进度和复测流程"
        summary={
          <div className="metric-grid metric-grid--3">
            <StatCard label="工单总数" value={ticketKpis.total} icon={<ClipboardList size={18} />} tone="neutral" />
            <StatCard label="处理中" value={ticketKpis.inProgress} icon={<Inbox size={18} />} tone={ticketKpis.inProgress > 0 ? 'high' : 'good'} hint="当前视图" />
            <StatCard label="待复测" value={ticketKpis.pendingRetest} icon={<Clock size={18} />} tone={ticketKpis.pendingRetest > 0 ? 'high' : 'good'} hint="当前视图" />
          </div>
        }
      />
      <ProTable<Ticket>
        key={`${reloadKey}-${tableKey}`}
        rowKey="id"
        columns={columns}
        search={false}
        options={false}
        className="surface-table"
        request={async (params) => {
          const keyword = typeof params.keyword === 'string' && params.keyword.trim() ? params.keyword.trim() : routeQuery;
          const page = await listTickets(projectId);
          const items = keyword ? page.items.filter((item) => matchTicket(item, keyword)) : page.items;
          setTicketItems(items);
          setTotalTickets(keyword ? items.length : page.total);
          return { data: items, total: keyword ? items.length : page.total, success: true };
        }}
        pagination={{ pageSize: 20 }}
        onRow={(record) => ({ onClick: () => void openDetail(record) })}
      />
      <Drawer title="工单详情" open={open} onClose={() => setOpen(false)} width={760}>
        <StateView loading={loading} error={detailError} empty={!detail}>
          {detail ? (
            <Space direction="vertical" size={18} className="full-width">
              <div className="detail-banner">
                <div className="detail-banner-main">
                  <Tag color={statusColor[detail.status]} className="detail-banner-severity">{detail.status}</Tag>
                  <div className="detail-banner-title">{detail.title}</div>
                </div>
                <div className="detail-banner-meta">
                  <div className="detail-banner-meta-item">
                    <span className="detail-banner-meta-label">负责人</span>
                    <span>{detail.assignee || '-'}</span>
                  </div>
                  <div className="detail-banner-meta-item">
                    <span className="detail-banner-meta-label">关联风险</span>
                    <Badge count={detail.risk_count} style={{ backgroundColor: '#1677ff' }} />
                  </div>
                </div>
              </div>
              <Space wrap>
                {can(Permission.TicketWrite)
                  ? detail.available_actions.map((action, index) => (
                      <Button key={action} type={index === 0 ? 'primary' : 'default'} onClick={() => void runAction(action)}>
                        {action}
                      </Button>
                    ))
                  : null}
                {can(Permission.TicketWrite) ? (
                  <Button icon={<RefreshCcw size={16} />} onClick={() => void retest()}>
                    提交复测
                  </Button>
                ) : null}
              </Space>
              <Descriptions title={<div className="card-title-row"><ShieldCheck size={16} /><span>关联风险</span></div>} bordered size="small" column={1}>
                {detail.risks.map((risk) => (
                  <Descriptions.Item key={risk.id} label={risk.severity}>{risk.title}</Descriptions.Item>
                ))}
              </Descriptions>
              <div className="card-title-row drawer-section-title"><History size={16} /><span>协作记录</span></div>
              <Timeline items={detail.comments.map((item) => ({ children: `${item.created_at} · ${item.actor} · ${item.content}` }))} />
            </Space>
          ) : null}
        </StateView>
      </Drawer>
    </section>
  );
}
