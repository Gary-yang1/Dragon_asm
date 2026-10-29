import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Alert, Button, Descriptions, Drawer, Space, Timeline, message } from 'antd';
import { ClipboardList, Clock, History, Inbox, ShieldCheck } from 'lucide-react';
import { useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { getTicket, listTickets, transitionTicket, type Ticket, type TicketDetail } from '../../api/operations';
import { errorMessage } from '../../api/errorMessage';
import { EnumChip } from '../../components/StatusChip';
import { describe, priorityMeta, ticketActionMeta, ticketStatusMeta } from '../../utils/taxonomy';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StatCard } from '../../components/StatCard';
import { StateView } from '../../components/StateView';
import { useProjectId } from '../../projects/ProjectContext';

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
  const [listError, setListError] = useState('');

  // Discards a slow response for a previously clicked row (see requestedTicketRef).
  const requestedTicketRef = useRef<number>(0);

  async function openDetail(row: Ticket) {
    requestedTicketRef.current = row.id;
    setLoading(true);
    setDetailError('');
    setOpen(true);
    try {
      const ticket = await getTicket(projectId, row.id);
      if (requestedTicketRef.current !== row.id) return;
      setDetail(ticket);
    } catch (error) {
      if (requestedTicketRef.current !== row.id) return;
      setDetail(null);
      setDetailError(errorMessage(error));
    } finally {
      if (requestedTicketRef.current === row.id) setLoading(false);
    }
  }

  // Both paths surface failures: a denied action returns 403 and a missing field
  // 400, and without this the modal simply sat there doing nothing.
  async function runAction(action: string) {
    if (!detail) return;
    try {
      setDetail(await transitionTicket(projectId, detail.id, action));
      setReloadKey((value) => value + 1);
      message.success('工单状态已更新');
    } catch (error) {
      message.error(errorMessage(error));
    }
  }

  const columns = useMemo<ProColumns<Ticket>[]>(() => [
    { title: '工单', dataIndex: 'title' },
    { title: '状态', dataIndex: 'status', render: (_, row) => <EnumChip map={ticketStatusMeta} value={row.status} /> },
    { title: '负责人', dataIndex: 'assignee' },
    { title: '优先级', dataIndex: 'priority', search: false, render: (_, row) => <EnumChip map={priorityMeta} value={row.priority} dot /> },
    // The API field is due_at; 'sla_due_at' rendered an always-empty column.
    { title: 'SLA', dataIndex: 'due_at', valueType: 'dateTime', search: false }
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
      {listError ? (
        <Alert
          type="error"
          showIcon
          message="工单列表加载失败"
          description={listError}
          action={<Button size="small" onClick={() => setReloadKey((value) => value + 1)}>重试</Button>}
          className="list-error-alert"
        />
      ) : null}
      {routeQuery ? (
        <Alert
          type="info"
          showIcon
          message={`关键词「${routeQuery}」仅在当前页的 ${ticketItems.length} 条结果内匹配`}
          description="服务端尚不支持工单关键词检索，跨页结果不会被匹配。"
          className="list-error-alert"
        />
      ) : null}
      <ProTable<Ticket>
        key={`${reloadKey}-${tableKey}`}
        rowKey="id"
        columns={columns}
        search={false}
        options={false}
        className="surface-table"
        request={async (params) => {
          const keyword = typeof params.keyword === 'string' && params.keyword.trim() ? params.keyword.trim() : routeQuery;
          try {
            // Real server-side paging: the table used to request page 1 for every
            // page, so any project with more than one page had unreachable tickets.
            const page = await listTickets(projectId, params.pageSize ?? 20, params.current ?? 1);
            const items = keyword ? page.items.filter((item) => matchTicket(item, keyword)) : page.items;
            setTicketItems(items);
            // total stays the server's count so page navigation keeps working; the
            // keyword only narrows what is already loaded (see the hint below).
            setTotalTickets(page.total);
            setListError('');
            return { data: items, total: page.total, success: true };
          } catch (error) {
            setListError(errorMessage(error));
            return { data: [], total: 0, success: false };
          }
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
                  <span className="detail-banner-severity"><EnumChip map={ticketStatusMeta} value={detail.status} /></span>
                  <div className="detail-banner-title">{detail.title}</div>
                </div>
                <div className="detail-banner-meta">
                  <div className="detail-banner-meta-item">
                    <span className="detail-banner-meta-label">负责人</span>
                    <span>{detail.assignee || '-'}</span>
                  </div>
                  <div className="detail-banner-meta-item">
                    <span className="detail-banner-meta-label">SLA</span>
                    <span>{detail.due_at || '-'}</span>
                  </div>
                </div>
              </div>
              <Space wrap>
                {can(Permission.TicketWrite)
                  ? (detail.available_actions ?? []).map((action, index) => (
                      <Button key={action} type={index === 0 ? 'primary' : 'default'} onClick={() => void runAction(action)}>
                        {describe(ticketActionMeta, action).label}
                      </Button>
                    ))
                  : null}

              </Space>
              <Descriptions title={<div className="card-title-row"><ShieldCheck size={16} /><span>工单详情</span></div>} bordered size="small" column={1}>
                <Descriptions.Item label="描述">{detail.description || '-'}</Descriptions.Item>
                <Descriptions.Item label="优先级"><EnumChip map={priorityMeta} value={detail.priority} dot /></Descriptions.Item>
                <Descriptions.Item label="业务单元">{detail.business_unit || '-'}</Descriptions.Item>
                <Descriptions.Item label="处置结论">{detail.resolution || '-'}</Descriptions.Item>
                <Descriptions.Item label="复测结果">{detail.retest_result || '-'}</Descriptions.Item>
                <Descriptions.Item label="外部工单">{detail.external_ticket_id || '-'}</Descriptions.Item>
              </Descriptions>
              <div className="card-title-row drawer-section-title"><History size={16} /><span>处置时间线</span></div>
              <Timeline
                items={[
                  detail.created_at ? { children: `${detail.created_at} · 创建` } : null,
                  detail.due_at ? { children: `${detail.due_at} · SLA 到期` } : null,
                  detail.closed_at ? { children: `${detail.closed_at} · 关闭` } : null,
                  detail.updated_at ? { children: `${detail.updated_at} · 最近更新` } : null
                ].filter((item): item is { children: string } => item !== null)}
              />
            </Space>
          ) : null}
        </StateView>
      </Drawer>
    </section>
  );
}
