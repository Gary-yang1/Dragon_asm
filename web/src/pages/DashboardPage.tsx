import { Button, Card, Col, Row, Space, Tag, Timeline } from 'antd';
import { ArrowDownRight, ArrowUpRight, CalendarClock, Download, Inbox, RefreshCw, Server, ShieldAlert, ShieldCheck, Siren, TimerReset, TriangleAlert } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import {
  getDashboardReport,
  getReportRemediation,
  getReportTrend,
  type DashboardReport,
  type ReportRemediation,
  type ReportTrendResponse
} from '../api/operations';
import { errorMessage } from '../api/errorMessage';
import { Permission } from '../auth/permissions';
import { usePermission } from '../auth/usePermission';
import { PageHeader } from '../components/PageHeader';
import { StatCard, type StatCardTone } from '../components/StatCard';
import { StateView } from '../components/StateView';
import { useProjectId } from '../projects/ProjectContext';

type TrendPoint = {
  date: string;
  new: number;
  fixed: number;
};

function normalizeTrendPoint(item: ReportTrendResponse): TrendPoint {
  if ('day' in item) {
    return { date: item.day, new: item.new, fixed: item.fixed };
  }
  return { date: item.date, new: item.risks, fixed: item.fixed };
}

function trendFromItems(items: TrendPoint[]) {
  if (!items.length) return [];
  return items
    .slice()
    .sort((a, b) => a.date.localeCompare(b.date))
    .slice(-4)
    .map((item) => ({
      time: new Date(item.date).toLocaleDateString(),
      type: item.new >= item.fixed ? 'high' : 'low',
      title: `${item.date} 风险动态`,
      body: `新增 ${item.new} 条，修复 ${item.fixed} 条`,
      tag: item.new >= item.fixed ? '新增' : '修复'
    }));
}

export function DashboardPage() {
  const { can } = usePermission();
  const navigate = useNavigate();
  const projectId = useProjectId();

  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [dashboard, setDashboard] = useState<DashboardReport | null>(null);
  const [trendPoints, setTrendPoints] = useState<TrendPoint[]>([]);
  const [remediation, setRemediation] = useState<ReportRemediation | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const loadSummary = useCallback(async () => {
    setLoading(true);
    setLoadError('');
    try {
      const dashboardData = await getDashboardReport(projectId);
      const trendData = await getReportTrend(projectId).catch(() => []);
      const remediationData = await getReportRemediation(projectId).catch(() => null);

      setDashboard(dashboardData);
      setTrendPoints(trendData.map(normalizeTrendPoint));
      setRemediation(remediationData);
    } catch (error: unknown) {
      setLoadError(errorMessage(error));
      setDashboard(null);
      setTrendPoints([]);
      setRemediation(null);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    void loadSummary();
  }, [loadSummary, reloadKey]);

  const normalizedTrend = useMemo(() => trendFromItems(trendPoints), [trendPoints]);

  const updates = useMemo(
    () =>
      normalizedTrend.map((item) => ({
        color: item.type === 'high' ? 'red' : item.type === 'low' ? 'blue' : 'green',
        children: (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, paddingBottom: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <Tag color={item.type === 'high' ? 'red' : item.type === 'low' ? 'blue' : 'green'} style={{ margin: 0 }}>
                {item.tag}
              </Tag>
              <strong style={{ color: 'var(--asm-text)', fontSize: '13px' }}>{item.title}</strong>
              <span style={{ color: 'var(--asm-muted)', fontSize: '12px' }}>{item.time}</span>
            </div>
            <div style={{ color: 'var(--asm-muted)', fontSize: '12px' }}>{item.body}</div>
          </div>
        )
      })),
    [normalizedTrend]
  );

  const severityDistribution = useMemo(() => {
    const riskSummary = dashboard?.risk;
    const medium = Math.max(0, (riskSummary?.total ?? 0) - (riskSummary?.critical ?? 0) - (riskSummary?.high ?? 0));
    return [
      { name: 'critical', label: 'Critical', value: riskSummary?.critical ?? 0, color: '#ff4d4f' },
      { name: 'high', label: 'High', value: riskSummary?.high ?? 0, color: '#ff7a45' },
      { name: 'medium', label: 'Medium', value: medium, color: '#faad14' },
      { name: 'low', label: 'Low', value: 0, color: '#1890ff' }
    ];
  }, [dashboard?.risk]);

  const maxSeverityValue = useMemo(() => {
    return Math.max(...severityDistribution.map((d) => d.value), 1);
  }, [severityDistribution]);

  const kpiCards = useMemo(() => {
    const riskSummary = dashboard?.risk;
    const ticketSummary = dashboard?.ticket;
    const remediationSummary = remediation;

    const openRisk = riskSummary?.open ?? dashboard?.risk_total ?? 0;
    const criticalAndHigh = (riskSummary?.critical ?? 0) + (riskSummary?.high ?? 0);
    const riskOverdue = riskSummary?.overdue ?? 0;
    const slaRate = typeof remediationSummary?.sla_hit_rate === 'number' ? remediationSummary.sla_hit_rate : (dashboard?.sla_rate ?? 0);
    const mttr = typeof remediationSummary?.mttr_hours === 'number' ? remediationSummary.mttr_hours : (dashboard?.mttr_hours ?? 0);
    const overdueTicket = ticketSummary?.overdue ?? 0;
    const openTicket = ticketSummary?.open ?? 0;

    return [
      { key: 'open_risk', title: '开放风险', value: openRisk, change: `${riskOverdue > 0 ? '+' : ''}${riskOverdue}`, tone: 'critical' as StatCardTone, icon: <Siren size={18} />, trend: (riskOverdue >= 0 ? 'up' : 'down') as 'up' | 'down' },
      { key: 'high_risk', title: '高危风险', value: criticalAndHigh, change: `${criticalAndHigh}`, tone: 'high' as StatCardTone, icon: <TriangleAlert size={18} />, trend: (criticalAndHigh > 0 ? 'down' : 'up') as 'up' | 'down' },
      { key: 'sla', title: 'SLA 达成率', value: `${Number(slaRate ?? 0).toFixed(1)}%`, change: `${openTicket}`, tone: 'good' as StatCardTone, icon: <ShieldCheck size={18} />, trend: (slaRate >= 80 ? 'up' : 'down') as 'up' | 'down' },
      { key: 'mttr', title: 'MTTR', value: `${Number(mttr ?? 0).toFixed(1)}h`, change: `${overdueTicket}`, tone: 'good' as StatCardTone, icon: <TimerReset size={18} />, trend: (overdueTicket > 0 ? 'up' : 'down') as 'up' | 'down' }
    ];
  }, [dashboard, remediation]);

  return (
    <section className="page-surface">
      <StateView loading={loading} error={loadError} onRetry={loadSummary}>
        <PageHeader
          title="暴露面工作台"
          subtitle="风险、资产与处置效率的今日状态"
          actions={
            <div className="page-actions">
              <Button icon={<RefreshCw size={16} />} aria-label="刷新" onClick={() => setReloadKey((value) => value + 1)}>
                刷新
              </Button>
              {can(Permission.ReportExport) ? (
                <Button aria-label="下载" icon={<Download size={16} />} type="primary">
                  下载报表
                </Button>
              ) : null}
            </div>
          }
        />
        <div className="metric-grid">
          {kpiCards.map((item) => (
            <StatCard
              key={item.key}
              label={item.title}
              value={item.value}
              icon={item.icon}
              tone={item.tone}
              delta={{ text: item.change, trend: item.trend }}
            />
          ))}
        </div>
        <Row gutter={[16, 16]}>
          <Col xs={24} lg={14}>
            <Card
              className="surface-card"
              title={
                <div className="card-title-row">
                  <ShieldAlert size={18} />
                  <span>风险动态</span>
                </div>
              }
              extra={
                <Button size="small" type="text" onClick={() => navigate(`/projects/${projectId}/risks`)}>
                  查看全部
                </Button>
              }
            >
              <Timeline items={updates} mode="left" />
            </Card>
          </Col>
          <Col xs={24} lg={10}>
            <Card
              className="surface-card"
              title={
                <div className="card-title-row">
                  <CalendarClock size={18} />
                  <span>分级分布</span>
                </div>
              }
            >
            <Space direction="vertical" size={12} className="full-width">
              {severityDistribution.map((card) => (
                <div
                  key={card.name}
                  className="severity-row"
                  style={{
                    position: 'relative',
                    overflow: 'hidden',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between'
                  }}
                >
                  <div
                    style={{
                      position: 'absolute',
                      left: 0,
                      top: 0,
                      bottom: 0,
                      width: `${(card.value / maxSeverityValue) * 100}%`,
                      background: card.color,
                      opacity: 0.08,
                      transition: 'width 0.6s cubic-bezier(0.4, 0, 0.2, 1)'
                    }}
                  />
                  <Space style={{ zIndex: 1 }}>
                    <Tag color={card.color} style={{ margin: 0 }}>
                      {card.label}
                    </Tag>
                    <span style={{ fontWeight: 600, color: 'var(--asm-text)' }}>{card.value}</span>
                  </Space>
                  <span style={{ zIndex: 1, display: 'flex', alignItems: 'center' }}>
                    {card.name === 'critical' || card.name === 'high' ? (
                      <ArrowUpRight size={14} color={card.color} />
                    ) : (
                      <ArrowDownRight size={14} color={card.color} />
                    )}
                  </span>
                </div>
              ))}
            </Space>
            </Card>
          </Col>
        </Row>
        <div className="metric-grid metric-grid--3">
          <StatCard label="总资产" value={dashboard?.exposure?.total ?? '-'} icon={<Server size={18} />} tone="neutral" />
          <StatCard label="过期工单" value={dashboard?.ticket?.overdue ?? 0} icon={<TimerReset size={18} />} tone={dashboard?.ticket?.overdue ? 'high' : 'neutral'} />
          <StatCard label="待处理工单" value={dashboard?.ticket?.open ?? 0} icon={<Inbox size={18} />} tone="neutral" />
        </div>
      </StateView>
    </section>
  );
}
