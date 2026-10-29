import { Button, Card, Empty, Col, Row, Space, Tag, Timeline } from 'antd';
import { CalendarClock, Download, Inbox, RefreshCw, Server, ShieldAlert, ShieldCheck, Siren, TimerReset, TriangleAlert } from 'lucide-react';
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
import { StatusChip } from '../components/StatusChip';
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
      time: new Date(item.date).toLocaleDateString('zh-CN', { month: 'long', day: 'numeric' }),
      type: item.new >= item.fixed ? 'high' : 'low',
      title: item.new >= item.fixed ? `新增 ${item.new} 条风险` : `修复 ${item.fixed} 条风险`,
      body: `新增 ${item.new} 条 · 修复 ${item.fixed} 条`,
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

  // The dashboard endpoint reports total/critical/high only. Splitting the
  // remainder into "Medium" and a hardcoded "Low: 0" invented a distribution the
  // server never sent, so the remainder is labelled for what it is.
  const severityDistribution = useMemo(() => {
    const riskSummary = dashboard?.risk;
    const others = Math.max(0, (riskSummary?.total ?? 0) - (riskSummary?.critical ?? 0) - (riskSummary?.high ?? 0));
    return [
      { name: 'critical', label: '严重', value: riskSummary?.critical ?? 0, tone: 'critical' as const },
      { name: 'high', label: '高危', value: riskSummary?.high ?? 0, tone: 'high' as const },
      { name: 'others', label: '中/低及其他', value: others, tone: 'warn' as const }
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
    // sla_hit_rate is a 0-1 ratio (slaMet/fixed, see report/repository.go); the
    // legacy dashboard field was already a percentage. Normalise to a percentage
    // once here — the card previously printed a ratio of 1 as "1.0%".
    const slaRate =
      typeof remediationSummary?.sla_hit_rate === 'number'
        ? remediationSummary.sla_hit_rate * 100
        : (dashboard?.sla_rate ?? 0);
    const mttr = typeof remediationSummary?.mttr_hours === 'number' ? remediationSummary.mttr_hours : (dashboard?.mttr_hours ?? 0);
    const overdueTicket = ticketSummary?.overdue ?? 0;
    const openTicket = ticketSummary?.open ?? 0;

    return [
      { key: 'open_risk', title: '开放风险', value: openRisk, change: `${riskOverdue > 0 ? '+' : ''}${riskOverdue}`, tone: (openRisk > 0 ? 'critical' : 'neutral') as StatCardTone, icon: <Siren size={18} />, trend: (riskOverdue >= 0 ? 'up' : 'down') as 'up' | 'down' },
      { key: 'high_risk', title: '高危风险', value: criticalAndHigh, change: `${criticalAndHigh}`, tone: (criticalAndHigh > 0 ? 'high' : 'neutral') as StatCardTone, icon: <TriangleAlert size={18} />, trend: (criticalAndHigh > 0 ? 'down' : 'up') as 'up' | 'down' },
      { key: 'sla', title: 'SLA 达成率', value: `${Number(slaRate ?? 0).toFixed(1)}%`, change: `${openTicket}`, tone: ((riskSummary?.total ?? 0) > 0 ? (slaRate >= 80 ? 'good' : 'high') : 'neutral') as StatCardTone, icon: <ShieldCheck size={18} />, trend: (slaRate >= 80 ? 'up' : 'down') as 'up' | 'down' },
      { key: 'mttr', title: 'MTTR', value: `${Number(mttr ?? 0).toFixed(1)}h`, change: `${overdueTicket}`, tone: 'neutral' as StatCardTone, icon: <TimerReset size={18} />, trend: (overdueTicket > 0 ? 'up' : 'down') as 'up' | 'down' }
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
                <Button
                  aria-label="下载"
                  icon={<Download size={16} />}
                  type="primary"
                  onClick={() => navigate(`/projects/${projectId}/reports`)}
                >
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
              {updates.length ? <Timeline items={updates} mode="left" /> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无风险动态" />}
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
                <div key={card.name} className={`severity-row severity-row--${card.tone}`}>
                  <span
                    className="severity-row-fill"
                    style={{ width: `${(card.value / maxSeverityValue) * 100}%` }}
                  />
                  <span className="severity-row-main">
                    <StatusChip label={card.label} tone={card.tone} dot />
                  </span>
                  <span className="severity-row-value">{card.value}</span>
                </div>
              ))}
            </Space>
            </Card>
          </Col>
        </Row>
        <div className="metric-grid metric-grid--3">
          <StatCard label="暴露面总数" value={dashboard?.exposure?.total ?? '-'} icon={<Server size={18} />} tone="neutral" />
          <StatCard label="过期工单" value={dashboard?.ticket?.overdue ?? 0} icon={<TimerReset size={18} />} tone={dashboard?.ticket?.overdue ? 'high' : 'neutral'} />
          <StatCard label="待处理工单" value={dashboard?.ticket?.open ?? 0} icon={<Inbox size={18} />} tone="neutral" />
        </div>
      </StateView>
    </section>
  );
}
