import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Button, Card, Empty, Select, message } from 'antd';
import { Download, RotateCcw, ShieldAlert, ShieldCheck, TimerReset, TrendingUp } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';

import {
  createExport,
  getDashboardReport,
  getReportRemediation,
  getReportTrend,
  listExports,
  type DashboardReport,
  type ExportTask,
  type ReportRemediation,
  type ReportTrendResponse
} from '../../api/operations';
import { errorMessage } from '../../api/errorMessage';
import { EnumChip } from '../../components/StatusChip';
import { exportStatusMeta } from '../../utils/taxonomy';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StatCard } from '../../components/StatCard';
import { StateView } from '../../components/StateView';
import { useProjectId } from '../../projects/ProjectContext';

/** Renders an API day value as MM-DD, tolerating both date and RFC3339 forms. */
function shortDay(value: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return `${String(parsed.getMonth() + 1).padStart(2, '0')}-${String(parsed.getDate()).padStart(2, '0')}`;
}

export function ReportsPage() {
  const { can } = usePermission();
  const projectId = useProjectId();
  const [report, setReport] = useState<DashboardReport | null>(null);
  const [loadError, setLoadError] = useState('');
  const [reportType, setReportType] = useState('risk_summary');
  const [reloadKey, setReloadKey] = useState(0);
  const chartRef = useRef<HTMLDivElement | null>(null);
  const [remediation, setRemediation] = useState<ReportRemediation | null>(null);
  const [trend, setTrend] = useState<ReportTrendResponse[]>([]);

  const trendData = useMemo<ReportTrendResponse[]>(() => (trend.length ? trend : report?.trend ?? []), [report?.trend, trend]);

  // sla_hit_rate and recurrence_rate are 0-1 ratios (report/repository.go:161).
  const summary = useMemo(() => {
    const pct = (ratio: number | undefined) => (typeof ratio === 'number' ? Number((ratio * 100).toFixed(1)) : undefined);
    return {
      riskTotal: remediation?.total_risks ?? report?.risk?.total ?? report?.risk_total,
      mttr: remediation?.mttr_hours ?? report?.mttr_hours,
      slaRate: pct(remediation?.sla_hit_rate) ?? report?.sla_rate,
      recurrenceRate: pct(remediation?.recurrence_rate) ?? report?.recurrence_rate
    };
  }, [remediation, report]);

  const reportTrendData = useMemo(
    () =>
      trendData.map((item) => ({
        day: 'day' in item ? item.day : item.date,
        risks: 'day' in item ? item.new : item.risks,
        fixed: item.fixed
      })),
    [trendData]
  );

  useEffect(() => {
    let active = true;
    setLoadError('');
    void Promise.all([
      getDashboardReport(projectId),
      getReportRemediation(projectId).catch(() => null),
      getReportTrend(projectId).catch(() => [] as ReportTrendResponse[])
    ])
      .then(([dashboardData, remediationData, trend]) => {
        if (!active) return;
        setReport(dashboardData);
        setRemediation(remediationData);
        setTrend(trend);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setLoadError(errorMessage(error));
      });
    return () => {
      active = false;
    };
  }, [projectId, reloadKey]);

  useEffect(() => {
    if (!chartRef.current || !report) return undefined;
    let cleanup: (() => void) | undefined;
    void import('echarts').then((echarts) => {
      if (!chartRef.current) return;
      const chart = echarts.init(chartRef.current);
      chart.setOption({
        color: ['#1677ff', '#52c41a'],
        grid: { left: 40, right: 24, top: 40, bottom: 32 },
        tooltip: { trigger: 'axis', axisPointer: { type: 'line', lineStyle: { color: '#cbd5e1' } } },
        legend: {
          data: ['新增风险', '已修复'],
          top: 4,
          right: 8,
          icon: 'roundRect',
          itemWidth: 12,
          itemHeight: 8,
          itemGap: 18,
          textStyle: { color: '#68758a' }
        },
        xAxis: {
          type: 'category',
          data: reportTrendData.map((item) => item.day),
          boundaryGap: false,
          axisTick: { show: false },
          axisLine: { lineStyle: { color: '#e6edf7' } },
          // The API returns full RFC3339 timestamps; printing them verbatim made
          // the axis a wall of overlapping "2026-07-02T00:00:00Z" strings.
          axisLabel: { color: '#68758a', formatter: (value: string) => shortDay(value) }
        },
        yAxis: {
          type: 'value',
          splitLine: { lineStyle: { color: '#eef3fa' } },
          axisLabel: { color: '#68758a' }
        },
        series: [
          {
            name: '新增风险',
            type: 'line',
            smooth: true,
            showSymbol: false,
            data: reportTrendData.map((item) => item.risks),
            lineStyle: { width: 2 },
            areaStyle: { color: 'rgba(22,119,255,0.12)' }
          },
          {
            name: '已修复',
            type: 'line',
            smooth: true,
            showSymbol: false,
            data: reportTrendData.map((item) => item.fixed),
            lineStyle: { width: 2 },
            areaStyle: { color: 'rgba(82,196,26,0.10)' }
          }
        ]
      });
      cleanup = () => chart.dispose();
    });
    return () => cleanup?.();
  }, [reportTrendData, report]);

  const columns = useMemo<ProColumns<ExportTask>[]>(() => [
    { title: '报表', dataIndex: 'report_type' },
    { title: '状态', dataIndex: 'status' },
    { title: '文件', dataIndex: 'file_name' },
    { title: '创建时间', dataIndex: 'created_at', valueType: 'dateTime' }
  ], []);

  async function exportReport() {
    await createExport(projectId, reportType);
    setReloadKey((value) => value + 1);
  }

  return (
    <section className="page-surface">
      <StateView loading={!report && !loadError} error={loadError}>
        {report ? (
          <>
            <PageHeader
              title="报表中心"
              subtitle="风险与修复趋势、报表导出"
              actions={
                <div className="page-actions">
                  <Select
                    value={reportType}
                    style={{ width: 180 }}
                    options={[
                      { value: 'risk_summary', label: '风险汇总' },
                      { value: 'sla_efficiency', label: '修复效能' }
                    ]}
                    onChange={setReportType}
                  />
                  <Button icon={<Download size={16} />} disabled={!can(Permission.ReportExport)} onClick={() => void exportReport()}>
                    异步导出
                  </Button>
                </div>
              }
            />
            <div className="metric-grid">
              <StatCard label="风险总量" value={summary.riskTotal ?? '-'} icon={<ShieldAlert size={18} />} tone={(summary.riskTotal ?? 0) > 0 ? 'high' : 'good'} />
              <StatCard label="MTTR" value={summary.mttr ?? '-'} suffix="h" icon={<TimerReset size={18} />} tone="neutral" hint="平均修复耗时" />
              <StatCard label="SLA 达成率" value={summary.slaRate ?? '-'} suffix="%" icon={<ShieldCheck size={18} />} tone={summary.riskTotal ? ((summary.slaRate ?? 0) >= 80 ? 'good' : 'high') : 'neutral'} />
              <StatCard label="复发率" value={summary.recurrenceRate ?? '-'} suffix="%" icon={<RotateCcw size={18} />} tone={(summary.recurrenceRate ?? 0) > 10 ? 'high' : 'neutral'} hint="同一资产再次出现风险" />
            </div>
            <Card
              className="surface-card"
              title={
                <div className="card-title-row">
                  <TrendingUp size={18} />
                  <span>风险趋势</span>
                </div>
              }
            >
              {reportTrendData.length ? <div ref={chartRef} className="report-chart" data-testid="report-chart" /> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="所选时间范围内暂无风险趋势数据" />}
            </Card>
            <Card className="surface-card" title="导出记录">
              <ProTable<ExportTask>
                key={reloadKey}
                className="surface-table"
                rowKey="id"
                search={false}
                options={false}
                columns={
                  columns.map((column) =>
                    column.dataIndex === 'status'
                      ? {
                          ...column,
                          render: (_, row) => <EnumChip map={exportStatusMeta} value={row.status} />
                        }
                      : column
                  )
                }
                request={async (params) => {
                  // Previously always requested page 1, so page 2 of the export
                  // history silently repeated page 1.
                  try {
                    const page = await listExports(projectId, params.pageSize ?? 20, params.current ?? 1);
                    return { data: page.items, total: page.total, success: true };
                  } catch (error) {
                    message.error(errorMessage(error));
                    return { data: [], total: 0, success: false };
                  }
                }}
              />
            </Card>
          </>
        ) : null}
      </StateView>
    </section>
  );
}
