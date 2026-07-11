import { ProTable, type ProColumns } from '@ant-design/pro-components';
import { Button, Card, Select, Tag, Typography } from 'antd';
import { Download, RotateCcw, ShieldAlert, ShieldCheck, TimerReset, TrendingUp } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';

import {
  createExport,
  getDashboardReport,
  listExports,
  type DashboardReport,
  type ExportTask,
  type ReportTrendResponse
} from '../../api/operations';
import { errorMessage } from '../../api/errorMessage';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StatCard } from '../../components/StatCard';
import { StateView } from '../../components/StateView';
import { useProjectId } from '../../projects/ProjectContext';

export function ReportsPage() {
  const { can } = usePermission();
  const projectId = useProjectId();
  const [report, setReport] = useState<DashboardReport | null>(null);
  const [loadError, setLoadError] = useState('');
  const [reportType, setReportType] = useState('risk_summary');
  const [reloadKey, setReloadKey] = useState(0);
  const chartRef = useRef<HTMLDivElement | null>(null);

  const trendData = useMemo<ReportTrendResponse[]>(() => report?.trend ?? [], [report?.trend]);

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
    setLoadError('');
    void getDashboardReport(projectId)
      .then(setReport)
      .catch((error: unknown) => setLoadError(errorMessage(error)));
  }, [projectId]);

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
          axisLabel: { color: '#68758a' }
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
              summary={
                <div className="page-summary-stats">
                  <div className="page-summary-stat">
                    <Typography.Text type="secondary">风险总量</Typography.Text>
                    <Typography.Text strong>{report.risk_total}</Typography.Text>
                  </div>
                  <div className="page-summary-stat">
                    <Typography.Text type="secondary">SLA 达成率</Typography.Text>
                    <Typography.Text strong>{report.sla_rate}%</Typography.Text>
                  </div>
                  <div className="page-summary-stat">
                    <Typography.Text type="secondary">复发率</Typography.Text>
                    <Typography.Text strong>{report.recurrence_rate}%</Typography.Text>
                  </div>
                </div>
              }
            />
            <div className="metric-grid">
              <StatCard label="风险总量" value={report.risk_total} icon={<ShieldAlert size={18} />} tone={(report.risk_total ?? 0) > 0 ? 'high' : 'good'} />
              <StatCard label="MTTR" value={report.mttr_hours} suffix="h" icon={<TimerReset size={18} />} tone="neutral" hint="平均修复耗时" />
              <StatCard label="SLA 达成率" value={report.sla_rate} suffix="%" icon={<ShieldCheck size={18} />} tone={(report.sla_rate ?? 0) >= 80 ? 'good' : 'high'} />
              <StatCard label="复发率" value={report.recurrence_rate} suffix="%" icon={<RotateCcw size={18} />} tone={(report.recurrence_rate ?? 0) > 10 ? 'high' : 'neutral'} hint="同一资产再次出现风险" />
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
              <div ref={chartRef} className="report-chart" data-testid="report-chart" />
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
                          render: (_, row) => <Tag color={row.status === 'success' ? 'green' : row.status === 'failed' ? 'red' : 'blue'}>{row.status}</Tag>
                        }
                      : column
                  )
                }
                request={async () => {
                  const page = await listExports(projectId);
                  return { data: page.items, total: page.total, success: true };
                }}
              />
            </Card>
          </>
        ) : null}
      </StateView>
    </section>
  );
}
