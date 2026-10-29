import { Alert, Button, Descriptions, Drawer, Space, Typography } from "antd";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getTaskRun, type TaskRun } from "../../api/discovery";
import { errorMessage } from "../../api/errorMessage";
import { Permission } from "../../auth/permissions";
import { usePermission } from "../../auth/usePermission";
import { EnumChip } from "../../components/StatusChip";
import { runStatusMeta } from "../../utils/taxonomy";
import { RunActivity } from "./RunActivity";
import { discoveryPurpose } from "./ExecutionSummary";

export function RunDetails({
  projectId,
  runId,
  onClose,
  onExposures,
  onContinue,
  onPrepareWeb,
}: {
  projectId: number;
  runId: number | null;
  onClose: () => void;
  onExposures: () => void;
  onContinue?: (runId: number) => void;
  onPrepareWeb?: (scopeId: number) => void;
}) {
  const { can } = usePermission();
  const [run, setRun] = useState<TaskRun>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    setRun(undefined);
    setError("");
    if (runId === null) return;
    const controller = new globalThis.AbortController();
    let timer: number | undefined;
    async function load() {
      setLoading(true);
      try {
        const value = await getTaskRun(projectId, runId!, controller.signal);
        if (controller.signal.aborted) return;
        setRun(value);
        setError("");
        if (["pending", "running"].includes(value.status))
          timer = window.setTimeout(() => void load(), 4000);
      } catch (err) {
        if (!controller.signal.aborted) {
          setRun(undefined);
          setError(errorMessage(err));
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [projectId, runId, refresh]);
  const time = (value?: string) =>
    value ? new Date(value).toLocaleString() : "尚未记录";
  return (
    <Drawer
      title={`执行详情 · #${runId ?? ""}`}
      open={runId !== null}
      onClose={onClose}
      width={920}
      className="discovery-drawer"
    >
      <Space direction="vertical" size={20} className="full-width">
        <Space wrap>
        <Button
          loading={loading}
          onClick={() => setRefresh((value) => value + 1)}
        >
          刷新详情
        </Button>
        {run && onPrepareWeb && can(Permission.DiscoveryRun) && can(Permission.AssetRead) && ['passive_intel','dns'].includes(run.task_type) && ['success','partial_success'].includes(run.status) && <Button type="primary" onClick={() => onPrepareWeb(run.scope_id)}>识别全部网站</Button>}
        {run && onContinue && can(Permission.AssetRead) && can(Permission.ScopeRead) && <Button disabled={!['success','partial_success'].includes(run.status)} onClick={() => onContinue(run.id)}>继承结果继续发现</Button>}
        </Space>
        {error && (
          <Alert
            type="error"
            showIcon
            message="无法加载执行详情"
            description={error}
          />
        )}
        {loading && !run && (
          <Typography.Text role="status">正在读取任务状态…</Typography.Text>
        )}
        {run && (
          <>
            <Descriptions column={{xs:1,sm:2}} size="small">
              <Descriptions.Item label="任务">
                {discoveryPurpose[run.task_type] ?? run.task_type}
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <EnumChip map={runStatusMeta} value={run.status} />
              </Descriptions.Item>
              <Descriptions.Item label="进度">
                {['passive_intel','dns'].includes(run.task_type) && ['pending','running'].includes(run.status)
                  ? (run.status === 'pending' ? '等待执行' : '分阶段执行，结果持续回传')
                  : `${run.progress}%`}
                {["success", "partial_success", "failed", "cancelled"].includes(
                  run.status,
                )
                  ? " · 本次执行已结束"
                  : ""}
              </Descriptions.Item>
              <Descriptions.Item label="结果">
                {['web_probe','fingerprint'].includes(run.task_type) && can(Permission.AssetRead) ? <Link to={`/projects/${projectId}/discovery?run_id=${run.id}`} onClick={onClose}>查看本次网站结果</Link> : run.result_count ?? "未提供"}
              </Descriptions.Item>
              <Descriptions.Item label="开始时间">
                {time(run.started_at)}
              </Descriptions.Item>
              <Descriptions.Item label="结束时间">
                {time(run.finished_at)}
              </Descriptions.Item>
              <Descriptions.Item label="最近回调">
                {time(run.last_callback_at)}
              </Descriptions.Item>
            </Descriptions>
            {(run.status === "partial_success" ||
              run.status === "failed" ||
              run.error_summary) && (
              <Alert
                showIcon
                type={run.status === "failed" ? "error" : "warning"}
                message={
                  run.status === "partial_success"
                    ? "本次任务仅部分完成"
                    : "任务执行异常"
                }
                description={
                  run.error_summary ||
                  (["passive_intel","dns"].includes(run.task_type) ? "请在下方查看来源和 DNS 阶段的状态；旧任务可能只保留了汇总错误。进度 100% 不代表全部步骤成功。" : "引擎未提供具体原因。请联系管理员核对引擎执行日志；进度 100% 不代表全部步骤成功。")
                }
              />
            )}
            {can(Permission.AssetRead) && ['passive_intel','dns'].includes(run.task_type) && <RunActivity key={`${projectId}:${run.id}`} projectId={projectId} runId={run.id} />}
            <div>
              <Typography.Title level={5}>查看发现产物</Typography.Title>
              <Typography.Paragraph type="secondary">
                {['web_probe','fingerprint'].includes(run.task_type) ? '网站任务可通过上方“查看本次网站结果”查看历史快照。以下入口查看当前项目的最新资产和暴露信息；记录数量不等于新增资产数。' : '上方展示本次运行已返回的资产，执行中持续更新；以下入口查看项目累计数据。记录数量不等于新增资产数。'}
              </Typography.Paragraph>
              <Space wrap>
                {can(Permission.AssetRead) && (
                  <Link to={`/projects/${projectId}/assets`}>查看项目资产</Link>
                )}
                {can(Permission.ExposureRead) && (
                  <Button onClick={onExposures}>查看项目暴露结果</Button>
                )}
              </Space>
            </div>
            <details className="inline-disclosure">
              <summary>执行标识与限制</summary>
              <Descriptions column={1} size="small">
                <Descriptions.Item label="模板编号">
                  {run.template_id}
                </Descriptions.Item>
                <Descriptions.Item label="引擎任务编号">
                  {run.engine_job_id || "尚未分配"}
                </Descriptions.Item>
                <Descriptions.Item label="超时">
                  {run.timeout_seconds ? `${run.timeout_seconds} 秒` : "未提供"}
                </Descriptions.Item>
                <Descriptions.Item label="并发">
                  {run.concurrency ?? "未提供"}
                </Descriptions.Item>
                <Descriptions.Item label="已尝试次数">
                  {run.attempt ?? "未提供"}
                </Descriptions.Item>
              </Descriptions>
            </details>
          </>
        )}
      </Space>
    </Drawer>
  );
}
