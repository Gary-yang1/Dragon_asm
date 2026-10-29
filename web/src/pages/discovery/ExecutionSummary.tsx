import { Alert, Descriptions, Space, Typography } from "antd";
import type { Scope, TaskTemplateTaskType } from "../../api/discovery";
import type { EngineManagementOverview } from "../../api/engineManagement";
import { scopeTargetInputs } from "./urlAuthorization";

export const discoveryPurpose: Partial<Record<TaskTemplateTaskType, string>> = {
  passive_intel: "发现子域名",
  dns: "查询域名解析",
  port_probe: "发现开放端口",
  web_probe: "识别网站",
  fingerprint: "识别网站技术",
  org_intel: "查询企业关联资产",
};

export function ExecutionSummary({
  scope,
  taskType,
  overview,
  overviewError,
  sources,
  ports,
  nodeId,
  inputTargets,
}: {
  scope?: Scope;
  taskType: TaskTemplateTaskType;
  overview?: EngineManagementOverview;
  overviewError?: string;
  sources?: string[];
  ports?: string;
  nodeId?: string;
  inputTargets?: Array<{ type: string; value: string }>;
}) {
  const active = ["port_probe", "web_probe", "fingerprint"].includes(taskType);
  const route = active ? "active" : "passive";
  const engine = overview?.items.find((item) => item.route === route);
  const targetType =
    taskType === "port_probe"
      ? "ip"
      : active
        ? "url"
        : taskType === "org_intel"
          ? "company"
          : "domain";
  const targets = inputTargets
    ? inputTargets
        .filter((target) => target.type === targetType)
        .map((target) => ({
          target_type: target.type,
          value: target.value,
          coverage_mode: "exact",
        }))
    : (scope?.targets.filter(
        (target) =>
          target.match_mode === "include" && target.target_type === targetType,
      ).flatMap(target => scopeTargetInputs(target).map(input => ({...target, value: input.value}))) ?? []);
  const excluded =
    scope?.targets.filter((target) => target.match_mode === "exclude") ?? [];
  const healthLabels = {
    healthy: "最近检测正常",
    degraded: "最近检测存在异常",
    unreachable: "最近检测无法连接",
    unconfigured: "尚未配置",
    unknown: "尚未检测",
  };
  return (
    <div className="discovery-execution-summary">
      <Descriptions column={1} size="small" colon={false}>
        <Descriptions.Item label="发现目的">
          {discoveryPurpose[taskType] ?? taskType}
        </Descriptions.Item>
        <Descriptions.Item label="授权范围">
          {scope?.name ?? "请选择有效的授权范围"}
        </Descriptions.Item>
        <Descriptions.Item label="本次输入">
          <div>
            {targets.length} 个目标
            {targets.slice(0, 3).map((target) => (
              <div key={target.value}>{target.value}</div>
            ))}
            {targets.length > 3 && (
              <span>另有 {targets.length - 3} 个目标，展开下方列表查看</span>
            )}
          </div>
        </Descriptions.Item>
        <Descriptions.Item label="执行引擎">
          {engine?.name ??
            (active ? "平台配置的主动引擎" : "平台配置的被动引擎")}
          {engine?.configuration_version
            ? ` · 配置版本 ${engine.configuration_version}`
            : ""}
        </Descriptions.Item>
        {engine && (
          <Descriptions.Item label="连接记录">
            {healthLabels[engine.health]}
            {engine.last_checked_at
              ? ` · ${new Date(engine.last_checked_at).toLocaleString()}`
              : " · 未进行实时连接检测"}
          </Descriptions.Item>
        )}
        {taskType === "passive_intel" && (
          <Descriptions.Item label="数据来源">
            {(sources ?? ["auto"])
              .map((source) => source === "auto" ? "自动使用已配置来源" : source.toUpperCase())
              .join("、")}
            （使用平台保存的密钥）
          </Descriptions.Item>
        )}
        {taskType === "port_probe" && (
          <Descriptions.Item label="探测端口">
            {ports ?? "80,443"}
          </Descriptions.Item>
        )}
        {active && (
          <Descriptions.Item label="执行节点">
            {nodeId || "由引擎自动分配"}
          </Descriptions.Item>
        )}
      </Descriptions>
      {targets.length > 0 && (
        <details className="inline-disclosure">
          <summary>查看目标与排除项</summary>
          <ul>
            {targets.map((target) => (
              <li key={`${target.target_type}:${target.value}`}>
                {target.value}
                {target.coverage_mode === "subdomains"
                  ? "（授权包含子域名）"
                  : ""}
              </li>
            ))}
          </ul>
          <Typography.Text type="secondary">
            排除项：
            {excluded.length
              ? excluded.map((target) => target.value).join("、")
              : "无"}
            。最终执行目标由后端结合授权规则校验。
          </Typography.Text>
        </details>
      )}
      <Space direction="vertical" className="full-width" size={8}>
        {overviewError && (
          <Alert
            type="warning"
            showIcon
            message="暂时无法读取引擎摘要"
            description={overviewError}
          />
        )}
        {engine && !engine.configured && (
          <Alert
            type="warning"
            showIcon
            message="对应引擎尚未配置，请联系平台管理员。"
          />
        )}
        {active && overview && !overview.active_policy.enabled && (
          <Alert
            type="warning"
            showIcon
            message="平台尚未允许主动任务下发，请联系管理员确认执行策略。"
          />
        )}
        {active && overview?.active_policy.require_approval && (
          <Typography.Text type="secondary">
            此任务需要审批；执行时由平台校验审批条件。
          </Typography.Text>
        )}
        {active && overview?.active_policy.require_ownership && (
          <Typography.Text type="secondary">
            此任务需要资产归属验证。
          </Typography.Text>
        )}
        <Typography.Text type="secondary">
          {active
            ? "会向已授权目标发送探测请求。"
            : "按授权目标查询已配置的数据来源。"}
          启动时重新校验授权和配置，连接记录不代表本次任务已经执行。
        </Typography.Text>
      </Space>
    </div>
  );
}
