/**
 * One place mapping backend enum values to the Chinese label and semantic tone
 * shown in the UI.
 *
 * The pages used to render raw values (`confirmed`, `pending_retest`,
 * `high_risk_exposure`) with per-page ad-hoc antd colour names, which read as a
 * debug view in an otherwise Chinese console and made the same status look
 * different on different pages. Tones map onto the theme tokens, so chips follow
 * light/dark automatically.
 */

export type Tone = 'critical' | 'high' | 'warn' | 'info' | 'progress' | 'success' | 'neutral';

export type EnumMeta = { label: string; tone: Tone };

/** describe falls back to the raw value so an unknown enum degrades to readable text. */
export function describe(map: Record<string, EnumMeta>, value: string | undefined): EnumMeta {
  if (!value) return { label: '-', tone: 'neutral' };
  return map[value] ?? { label: value, tone: 'neutral' };
}

/** Builds a ProTable valueEnum from a taxonomy map so filters show the same labels. */
export function toValueEnum(map: Record<string, EnumMeta>) {
  return Object.fromEntries(Object.entries(map).map(([value, meta]) => [value, meta.label]));
}

export const severityMeta: Record<string, EnumMeta> = {
  critical: { label: '严重', tone: 'critical' },
  high: { label: '高危', tone: 'high' },
  medium: { label: '中危', tone: 'warn' },
  low: { label: '低危', tone: 'info' },
  info: { label: '提示', tone: 'neutral' }
};

export const riskStatusMeta: Record<string, EnumMeta> = {
  new: { label: '新发现', tone: 'info' },
  confirmed: { label: '已确认', tone: 'info' },
  assigned: { label: '已分派', tone: 'progress' },
  fixing: { label: '修复中', tone: 'progress' },
  fixed: { label: '已修复', tone: 'success' },
  reopened: { label: '已重开', tone: 'warn' },
  risk_accepted: { label: '风险接受', tone: 'neutral' },
  false_positive: { label: '误报', tone: 'neutral' }
};

/** Transition actions the risk API advertises in available_actions. */
export const riskActionMeta: Record<string, EnumMeta> = {
  confirm: { label: '确认', tone: 'info' },
  assign: { label: '分派', tone: 'progress' },
  start_fix: { label: '开始修复', tone: 'progress' },
  mark_fixed: { label: '标记已修复', tone: 'success' },
  reopen: { label: '重新打开', tone: 'warn' },
  accept: { label: '接受风险', tone: 'critical' },
  false_positive: { label: '标记误报', tone: 'critical' }
};

export const riskTypeMeta: Record<string, EnumMeta> = {
  vulnerability: { label: '漏洞', tone: 'neutral' },
  weak_config: { label: '弱配置', tone: 'neutral' },
  sensitive_exposure: { label: '敏感信息暴露', tone: 'neutral' },
  unknown_asset: { label: '未知资产', tone: 'neutral' },
  expired_certificate: { label: '证书过期', tone: 'neutral' },
  high_risk_port: { label: '高危端口', tone: 'neutral' },
  high_risk_exposure: { label: '高危暴露面', tone: 'neutral' },
  shadow_it: { label: '影子资产', tone: 'neutral' },
  vendor_exposure: { label: '第三方暴露', tone: 'neutral' }
};

export const ticketStatusMeta: Record<string, EnumMeta> = {
  open: { label: '待处理', tone: 'info' },
  assigned: { label: '已分派', tone: 'progress' },
  in_progress: { label: '处理中', tone: 'progress' },
  pending_retest: { label: '待复测', tone: 'warn' },
  extended: { label: '已延期', tone: 'warn' },
  resolved: { label: '已解决', tone: 'success' },
  closed: { label: '已关闭', tone: 'success' },
  rejected: { label: '已驳回', tone: 'critical' },
  cancelled: { label: '已取消', tone: 'neutral' }
};

/** Transition actions the ticket API advertises in available_actions. */
export const ticketActionMeta: Record<string, EnumMeta> = {
  assign: { label: '分派', tone: 'progress' },
  start: { label: '开始处理', tone: 'progress' },
  submit_retest: { label: '提交复测', tone: 'info' },
  retest_pass: { label: '复测通过', tone: 'success' },
  retest_reject: { label: '复测不通过', tone: 'warn' },
  close: { label: '关闭', tone: 'success' },
  accept_risk: { label: '接受风险', tone: 'critical' },
  false_positive: { label: '标记误报', tone: 'critical' },
  extend: { label: '延期', tone: 'warn' },
  cancel: { label: '取消', tone: 'neutral' }
};

export const priorityMeta: Record<string, EnumMeta> = {
  urgent: { label: '紧急', tone: 'critical' },
  high: { label: '高', tone: 'high' },
  medium: { label: '中', tone: 'warn' },
  low: { label: '低', tone: 'neutral' }
};

/**
 * Asset type stays deliberately toneless: it is a classification, not a
 * judgement, and colouring nine of them turns a dense table into confetti.
 */
export const assetTypeMeta: Record<string, EnumMeta> = {
  domain: { label: '主域名', tone: 'neutral' },
  subdomain: { label: '子域名', tone: 'neutral' },
  ip: { label: 'IP', tone: 'neutral' },
  port: { label: '端口', tone: 'neutral' },
  service: { label: '服务', tone: 'neutral' },
  web: { label: 'Web 应用', tone: 'neutral' },
  certificate: { label: '证书', tone: 'neutral' },
  cloud_resource: { label: '云资源', tone: 'neutral' },
  third_party: { label: '第三方', tone: 'neutral' }
};

export const assetStatusMeta: Record<string, EnumMeta> = {
  active: { label: '活跃', tone: 'success' },
  inactive: { label: '不活跃', tone: 'neutral' },
  ignored: { label: '已忽略', tone: 'neutral' },
  deleted: { label: '已删除', tone: 'critical' }
};

export const assetSourceMeta: Record<string, EnumMeta> = {
  manual: { label: '手动维护', tone: 'neutral' },
  discovery: { label: '暴露发现', tone: 'neutral' },
  project_profile: { label: '项目资料', tone: 'neutral' }
};

/** Severity band for a 0-100 risk score, used to colour the score meter. */
export function scoreTone(score: number): Tone {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'warn';
  return 'info';
}

export const projectStatusMeta: Record<string, EnumMeta> = {
  draft: { label: '草稿', tone: 'neutral' },
  active: { label: '运行中', tone: 'success' },
  suspended: { label: '已暂停', tone: 'warn' },
  archived: { label: '已归档', tone: 'neutral' }
};

/** Discovery task run lifecycle. */
export const runStatusMeta: Record<string, EnumMeta> = {
  pending: { label: '待下发', tone: 'info' },
  running: { label: '执行中', tone: 'progress' },
  success: { label: '成功', tone: 'success' },
  partial_success: { label: '部分成功', tone: 'warn' },
  failed: { label: '失败', tone: 'critical' },
  cancelled: { label: '已取消', tone: 'neutral' }
};

/** Scope authorisation state. */
export const scopeStatusMeta: Record<string, EnumMeta> = {
  active: { label: '生效中', tone: 'success' },
  inactive: { label: '未生效', tone: 'neutral' },
  expired: { label: '已过期', tone: 'warn' }
};

/** Async report export job state. */
export const exportStatusMeta: Record<string, EnumMeta> = {
  pending: { label: '排队中', tone: 'info' },
  running: { label: '生成中', tone: 'progress' },
  success: { label: '已完成', tone: 'success' },
  failed: { label: '失败', tone: 'critical' }
};
