export type Attribution = { status: string; provider?: string; evidence?: string[] };

export type Website = {
  asset_id: number; run_id: number; url: string; title: string; status_code: number; fingerprints: string[];
  outcome: string; error_kind?: string; final_url?: string; redirect_chain?: string[]; resolved_ips: string[]; connected_ip?: string; cname_chain: string[];
  cdn: Attribution; cloud: Attribution; observed_at: string; info_observed_at?: string; rule_version?: string;
  enrichment_state?: 'not_started' | 'pending' | 'running' | 'complete' | 'failed'; enrichment_error?: string;
  network_source?: 'baiyan' | 'active_engine'; network_observed_at?: string; network_status?: 'success' | 'partial' | 'failed';
  /** Management fields of the linked asset; empty when the site is not an asset. */
  owner?: string; business_unit?: string; asset_status?: string;
  /** Where the shown observation came from; passive means a search-engine crawl. */
  provider?: string; active_probe?: boolean;
};

const searchEngines: Record<string, string> = { fofa: 'FOFA', quake: 'Quake', hunter: 'Hunter' };

/** Name of the search engine whose crawl this row shows, or '' for a live probe. */
export function crawlSource(row: Website) {
  if (row.active_probe !== false || !row.provider) return '';
  return searchEngines[row.provider] ?? row.provider;
}

export const outcomes: Record<string, string> = { responded: '有 HTTP 响应', unknown: '未返回详情', timeout: '请求超时', dns_error: 'DNS 解析失败', network_error: '连接失败', tls_error: 'TLS 错误', cancelled: '已取消' };

export const known = (a?: Attribution) => a?.status === 'identified' ? a.provider || '已识别' : '未知';
export const stamp = (value: string) => new Date(value).toLocaleString();
export const primaryIP = (row: Website) => row.connected_ip || row.resolved_ips?.find(ip => !ip.includes(':')) || row.resolved_ips?.[0];
export const fingerprintNames = (names: string[]) => [...new Set(names.flatMap(name => name.split(',').map(value => value.trim()).filter(Boolean)))];
export const enrichmentPending = (row: Website) => row.enrichment_state === 'pending' || row.enrichment_state === 'running';
export const networkSource = (row: Website) => row.network_source === 'baiyan' ? 'Baiyan' : row.network_source === 'active_engine' ? '主动引擎（历史记录）' : '未采集';

export const networkProgress = (row: Website) => {
  if (enrichmentPending(row)) return row.enrichment_error ? '归属查询自动重试中' : '网络归属查询中';
  if (row.enrichment_state === 'failed') return '网络归属查询失败';
  if (row.network_status === 'partial') return '网络信息部分补齐';
  if (!row.network_source) return '网络归属尚未查询';
  return '';
};

/** Host plus any non-default port, used as the site name when no title was captured. */
export function siteHost(url: string) {
  try {
    const parsed = new URL(url);
    return parsed.host;
  } catch {
    return url;
  }
}

/**
 * Why a site has no title. "unknown" only means the engine reported no status:
 * the site may be unreachable, or it answered but matched no fingerprint, since
 * the active engine currently attaches status and title to fingerprint hits.
 */
export function missingTitleReason(row: Website) {
  if (crawlSource(row)) return '测绘未记录标题';
  if (row.outcome === 'responded') return '页面无标题';
  if (row.outcome === 'unknown') return '未获取到响应信息';
  return outcomes[row.outcome] || '未获取到响应信息';
}
