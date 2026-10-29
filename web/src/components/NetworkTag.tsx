import { Tag, Tooltip } from 'antd';

import type { AssetNetworkInfo } from '../api/assets';

export function cdnEdgeLabel(info: AssetNetworkInfo) {
  return info.provider ? `CDN · ${info.provider}` : 'CDN 边缘节点';
}

/**
 * Labels an address that is not the organisation's own origin. Nothing is shown
 * for an address with no judgement: unknown is not "own", so it gets no badge.
 */
export function NetworkTag({ info }: { info?: AssetNetworkInfo }) {
  if (!info) return null;
  if (info.role === 'cdn_edge') {
    return (
      <Tooltip title={`${info.evidence || '已识别为 CDN 边缘节点'}${info.rule_version ? `（规则 ${info.rule_version}）` : ''}。不计入本单位 IP 资产，不能作为扫描目标。`}>
        <Tag color="blue" className="network-tag">{cdnEdgeLabel(info)}</Tag>
      </Tooltip>
    );
  }
  if (info.shared) {
    return (
      <Tooltip title="被大量域名解析到，可能是共享主机或未收录的 CDN。仍计入 IP 资产，请核实归属后再用于扫描。">
        <Tag color="gold" className="network-tag">{`疑似共享 · ${info.resolved_by} 个域名`}</Tag>
      </Tooltip>
    );
  }
  return null;
}
