import { Alert, Empty, Tag, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { assetLocation } from '../../utils/assetRoutes';
import { useEffect, useMemo, useRef } from 'react';

import type { AssetGraphData, AssetGraphNode } from '../../api/assets';
import { useThemeStore } from '../../stores/themeStore';
import { describe, assetTypeMeta } from '../../utils/taxonomy';

type AssetGraphProps = {
  graph: AssetGraphData | null;
  projectId?: number;
};

const relationLabels: Record<string, string> = {
  contains: '包含',
  resolves_to: '解析到',
  redirects_to: '重定向到',
  cert_binding: '证书绑定',
  references: '关联'
};

const nodeColors: Record<string, string> = {
  domain: '#dbeafe',
  subdomain: '#e0e7ff',
  ip: '#cffafe',
  port: '#fef3c7',
  service: '#ffedd5',
  web: '#dcfce7',
  certificate: '#f3e8ff',
  cloud_resource: '#fce7f3',
  third_party: '#e5e7eb'
};

function nodeLabel(node: AssetGraphNode) {
  return node.display_name || node.value || `资产 #${node.id}`;
}

function relationLabel(relationType: string) {
  return relationLabels[relationType] ?? relationType;
}

export function AssetGraph({ graph, projectId }: AssetGraphProps) {
  const themeMode = useThemeStore((state) => state.mode);
  const labelColor = themeMode === 'dark' ? '#e2e8f0' : '#334155';
  const ref = useRef<HTMLDivElement | null>(null);
  const data = useMemo(() => buildGraphData(graph), [graph]);
  const nodeByID = useMemo(
    () => new Map((graph?.nodes ?? []).map((node) => [node.id, node])),
    [graph?.nodes]
  );

  useEffect(() => {
    if (!ref.current || !graph?.nodes.length) return undefined;
    let destroyed = false;
    let cleanup: (() => void) | undefined;

    void import('@antv/g6').then(({ Graph }) => {
      if (destroyed || !ref.current) return;
      const graphInstance = new Graph({
        container: ref.current,
        width: ref.current.clientWidth || 680,
        height: 320,
        data,
        autoFit: 'view',
        layout: {
          type: 'dagre',
          rankdir: 'LR',
          nodesep: 28,
          ranksep: 64
        },
        behaviors: ['drag-canvas', 'zoom-canvas', 'drag-element'],
        node: {
          style: {
            labelText: (datum) => String(datum.data?.label ?? datum.id),
            labelPlacement: 'bottom',
            labelFill: labelColor,
            labelMaxWidth: 150,
            size: (datum) => (datum.data?.focus ? 38 : 28),
            fill: (datum) => String(datum.data?.fill ?? '#e5e7eb'),
            stroke: (datum) => (datum.data?.focus ? '#176b87' : '#94a3b8'),
            lineWidth: (datum) => (datum.data?.focus ? 3 : 1),
            opacity: (datum) => (datum.data?.status === 'inactive' ? 0.48 : 1)
          }
        },
        edge: {
          style: {
            labelText: (datum) => String(datum.data?.label ?? ''),
            labelFill: labelColor,
            stroke: '#94a3b8',
            endArrow: true
          }
        }
      });
      void graphInstance.render();
      cleanup = () => graphInstance.destroy();
    });

    return () => {
      destroyed = true;
      cleanup?.();
    };
  }, [data, graph?.nodes.length, labelColor]);

  if (!graph?.nodes.length) {
    return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚未发现关联资产" />;
  }

  return (
    <div className="asset-graph-shell">
      <div className="asset-graph-legend" aria-label="资产类型图例">
        {Array.from(new Set(graph.nodes.map((node) => node.asset_type))).map((type) => (
          <Tag key={type} style={{ color: '#334155', background: nodeColors[type] }}>
            {describe(assetTypeMeta, type).label}
          </Tag>
        ))}
        <Typography.Text type="secondary">箭头表示关系方向，淡色节点表示不活跃</Typography.Text>
      </div>
      {graph.truncated ? (
        <Alert type="warning" showIcon message="关系较多，当前仅展示前 100 条" />
      ) : null}
      <div className="asset-graph" ref={ref} data-testid="asset-graph" />
      <ul className="asset-graph-list" aria-label="关系列表">
        {graph.edges.map((edge) => {
          const from = nodeByID.get(edge.from_asset_id);
          const to = nodeByID.get(edge.to_asset_id);
          return (
            <li key={edge.id}>
              <strong>{from && projectId ? <Link to={assetLocation(projectId, from.id, from.asset_type)}>{nodeLabel(from)}</Link> : from ? nodeLabel(from) : `资产 #${edge.from_asset_id}`}</strong>
              {' → '}
              <strong>{to && projectId ? <Link to={assetLocation(projectId, to.id, to.asset_type)}>{nodeLabel(to)}</Link> : to ? nodeLabel(to) : `资产 #${edge.to_asset_id}`}</strong>
              {' · '}
              {relationLabel(edge.relation_type)}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function buildGraphData(graph: AssetGraphData | null) {
  if (!graph) return { nodes: [], edges: [] };
  return {
    nodes: graph.nodes.map((node) => ({
      id: String(node.id),
      data: {
        label: nodeLabel(node),
        assetType: node.asset_type,
        status: node.status,
        focus: node.focus,
        fill: nodeColors[node.asset_type] ?? '#e5e7eb'
      }
    })),
    edges: graph.edges.map((edge) => ({
      id: String(edge.id),
      source: String(edge.from_asset_id),
      target: String(edge.to_asset_id),
      data: { label: relationLabel(edge.relation_type) }
    }))
  };
}
