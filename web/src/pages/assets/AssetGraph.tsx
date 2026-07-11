import { useEffect, useMemo, useRef } from 'react';

import type { Asset, AssetRelation } from '../../api/assets';

type AssetGraphProps = {
  asset: Asset | null;
  relations: AssetRelation[];
};

export function AssetGraph({ asset, relations }: AssetGraphProps) {
  const ref = useRef<HTMLDivElement | null>(null);
  const data = useMemo(() => buildGraphData(asset, relations), [asset, relations]);

  useEffect(() => {
    if (!ref.current || !asset) return undefined;
    let destroyed = false;
    let cleanup: (() => void) | undefined;

    void import('@antv/g6').then(({ Graph }) => {
      if (destroyed || !ref.current) return;
      const graph = new Graph({
        container: ref.current,
        width: ref.current.clientWidth || 520,
        height: 260,
        data,
        autoFit: 'view',
        layout: { type: 'force', preventOverlap: true },
        node: {
          style: {
            labelText: (d) => String(d.data?.label ?? d.id),
            labelPlacement: 'bottom',
            size: (d) => (d.id === String(asset.id) ? 34 : 24),
            fill: (d) => (d.id === String(asset.id) ? '#176b87' : '#d7e8ef')
          }
        },
        edge: {
          style: {
            labelText: (d) => String(d.data?.label ?? ''),
            stroke: '#9ca3af',
            endArrow: true
          }
        }
      });
      void graph.render();
      cleanup = () => graph.destroy();
    });

    return () => {
      destroyed = true;
      cleanup?.();
    };
  }, [asset, data]);

  if (!asset) return <div className="asset-graph-empty">选择资产</div>;

  return (
    <div>
      <div className="asset-graph" ref={ref} data-testid="asset-graph" />
      <ul className="asset-graph-list" aria-label="关系列表">
        {relations.map((rel) => (
          <li key={rel.id}>
            {rel.from_asset_id} → {rel.to_asset_id} · {rel.relation_type}
          </li>
        ))}
      </ul>
    </div>
  );
}

function buildGraphData(asset: Asset | null, relations: AssetRelation[]) {
  if (!asset) return { nodes: [], edges: [] };
  const ids = new Set<string>([String(asset.id)]);
  for (const rel of relations) {
    ids.add(String(rel.from_asset_id));
    ids.add(String(rel.to_asset_id));
  }
  return {
    nodes: [...ids].map((id) => ({
      id,
      data: { label: id === String(asset.id) ? asset.display_name || asset.value : `Asset ${id}` }
    })),
    edges: relations.map((rel) => ({
      id: String(rel.id),
      source: String(rel.from_asset_id),
      target: String(rel.to_asset_id),
      data: { label: rel.relation_type }
    }))
  };
}
