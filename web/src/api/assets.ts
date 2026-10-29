import { getJSON, patchJSON, postJSON } from './http';

export type PageData<T> = {
  items: T[];
  total: number;
  page_size: number;
  page_number: number;
};

export type Asset = {
  id: number;
  project_id: number;
  asset_type: string;
  asset_key: string;
  display_name: string;
  value: string;
  source: string;
  owner: string;
  business_unit: string;
  confidence: number;
  miss_count: number;
  status: string;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  created_by: string;
  updated_by: string;
};

export type AssetRelation = {
  id: number;
  project_id: number;
  from_asset_id: number;
  to_asset_id: number;
  relation_type: string;
  source: string;
  confidence: number;
  direction?: 'in' | 'out';
};

export type AssetSummary = {
  inventory: {
    total: number;
    managed_total: number;
    active: number;
    inactive: number;
    ignored: number;
  };
  by_type: {
    domain: number;
    subdomain: number;
    ip: number;
    port: number;
    service: number;
    web: number;
    certificate: number;
    cloud_resource: number;
    third_party: number;
  };
  freshness: {
    new_24h: number;
    observed_24h: number;
    stale_30d: number;
  };
  governance: {
    unowned: number;
    unassigned_business_unit: number;
    low_confidence: number;
    low_confidence_below: number;
  };
  /** CDN edges are excluded from every other figure; shared IPs are only labelled. */
  network?: {
    cdn_edge: number;
    shared_ip: number;
    shared_ip_min_names: number;
  };
};

/** Where an asset sits on the network. No role means unknown, not "own origin". */
export type AssetNetworkInfo = {
  asset_id: number;
  role?: 'cdn_edge' | 'cdn_served';
  provider?: string;
  evidence?: string;
  rule_version?: string;
  source_run_id?: number;
  observed_at?: string;
  resolved_by: number;
  shared: boolean;
};

export type AssetGraphNode = {
  id: number;
  asset_type: string;
  display_name: string;
  value: string;
  status: string;
  source: string;
  owner: string;
  business_unit: string;
  confidence: number;
  last_seen: string;
  focus: boolean;
};

export type AssetGraphEdge = {
  id: number;
  from_asset_id: number;
  to_asset_id: number;
  relation_type: string;
  source: string;
  confidence: number;
  last_seen: string;
};

export type AssetGraphData = {
  nodes: AssetGraphNode[];
  edges: AssetGraphEdge[];
  truncated: boolean;
};

export type AssetListQuery = {
  projectId: number;
  pageSize: number;
  pageNumber: number;
  assetType?: string;
  category?: 'domains' | 'ips' | 'cdn_edges' | 'web' | 'external';
  status?: string;
  keyword?: string;
};

export type ImportRow = {
  asset_type: string;
  value: string;
  display_name?: string;
  source?: string;
  owner?: string;
  business_unit?: string;
  confidence?: number;
  status?: string;
};

export type DryRunRow = {
  index: number;
  status: string;
  asset_type?: string;
  value?: string;
  asset_key?: string;
  existing_id?: number;
  error?: string;
};

export type DryRunReport = {
  total: number;
  new: number;
  update: number;
  duplicate: number;
  failed: number;
  rows: DryRunRow[];
};

export type ImportReport = {
  total: number;
  success: number;
  failed: number;
  rows: Array<{
    index: number;
    status: string;
    asset_id?: number;
    asset_key?: string;
    error?: string;
  }>;
};

export function listAssets(query: AssetListQuery) {
  return getJSON<PageData<Asset>>(`/projects/${query.projectId}/assets`, {
    page_size: query.pageSize,
    page_number: query.pageNumber,
    asset_type: query.assetType,
    category: query.category,
    status: query.status,
    keyword: query.keyword
  });
}

export function getAsset(projectId: number, assetId: number) {
  return getJSON<Asset>(`/projects/${projectId}/assets/${assetId}`);
}

/** Fields the operator may edit; asset identity and discovery source stay read-only. */
export type AssetUpdateInput = Partial<Pick<Asset, 'display_name' | 'owner' | 'business_unit' | 'status'>>;

export function updateAsset(projectId: number, assetId: number, input: AssetUpdateInput) {
  return patchJSON<Asset>(`/projects/${projectId}/assets/${assetId}`, input);
}

export function getAssetSummary(projectId: number) {
  return getJSON<AssetSummary>(`/projects/${projectId}/assets/summary`);
}

/** Network attribution for up to 100 assets in one request (one list page). */
export async function getAssetNetwork(projectId: number, assetIds: number[]) {
  if (assetIds.length === 0) return [];
  const result = await getJSON<{ items: AssetNetworkInfo[] }>(`/projects/${projectId}/assets/network`, { asset_ids: assetIds.join(',') });
  return result.items;
}

export function getAssetGraph(projectId: number, assetId: number) {
  return getJSON<AssetGraphData>(`/projects/${projectId}/assets/${assetId}/graph`);
}

export function listAssetRelations(projectId: number, assetId: number) {
  return getJSON<PageData<AssetRelation>>(`/projects/${projectId}/assets/${assetId}/relations`, {
    page_size: 100,
    page_number: 1
  });
}

export function dryRunImport(projectId: number, rows: ImportRow[]) {
  return postJSON<DryRunReport>(`/projects/${projectId}/assets/import?dry_run=true`, { rows });
}

export function importAssets(projectId: number, rows: ImportRow[]) {
  return postJSON<ImportReport>(`/projects/${projectId}/assets/import`, { rows });
}
