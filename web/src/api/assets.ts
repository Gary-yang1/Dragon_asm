import { getJSON, postJSON } from './http';

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

export type AssetListQuery = {
  projectId: number;
  pageSize: number;
  pageNumber: number;
  assetType?: string;
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
    status: query.status,
    keyword: query.keyword
  });
}

export function getAsset(projectId: number, assetId: number) {
  return getJSON<Asset>(`/projects/${projectId}/assets/${assetId}`);
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
