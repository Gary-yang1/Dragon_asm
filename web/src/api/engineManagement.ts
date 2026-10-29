import { getJSON, postJSON, putJSON } from './http';

export type EngineRoute = 'passive' | 'active';
export type EngineHealth = 'healthy' | 'degraded' | 'unreachable' | 'unconfigured' | 'unknown';

export type CredentialSummary = {
  key: string;
  label: string;
  configured: boolean;
  /** Already masked by the API. The frontend must never receive a raw secret. */
  masked_value: string;
};

export type EngineProviderSummary = {
  key: string;
  name: string;
  configured: boolean;
  credentials: CredentialSummary[];
};

export type EngineNodeSummary = {
  node_id: string;
  capabilities: string[];
};

export type EngineSummary = {
  configuration_version?: number;
  route: EngineRoute;
  key: string;
  name: string;
  instance_id?: string;
  configured: boolean;
  ready: boolean;
  health: EngineHealth;
  base_url: string;
  capabilities: string[];
  credentials: CredentialSummary[];
  providers?: EngineProviderSummary[];
  nodes?: EngineNodeSummary[];
  last_checked_at?: string;
  latency_ms?: number;
  error_summary?: string;
  project_mapping_count?: number;
};

export type ActiveEnginePolicy = {
  enabled: boolean;
  require_approval: boolean;
  require_ownership: boolean;
};

export type EngineWorkerStatus = {
  status: 'online' | 'stale' | 'unknown';
  last_seen_at?: string;
  config_matches?: boolean;
};

export type EngineManagementOverview = {
  configuration_version?: number;
  editable?: boolean;
  items: EngineSummary[];
  active_policy: ActiveEnginePolicy;
  worker: EngineWorkerStatus;
};

export function getDiscoveryEngines() {
  return getJSON<EngineManagementOverview>('/platform/discovery-engines');
}

export function checkDiscoveryEngine(route: EngineRoute) {
  return postJSON<EngineSummary>(`/platform/discovery-engines/${route}/check`);
}

export type EngineConfiguration = {
  version: number;
  values: Record<string, string>;
  secrets: Record<string, CredentialSummary>;
  providers_managed: boolean;
  provider_error?: string;
};
export function getEngineConfiguration() {
  return getJSON<EngineConfiguration>('/platform/discovery-engines/configuration');
}
export function saveEngineConfiguration(input: { version: number; values: Record<string, string>; clear_secrets: string[]; reason: string }) {
  return putJSON<EngineConfiguration>('/platform/discovery-engines/configuration', input);
}
