export function assetLocation(projectId: number, id: number, type: string) {
  const view = ['domain', 'subdomain'].includes(type) ? 'domains' : type === 'ip' ? 'ips' : type === 'web' ? 'web' : 'all';
  return `/projects/${projectId}/assets?view=${view}&asset_id=${id}`;
}
