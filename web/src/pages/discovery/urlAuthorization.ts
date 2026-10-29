import type { ScopeTarget, URLAuthorizationRule } from '../../api/discovery';

export function parseURLAuthorization(input: string, rule?: URLAuthorizationRule | null) {
  const raw = input.trim();
  const absolute = raw.includes('://') ? raw : (rule?.protocol === 'http' ? 'http://' : 'https://') + raw;
  // WebKit percent-encodes '*' in URL hostnames. Remove only the permitted
  // prefix before using the browser parser, so all browsers produce one rule.
  const wildcard = /^https?:\/\/\*\./i.test(absolute);
  const parsedInput = wildcard ? absolute.replace(/^(https?:\/\/)\*\./i, '$1') : absolute;
  const url = new globalThis.URL(parsedInput);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('仅支持不含账号密码的 HTTP / HTTPS 地址');
  const host = url.hostname;
  if (host.includes('*') || host.includes('%') || !host || (wildcard && (/^[\d.]+$/.test(host) || host.includes(':')))) throw new Error('通配符只能写在域名前面，例如 *.example.com');
  const converted: URLAuthorizationRule = rule ? { ...rule, ports: [...rule.ports] } : {
    protocol: url.protocol === 'http:' ? 'http' : 'https',
    include_root: !wildcard, include_subdomains: wildcard,
    ports: url.port ? [Number(url.port)] : []
  };
  if (wildcard) { converted.include_subdomains = true; converted.include_root = false; converted.protocol = url.protocol === 'http:' ? 'http' : 'https'; converted.ports = url.port ? [Number(url.port)] : []; }
  const scheme = converted.protocol === 'http' ? 'http://' : 'https://';
  return { value: scheme + host, rule: converted, discardedPath: (url.pathname !== '/' && url.pathname !== '') || Boolean(url.search || url.hash) };
}

export function validateURLRule(rule?: URLAuthorizationRule | null) {
  if (!rule) return null;
  if (!rule.include_root && !rule.include_subdomains) return '请至少选择根域名或子域名';
  if (rule.ports.length > 20 || rule.ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) return '端口须为 1–65535 的整数，最多 20 个';
  return null;
}

export function scopeTargetInputs(target: ScopeTarget): Array<{ type: string; value: string }> {
  const rule = target.url_rule;
  if (target.target_type !== 'url' || !rule) return [{ type: target.target_type, value: target.value }];
  if (!rule.include_root) return [];
  try {
    const host = new globalThis.URL(target.value).hostname;
    const protocols = rule.protocol === 'both' ? ['http', 'https'] : [rule.protocol];
    return protocols.flatMap(protocol => (rule.ports.length ? rule.ports : [protocol === 'https' ? 443 : 80]).map(port => ({type:'url',value:protocol + '://' + host + ':' + port})));
  } catch { return []; }
}
