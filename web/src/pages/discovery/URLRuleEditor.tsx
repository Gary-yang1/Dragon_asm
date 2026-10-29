import { Checkbox, Input, Select, Space, Typography } from 'antd';
import { useEffect, useRef, useState } from 'react';
import type { URLAuthorizationRule } from '../../api/discovery';

export function URLRuleEditor({ value, onChange, id }: { value?: URLAuthorizationRule | null; onChange?: (value: URLAuthorizationRule) => void; id?: string }) {
  const focused = useRef(false);
  const [ports, setPorts] = useState(value?.ports.join(', ') ?? '');
  const portSignature = value?.ports.join(', ') ?? '';
  useEffect(() => { if (!focused.current && !value?.ports.includes(0)) setPorts(portSignature); }, [portSignature, value?.ports]);
  if (!value) return null;
  const commitPorts = () => { focused.current = false; onChange?.({...value, ports: ports.trim() ? ports.split(/[,，\s]+/).filter(Boolean).map(part => /^\d+$/.test(part) ? Number(part) : 0) : []}); };
  return <Space direction="vertical" size={12} className="full-width">
    <label htmlFor={id}>协议</label>
    <Select id={id} aria-label="URL 协议" value={value.protocol} onChange={protocol => onChange?.({...value, protocol})}
      options={[{value:'https',label:'仅 HTTPS'},{value:'http',label:'仅 HTTP'},{value:'both',label:'HTTP 和 HTTPS'}]} style={{width:'100%'}} />
    <Space wrap>
      <Checkbox checked={value.include_root} onChange={event => onChange?.({...value, include_root:event.target.checked})}>包含当前主机</Checkbox>
      <Checkbox checked={value.include_subdomains} onChange={event => onChange?.({...value, include_subdomains:event.target.checked})}>包含其子域名</Checkbox>
    </Space>
    <label htmlFor={id + '-ports'}>允许端口（逗号分隔）</label>
    <Input id={id + '-ports'} aria-label="URL 允许端口" placeholder="留空：HTTP 80、HTTPS 443；例如 443,8443" value={ports} maxLength={180}
      onFocus={() => {focused.current=true;}} onChange={event => setPorts(event.target.value)} onBlur={commitPorts} onPressEnter={commitPorts} />
    <Typography.Text type="secondary">覆盖整个站点，路径和参数不作为限制。指定端口适用于每种已选协议。同主机的 URL 规则优先于宽泛域名授权，排除规则始终优先。</Typography.Text>
  </Space>;
}
