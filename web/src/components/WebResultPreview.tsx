import { Alert, Button, Descriptions, Empty, Skeleton, Tabs, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { getAssetGraph, type AssetGraphData } from '../api/assets';
import { errorMessage } from '../api/errorMessage';
import { Permission } from '../auth/permissions';
import { usePermission } from '../auth/usePermission';
import { assetTypeMeta, describe } from '../utils/taxonomy';
import { assetLocation } from '../utils/assetRoutes';
import type { Website } from './WebResults';


export function WebResultPreview({ projectId, row, onOpen }: { projectId: number; row: Website; onOpen: () => void }) {
  const { can } = usePermission();
  const [graph, setGraph] = useState<AssetGraphData>();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [revision, setRevision] = useState(0);
  const [tab, setTab] = useState('relations');
  const canReadAssets = can(Permission.AssetRead);
  useEffect(() => {
    if (!canReadAssets || row.asset_id <= 0) return;
    let active = true;
    setGraph(undefined);
    setError('');
    setLoading(true);
    getAssetGraph(projectId, row.asset_id).then(value => {
      if (active) setGraph(value);
    }).catch(reason => {
      if (active) setError(errorMessage(reason));
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [projectId, row.asset_id, canReadAssets, revision]);

  const nodes = graph?.nodes.filter(node => node.id !== row.asset_id) ?? [];
  const ips = [...new Set([row.connected_ip, ...(row.resolved_ips ?? [])].filter((ip): ip is string => !!ip))];
  const time = (value?: string) => value ? new Date(value).toLocaleString() : '未记录';
  return <div className="web-row-preview">
    <Tabs activeKey={tab} onChange={setTab} tabBarExtraContent={<Button type="link" onClick={onOpen}>查看完整详情</Button>} items={[
      { key: 'relations', label: '关联资产', children: <>
        <div className="web-relation-columns">
          <section><h4>已记录的关联资产</h4>
            {!canReadAssets ? <Typography.Text type="secondary">暂无资产查看权限</Typography.Text> : loading ? <Skeleton active paragraph={{ rows: 2 }} title={false} /> : error ? <Alert type="warning" message="关联信息加载失败" description={error} action={<Button size="small" onClick={() => setRevision(v => v + 1)}>重试</Button>} /> : nodes.length ? <ul className="web-relation-list">{nodes.map(node => <li key={node.id}><Link to={assetLocation(projectId, node.id, node.asset_type)}>{node.display_name || node.value}</Link><small>{describe(assetTypeMeta, node.asset_type).label}</small></li>)}</ul> : <Typography.Text type="secondary">尚未记录关联资产</Typography.Text>}
            {graph?.truncated && <p className="secondary-text">关联较多，当前展示部分记录。</p>}
          </section>
          <section><h4>观察到的 IP</h4>{ips.length ? ips.slice(0, 3).map(ip => <div key={ip} className="web-observed-ip"><Typography.Text copyable={{ text: ip }}>{ip}</Typography.Text><small>{ip === row.connected_ip ? '扫描时连接' : 'DNS 解析地址'}</small></div>) : <Typography.Text type="secondary">未采集</Typography.Text>}{ips.length > 3 && <Button type="link" size="small" onClick={onOpen}>另有 {ips.length - 3} 个 IP，查看全部</Button>}<p className="secondary-text">解析地址不等同于已纳管或已授权的 IP。</p></section>
          <section><h4>网站入口</h4><Typography.Paragraph copyable={{ text: row.url }}>{row.url}</Typography.Paragraph><Typography.Text type="secondary">{row.status_code ? `HTTP ${row.status_code}` : '未返回 HTTP 响应'}</Typography.Text>{row.final_url && row.final_url !== row.url && <p className="secondary-text">最终 URL：{row.final_url}</p>}</section>
        </div>
      </> },
      { key: 'evidence', label: '探测证据', children: <Descriptions column={2} size="small">
        <Descriptions.Item label="技术指纹">{row.fingerprints?.join('、') || '未识别'}</Descriptions.Item>
        <Descriptions.Item label="CNAME">{row.cname_chain?.join(' → ') || '未采集'}</Descriptions.Item>
        <Descriptions.Item label="CDN 证据">{row.cdn?.evidence?.join('；') || '未提供判断证据'}</Descriptions.Item>
        <Descriptions.Item label="云归属证据">{row.cloud?.evidence?.join('；') || '未提供判断证据'}</Descriptions.Item>
        <Descriptions.Item label="跳转链" span={2}>{row.redirect_chain?.join(' → ') || '未记录跳转'}</Descriptions.Item>
        {row.info_observed_at && <Descriptions.Item label="标题与指纹来源" span={2}>保留自 {time(row.info_observed_at)} 的观察，本次未返回 HTTP 响应。</Descriptions.Item>}
      </Descriptions> },
      { key: 'source', label: '采集记录', children: row.observed_at ? <Descriptions column={2} size="small">
        <Descriptions.Item label="网站观察">{time(row.observed_at)}</Descriptions.Item>
        <Descriptions.Item label="网络采集">{time(row.network_observed_at)}</Descriptions.Item>
        <Descriptions.Item label="网络来源">{row.network_source === 'baiyan' ? 'Baiyan' : row.network_source === 'active_engine' ? '主动引擎（历史记录）' : '未采集'}</Descriptions.Item>
        <Descriptions.Item label="来源任务">{row.run_id > 0 && can(Permission.DiscoveryRead) ? <Link to={`/projects/${projectId}/discovery?run_id=${row.run_id}`}>任务 #{row.run_id}</Link> : '未提供可查看的来源任务'}</Descriptions.Item>
      </Descriptions> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚无采集记录" /> }
    ]} />
  </div>;
}
