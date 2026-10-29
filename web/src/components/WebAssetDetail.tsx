import { Alert, Button, Collapse, Descriptions, Skeleton, Space, Tag, Typography } from 'antd';
import { ExternalLink } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { getAsset, getAssetGraph, type Asset, type AssetGraphData } from '../api/assets';
import { errorMessage } from '../api/errorMessage';
import { Permission } from '../auth/permissions';
import { usePermission } from '../auth/usePermission';
import { AssetManagementCard, formatTime } from '../pages/assets/AssetDetail';
import { assetLocation } from '../utils/assetRoutes';
import { assetStatusMeta, assetTypeMeta, describe } from '../utils/taxonomy';
import { AssetRiskList } from './AssetRiskList';
import { EnumChip } from './StatusChip';
import { crawlSource, fingerprintNames, known, missingTitleReason, networkProgress, networkSource, outcomes, siteHost, stamp, enrichmentPending, type Website } from './webResultFormat';

type WebAssetDetailProps = {
  projectId: number;
  row: Website;
  runId?: number;
  retrying: boolean;
  retryError: string;
  onRetryEnrichment: (runId: number) => void;
};

/**
 * Website detail ordered by what an exposure owner asks first: what the site is
 * and who owns it, what it exposes, and only then where the evidence came from.
 */
export function WebAssetDetail({ projectId, row, runId, retrying, retryError, onRetryEnrichment }: WebAssetDetailProps) {
  const { can } = usePermission();
  const canReadAssets = can(Permission.AssetRead);
  const canRetry = row.enrichment_state === 'failed' && row.run_id > 0 && can(Permission.DiscoveryRun) && canReadAssets;
  const [asset, setAsset] = useState<Asset | null>(null);
  const [graph, setGraph] = useState<AssetGraphData | null>(null);
  const [assetLoading, setAssetLoading] = useState(false);
  const [assetError, setAssetError] = useState('');
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    if (!canReadAssets || row.asset_id <= 0) return;
    let active = true;
    setAsset(null);
    setGraph(null);
    setAssetError('');
    setAssetLoading(true);
    // The graph only supplies the host link; a graph failure must not hide ownership.
    Promise.allSettled([getAsset(projectId, row.asset_id), getAssetGraph(projectId, row.asset_id)]).then(([assetResult, graphResult]) => {
      if (!active) return;
      if (assetResult.status === 'fulfilled') setAsset(assetResult.value);
      else setAssetError(errorMessage(assetResult.reason));
      if (graphResult.status === 'fulfilled') setGraph(graphResult.value);
      setAssetLoading(false);
    });
    return () => { active = false; };
  }, [projectId, row.asset_id, canReadAssets, revision]);

  const host = hostNode(graph, row.asset_id);
  const ips = [...new Set([row.connected_ip, ...(row.resolved_ips ?? [])].filter((ip): ip is string => !!ip))];
  const stack = fingerprintNames(row.fingerprints ?? []);
  const progress = networkProgress(row);

  return (
    <Space direction="vertical" size={20} className="full-width web-asset-detail">
      <header className="web-asset-header">
        <Typography.Title level={4}>{row.title || siteHost(row.url)}</Typography.Title>
        <Space size={8} wrap>
          {crawlSource(row) ? <Tag color="blue">{`${crawlSource(row)} 测绘数据`}</Tag> : null}
          {row.status_code ? <Tag color={row.status_code >= 400 ? 'orange' : 'green'}>HTTP {row.status_code}</Tag> : <Tag>{crawlSource(row) ? '状态码未知' : missingTitleReason(row)}</Tag>}
          {!row.title && row.status_code ? <Tag>页面无标题</Tag> : null}
          {asset ? <EnumChip map={assetStatusMeta} value={asset.status} /> : null}
        </Space>
        <Typography.Paragraph className="web-asset-url" copyable={{ text: row.url }}>
          <a href={row.url} target="_blank" rel="noopener noreferrer">{row.url}<ExternalLink size={12} aria-hidden="true" /></a>
        </Typography.Paragraph>
        {crawlSource(row) ? <Typography.Text type="secondary">以下标题与技术栈来自 {crawlSource(row)} 的历史收录（{stamp(row.observed_at)} 采集），本平台尚未实时探测该网站。</Typography.Text> : null}
        {row.final_url && row.final_url !== row.url ? <Typography.Text type="secondary" className="web-asset-redirect">跳转至 {row.final_url}</Typography.Text> : null}
        {row.info_observed_at ? <Typography.Text type="secondary">本次未返回 HTTP 响应，标题与技术栈保留自 {stamp(row.info_observed_at)} 的观察。</Typography.Text> : null}
        <Space size={16} wrap>
          {runId && row.asset_id > 0 && canReadAssets ? <Link to={`/projects/${projectId}/assets?view=web&q=${encodeURIComponent(row.url)}`}>在 Web 资产中定位</Link> : null}
          {!runId && row.run_id > 0 && can(Permission.DiscoveryRead) ? <Link to={`/projects/${projectId}/discovery?run_id=${row.run_id}`}>查看来源任务 #{row.run_id}</Link> : null}
        </Space>
      </header>

      <section aria-label="归属">
        <Typography.Title level={5}>归属</Typography.Title>
        {row.asset_id <= 0 ? <Typography.Text type="secondary">该网站尚未纳入资产清单。</Typography.Text>
          : !canReadAssets ? <Typography.Text type="secondary">暂无资产查看权限。</Typography.Text>
          : assetLoading ? <Skeleton active paragraph={{ rows: 2 }} title={false} />
          : assetError ? <Alert type="warning" showIcon message="资产信息加载失败" description={assetError} action={<Button size="small" onClick={() => setRevision(value => value + 1)}>重试</Button>} />
          : asset ? (
            <AssetManagementCard
              projectId={projectId}
              asset={asset}
              canEdit={can(Permission.AssetWrite)}
              onUpdated={setAsset}
              extra={<>
                <Descriptions.Item label="所属主机">
                  {host ? <Link to={assetLocation(projectId, host.id, host.asset_type)}>{host.display_name || host.value}</Link> : <span className="secondary-text">未记录</span>}
                  {host ? <span className="secondary-text"> · {describe(assetTypeMeta, host.asset_type).label}</span> : null}
                </Descriptions.Item>
                <Descriptions.Item label="首次 / 最近发现">{formatTime(asset.first_seen)} / {formatTime(asset.last_seen)}</Descriptions.Item>
              </>}
            />
          ) : null}
      </section>

      <section aria-label="暴露面">
        <Typography.Title level={5}>暴露面</Typography.Title>
        <Descriptions size="small" column={1} bordered>
          <Descriptions.Item label="技术栈">
            {stack.length ? <Space size={[4, 4]} wrap>{stack.map(name => <Tag key={name}>{name}</Tag>)}</Space> : <span className="secondary-text">未识别</span>}
          </Descriptions.Item>
          <Descriptions.Item label="IP">
            {ips.length ? <Space size={[12, 4]} wrap>{ips.map(ip => <Typography.Text key={ip} copyable={{ text: ip }}>{ip}</Typography.Text>)}</Space> : <span className="secondary-text">未知</span>}
          </Descriptions.Item>
          <Descriptions.Item label="CDN / 云">
            CDN {known(row.cdn)} · 云 {known(row.cloud)}
            {progress ? <div className="secondary-text">{progress}{canRetry ? <Button type="link" size="small" loading={retrying} onClick={() => onRetryEnrichment(row.run_id)}>重试本次任务网络查询</Button> : null}</div> : null}
            {retryError ? <Alert type="error" showIcon message="网络查询重试失败" description={retryError} /> : null}
          </Descriptions.Item>
        </Descriptions>
      </section>

      {row.asset_id > 0 && can(Permission.RiskRead) ? (
        <section aria-label="风险">
          <Typography.Title level={5}>风险</Typography.Title>
          <AssetRiskList projectId={projectId} assetId={row.asset_id} />
        </section>
      ) : null}

      <Collapse
        ghost
        className="web-asset-source"
        items={[{
          key: 'source',
          label: '数据来源（探测证据、采集时间、来源任务）',
          children: <Space direction="vertical" size={12} className="full-width">
            {progress ? <Alert
              type={row.enrichment_state === 'failed' ? 'warning' : 'info'}
              message={progress}
              description={row.enrichment_state === 'failed' ? '网站探测结果已保留。检查 Baiyan 服务及配置后，可重试本次任务中失败的网络查询，无需重新扫描网站。' : enrichmentPending(row) ? '网站结果已可查看，归属查询完成后将自动更新。' : row.network_status === 'partial' ? '展示已获得的网络证据，未识别部分保留为未知。' : '此历史记录尚无 Baiyan 网络观察，不会用当前 DNS 覆盖扫描历史。'}
            /> : null}
            <Descriptions column={1} size="small">
              <Descriptions.Item label="探测结果">{outcomes[row.outcome] || '未返回详情'}{row.status_code ? ` · HTTP ${row.status_code}` : ''}</Descriptions.Item>
              <Descriptions.Item label="跳转链">{row.redirect_chain?.join(' → ') || '未记录跳转'}</Descriptions.Item>
              <Descriptions.Item label="解析 IP">{row.resolved_ips.join('、') || '未知'}{row.network_source === 'baiyan' ? '（Baiyan 查询，可能与扫描时地址不同）' : ''}</Descriptions.Item>
              <Descriptions.Item label="扫描时连接 IP">{row.connected_ip || '未采集'}</Descriptions.Item>
              <Descriptions.Item label="CNAME">{row.cname_chain.join(' → ') || '未采集'}{row.network_source === 'baiyan' && row.cname_chain.length > 0 ? '（DNS 规范名称，未保证覆盖完整 CNAME 链）' : ''}</Descriptions.Item>
              <Descriptions.Item label="CDN 证据">{row.cdn.evidence?.join('；') || '未提供判断证据'}</Descriptions.Item>
              <Descriptions.Item label="云归属证据">{row.cloud.evidence?.join('；') || '未提供判断证据'}</Descriptions.Item>
              <Descriptions.Item label="规则版本">{row.rule_version || '未提供'}</Descriptions.Item>
              <Descriptions.Item label="网站观察时间">{stamp(row.observed_at)}</Descriptions.Item>
              <Descriptions.Item label="网络信息来源">{networkSource(row)}</Descriptions.Item>
              <Descriptions.Item label="网络采集时间">{row.network_observed_at ? stamp(row.network_observed_at) : '未记录'}</Descriptions.Item>
              {row.enrichment_error ? <Descriptions.Item label="网络查询说明">{row.enrichment_error}</Descriptions.Item> : null}
            </Descriptions>
          </Space>
        }]}
      />
    </Space>
  );
}

/** The domain or IP that "contains" this website, as recorded by discovery. */
function hostNode(graph: AssetGraphData | null, assetId: number) {
  if (!graph) return undefined;
  const edge = graph.edges.find(item => item.to_asset_id === assetId && item.relation_type === 'contains');
  if (!edge) return undefined;
  return graph.nodes.find(node => node.id === edge.from_asset_id);
}
