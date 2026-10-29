import { Alert, Button, Empty, Skeleton, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { errorMessage } from '../api/errorMessage';
import { listRisks, type Risk } from '../api/risks';
import { riskStatusMeta, severityMeta } from '../utils/taxonomy';
import { EnumChip } from './StatusChip';

// Terminal statuses: the risk no longer needs work, so it sorts after open ones.
const closedStatuses = new Set(['fixed', 'risk_accepted', 'false_positive']);
const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const pageSize = 50;

/** Risks raised on one asset, open and most severe first. */
export function AssetRiskList({ projectId, assetId }: { projectId: number; assetId: number }) {
  const [risks, setRisks] = useState<Risk[] | null>(null);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let active = true;
    setRisks(null);
    setError('');
    listRisks({ projectId, assetId, pageSize, pageNumber: 1 })
      .then((page) => {
        if (!active) return;
        setRisks(page.items);
        setTotal(page.total);
      })
      .catch((reason: unknown) => { if (active) setError(errorMessage(reason)); });
    return () => { active = false; };
  }, [projectId, assetId, revision]);

  if (error) return <Alert type="warning" showIcon message="关联风险加载失败" description={error} action={<Button size="small" onClick={() => setRevision(value => value + 1)}>重试</Button>} />;
  if (!risks) return <Skeleton active paragraph={{ rows: 2 }} title={false} />;
  if (risks.length === 0) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="该资产暂无关联风险" />;

  const sorted = [...risks].sort((a, b) =>
    Number(closedStatuses.has(a.status)) - Number(closedStatuses.has(b.status))
    || (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9)
    || b.id - a.id);
  const open = risks.filter(risk => !closedStatuses.has(risk.status)).length;

  return (
    <div className="asset-risk-list">
      <Typography.Text type="secondary">开放 {open} 个 · 共 {total} 个</Typography.Text>
      <ul aria-label="关联风险">
        {sorted.map(risk => (
          <li key={risk.id} className={closedStatuses.has(risk.status) ? 'is-closed' : undefined}>
            <EnumChip map={severityMeta} value={risk.severity} dot />
            <Link to={`/projects/${projectId}/risks?risk_id=${risk.id}`}>{risk.title}</Link>
            <EnumChip map={riskStatusMeta} value={risk.status} />
          </li>
        ))}
      </ul>
      {total > risks.length ? <Link to={`/projects/${projectId}/risks?asset_id=${assetId}`}>另有 {total - risks.length} 个，前往风险中心查看</Link> : null}
    </div>
  );
}
