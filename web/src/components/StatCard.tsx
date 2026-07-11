import { Badge } from 'antd';
import type { ReactNode } from 'react';

export type StatCardTone = 'critical' | 'high' | 'good' | 'neutral';

export type StatCardDelta = {
  text: string;
  trend: 'up' | 'down' | 'flat';
};

type StatCardProps = {
  label: ReactNode;
  value: ReactNode;
  icon?: ReactNode;
  tone?: StatCardTone;
  suffix?: ReactNode;
  delta?: StatCardDelta;
  hint?: ReactNode;
};

const toneClass: Record<StatCardTone, string> = {
  critical: 'metric-card--critical',
  high: 'metric-card--high',
  good: 'metric-card--good',
  neutral: 'metric-card--neutral'
};

function deltaColor(trend: StatCardDelta['trend']) {
  if (trend === 'up') return '#ff4d4f';
  if (trend === 'down') return '#52c41a';
  return '#94a3b8';
}

export function StatCard({ label, value, icon, tone = 'neutral', suffix, delta, hint }: StatCardProps) {
  return (
    <article className={`metric-card ${toneClass[tone]}`}>
      <div className="metric-card-head">
        <span className="metric-card-icon">{icon}</span>
        {delta ? <Badge count={delta.text} style={{ backgroundColor: deltaColor(delta.trend) }} /> : null}
      </div>
      <div className="metric-card-body">
        <div className="metric-card-value">
          {value}
          {suffix}
        </div>
        <div className="metric-card-label">{label}</div>
        {hint ? <div className="metric-card-hint">{hint}</div> : null}
      </div>
    </article>
  );
}