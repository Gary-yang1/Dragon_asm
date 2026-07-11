import { Typography } from 'antd';
import type { ReactNode } from 'react';

type PageHeaderProps = {
  title: string;
  subtitle: string;
  actions?: ReactNode;
  summary?: ReactNode;
};

export function PageHeader({ title, subtitle, actions, summary }: PageHeaderProps) {
  return (
    <section className="page-header">
      <div className="page-header-main">
        <div>
          <Typography.Title level={2}>{title}</Typography.Title>
          <Typography.Text type="secondary">{subtitle}</Typography.Text>
        </div>
        {actions ? <div className="page-actions">{actions}</div> : null}
      </div>
      {summary ? <div className="page-header-summary">{summary}</div> : null}
    </section>
  );
}
